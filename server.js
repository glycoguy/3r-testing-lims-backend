
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3001;

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Email configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER || 'your-email@gmail.com',
    pass: process.env.SMTP_PASS || 'your-app-password'
  }
});

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', process.env.FRONTEND_URL || '*'],
  credentials: true
}));

app.use('/api/webhooks/woocommerce', express.raw({ type: 'application/json' }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || '3rtesting-super-secure-secret-key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Database query helper
async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

// Safe audit logging function
const logAudit = async (userId, action, entityType, entityId, details = null) => {
  try {
    // Skip audit logging if table doesn't exist
    console.log(`Audit: User ${userId} ${action} ${entityType} ${entityId}: ${details}`);
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
};

// WooCommerce Configuration
const WOOCOMMERCE_WEBHOOK_SECRET = process.env.WOOCOMMERCE_WEBHOOK_SECRET;

// Product mapping configuration
const PRODUCT_SAMPLE_MAPPING = {
  'pathogen-test-single': { sample_count: 1, test_type: 'HLVD' },
  'pathogen-test-5pack': { sample_count: 5, test_type: 'HLVD' },
  'pathogen-test-10pack': { sample_count: 10, test_type: 'HLVD' },
  'fusarium-test': { sample_count: 1, test_type: 'Fusarium' },
  'pythium-test': { sample_count: 1, test_type: 'Pythium' },
  'combo-test': { sample_count: 1, test_type: 'Fus+Pyth' },
  'bctv-test': { sample_count: 1, test_type: 'BCTV' },
  'lcv-test': { sample_count: 1, test_type: 'LCV' }
};

// WooCommerce webhook signature verification
const verifyWooCommerceSignature = (body, signature) => {
  if (!WOOCOMMERCE_WEBHOOK_SECRET) {
    console.warn('WooCommerce webhook secret not configured - allowing for development');
    return true;
  }
  
  const expectedSignature = crypto
    .createHmac('sha256', WOOCOMMERCE_WEBHOOK_SECRET)
    .update(body)
    .digest('base64');
  
  return signature === expectedSignature;
};

// Helper function to find or create customer from WooCommerce data
const findOrCreateCustomer = async (wooCustomerData) => {
  try {
    // Try to find by email first
    const existingByEmail = await query(
      'SELECT * FROM customers WHERE email = $1',
      [wooCustomerData.email]
    );
    
    if (existingByEmail.rows.length > 0) {
      return existingByEmail.rows[0];
    }
    
    // Create new customer
    const customerResult = await query(`
      INSERT INTO customers (name, email, company_name, phone, shipping_address)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `, [
      `${wooCustomerData.first_name} ${wooCustomerData.last_name}`.trim(),
      wooCustomerData.email,
      wooCustomerData.billing?.company || null,
      wooCustomerData.billing?.phone || null,
      formatAddress(wooCustomerData.shipping)
    ]);
    
    return customerResult.rows[0];
  } catch (error) {
    console.error('Error finding/creating customer:', error);
    throw error;
  }
};

// Helper function to format address from WooCommerce data
const formatAddress = (addressData) => {
  if (!addressData) return null;
  
  const parts = [
    addressData.address_1,
    addressData.address_2,
    addressData.city,
    addressData.state,
    addressData.postcode,
    addressData.country
  ].filter(Boolean);
  
  return parts.join(', ');
};

// Helper function to parse WooCommerce line items
const parseOrderLineItems = (lineItems) => {
  let totalSampleCount = 0;
  let testTypes = new Set();
  
  lineItems.forEach(item => {
    const sku = item.sku || item.product_id?.toString();
    const mapping = PRODUCT_SAMPLE_MAPPING[sku];
    
    if (mapping) {
      totalSampleCount += mapping.sample_count * item.quantity;
      testTypes.add(mapping.test_type);
    } else {
      totalSampleCount += item.quantity;
      testTypes.add('HLVD');
    }
  });
  
  return {
    sample_count: totalSampleCount,
    test_type: testTypes.size === 1 ? Array.from(testTypes)[0] : 'MIXED'
  };
};

// Check if column exists helper
const columnExists = async (tableName, columnName) => {
  try {
    const result = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns 
        WHERE table_name = $1 AND column_name = $2
      );
    `, [tableName, columnName]);
    return result.rows[0].exists;
  } catch (error) {
    console.error(`Error checking column ${columnName} in ${tableName}:`, error);
    return false;
  }
};

// VALIDATEBARCODE FUNCTION:
const validateBarcode = (barcode) => {
  const pattern = /^[A-Z]+\d+$/;
  return pattern.test(barcode.toUpperCase());
};

// Basic database initialization
async function initializeDatabase() {
  try {
    console.log('Checking database tables...');
    
    // Create basic users table if it doesn't exist
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        email VARCHAR(100),
        full_name VARCHAR(100)
      )
    `);

    // Create basic customers table
    await query(`
      CREATE TABLE IF NOT EXISTS customers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        company_name VARCHAR(100),
        phone VARCHAR(20),
        shipping_address TEXT
      )
    `);

    // Create basic orders table
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        order_number VARCHAR(50) UNIQUE,
        sample_count INTEGER NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        tracking_number VARCHAR(100),
        notes TEXT
      )
    `);

    // Create basic samples table
    await query(`
      CREATE TABLE IF NOT EXISTS samples (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        barcode VARCHAR(50) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending'
      )
    `);

    // Create basic batches table
    await query(`
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY,
        test_type VARCHAR(100),
        status VARCHAR(50) DEFAULT 'active'
      )
    `);

    // Create default users
    const defaultUsers = [
      { username: 'admin', password: 'admin123', role: 'admin', email: 'admin@3rtesting.com', full_name: 'System Administrator' },
      { username: 'technician', password: 'tech123', role: 'technician', email: 'tech@3rtesting.com', full_name: 'Lab Technician' }
    ];

    for (const user of defaultUsers) {
      const existingUser = await query('SELECT id FROM users WHERE username = $1', [user.username]);
      if (existingUser.rows.length === 0) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        await query(
          'INSERT INTO users (username, password_hash, role, email, full_name) VALUES ($1, $2, $3, $4, $5)',
          [user.username, hashedPassword, user.role, user.email, user.full_name]
        );
        console.log(`Created default user: ${user.username}`);
      }
    }

    console.log('✅ Database tables verified');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: '3R Testing LIMS Backend is running',
    database: 'PostgreSQL',
    version: '3.0.0 - Simplified'
  });
});

// Authentication endpoints
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const userResult = await query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email,
        full_name: user.full_name
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    const userResult = await query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [hashedPassword, req.user.userId]
    );
    
    await logAudit(req.user.userId, 'UPDATE', 'user', req.user.userId, 'Password changed');
    
    res.json({ message: 'Password changed successfully' });
    
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Customer endpoints
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT c.*, 
             COUNT(o.id) as total_orders
      FROM customers c
      LEFT JOIN orders o ON c.id = o.customer_id
      GROUP BY c.id
      ORDER BY c.id DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Customers fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
    console.log('Create customer request from user:', req.user);
    console.log('Request body:', req.body);
    
    const { name, email, company_name, phone, shipping_address } = req.body;
    
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    const existingCustomer = await query(
      'SELECT id FROM customers WHERE email = $1',
      [email]
    );
    
    if (existingCustomer.rows.length > 0) {
      return res.status(409).json({ error: 'Customer with this email already exists' });
    }
    
    const result = await query(`
      INSERT INTO customers (name, email, company_name, phone, shipping_address)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `, [name, email, company_name, phone, shipping_address]);
    
    await logAudit(req.user.userId, 'CREATE', 'customer', result.rows[0].id, `Created customer: ${name}`);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Customer creation error:', error);
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

// Order endpoints
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT o.*, 
             c.name as customer_name,
             c.email as customer_email,
             c.company_name,
             COUNT(s.id) as received_samples
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN samples s ON o.id = s.order_id
      GROUP BY o.id, c.id
      ORDER BY o.id DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { customer_id, sample_count, priority = 'normal', shipping_method = 'ups_ground', notes = '' } = req.body;
    
    if (!customer_id || !sample_count) {
      return res.status(400).json({ error: 'Customer ID and sample count are required' });
    }
    
    if (sample_count < 1 || sample_count > 100) {
      return res.status(400).json({ error: 'Sample count must be between 1 and 100' });
    }
    
    // Verify customer exists
    const customerResult = await query('SELECT * FROM customers WHERE id = $1', [customer_id]);
    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    // Generate order number
    const orderNumber = `ORD-${Date.now()}`;
    
    const result = await query(`
      INSERT INTO orders (customer_id, order_number, sample_count, status, notes)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `, [customer_id, orderNumber, sample_count, 'pending', notes]);
    
    await logAudit(req.user.userId, 'CREATE', 'order', result.rows[0].id, `Created order: ${orderNumber}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Barcode assignment endpoint - simplified
app.post('/api/orders/:id/assign-barcodes', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { barcodes } = req.body;
    
    console.log(`Assigning barcodes to order ${id}:`, barcodes);
    
    if (!barcodes || !Array.isArray(barcodes)) {
      return res.status(400).json({ error: 'Barcodes array is required' });
    }
    
    if (barcodes.length === 0) {
      return res.status(400).json({ error: 'At least one barcode is required' });
    }
    
    // Get order details
    const orderResult = await query('SELECT * FROM orders WHERE id = $1', [id]);
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    if (barcodes.length !== order.sample_count) {
      return res.status(400).json({ 
        error: `Expected ${order.sample_count} barcodes, received ${barcodes.length}` 
      });
    }
    
    // Validate each barcode format
    const normalizedBarcodes = [];
    
    for (let i = 0; i < barcodes.length; i++) {
      const barcode = barcodes[i].toString().trim().toUpperCase();
      
      if (!barcode) {
        return res.status(400).json({ error: `Empty barcode at position ${i + 1}` });
      }
      
      if (!barcode.match(/^[A-Z]+\d+$/)) {
        return res.status(400).json({ 
          error: `Invalid barcode format: ${barcode}. Use format like CA000001` 
        });
      }
      
      normalizedBarcodes.push(barcode);
    }
    
    // Check for duplicates
    const uniqueBarcodes = [...new Set(normalizedBarcodes)];
    if (uniqueBarcodes.length !== normalizedBarcodes.length) {
      return res.status(400).json({ error: 'Duplicate barcodes detected' });
    }
    
    // Check if any barcodes already exist
    const existingBarcodesResult = await query(
      'SELECT barcode FROM samples WHERE barcode = ANY($1::text[])',
      [normalizedBarcodes]
    );
    
    if (existingBarcodesResult.rows.length > 0) {
      const existingBarcodes = existingBarcodesResult.rows.map(row => row.barcode);
      return res.status(409).json({ 
        error: 'Some barcodes already exist in the system',
        existing_barcodes: existingBarcodes
      });
    }
    
    // Begin transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Delete existing samples for this order
      await client.query('DELETE FROM samples WHERE order_id = $1', [id]);
      
      // Create new samples with basic required fields only
      for (let i = 0; i < normalizedBarcodes.length; i++) {
        const barcode = normalizedBarcodes[i];
        
        await client.query(`
          INSERT INTO samples (order_id, barcode, status) 
          VALUES ($1, $2, $3)
        `, [id, barcode, 'pending']);
      }
      
      await client.query('COMMIT');
      
      await logAudit(req.user.userId, 'UPDATE', 'order', id, 
        `Assigned ${normalizedBarcodes.length} barcodes`);
      
      res.json({ 
        message: 'Barcodes assigned successfully',
        assigned_count: normalizedBarcodes.length,
        barcodes: normalizedBarcodes
      });
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Barcode assignment error:', error);
    res.status(500).json({ 
      error: 'Failed to assign barcodes',
      details: error.message 
    });
  }
});

// Basic samples endpoint
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        s.id,
        s.barcode,
        s.status,
        s.order_id,
        o.order_number,
        c.name as customer_name,
        c.company_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      ORDER BY s.id DESC
    `);
    
    console.log(`Returning ${result.rows.length} samples to frontend`);
    res.json(result.rows);
  } catch (error) {
    console.error('Samples fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch samples', details: error.message });
  }
});

// Basic batches endpoint
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        b.id,
        b.test_type,
        b.status,
        0 as sample_count
      FROM batches b
      ORDER BY b.id DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Batches fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch batches', details: error.message });
  }
});

// Sample receiving endpoint
app.post('/api/samples/receive', authenticateToken, async (req, res) => {
  try {
    const { barcode, location = 'Main Lab', notes = '' } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const sampleResult = await query(`
      SELECT s.*, o.order_number, c.name as customer_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE s.barcode = $1
    `, [barcode]);
    
    if (sampleResult.rows.length === 0) {
      return res.status(404).json({ error: 'Sample not found' });
    }
    
    const sample = sampleResult.rows[0];
    
    await query(`
      UPDATE samples SET status = 'received' WHERE id = $1
    `, [sample.id]);
    
    await logAudit(req.user.userId, 'UPDATE', 'sample', sample.id, `Received sample: ${barcode}`);
    
    res.json({ 
      message: 'Sample received successfully',
      sample: { ...sample, status: 'received' }
    });
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await Promise.all([
      query('SELECT COUNT(*) FROM orders WHERE status = $1', ['pending']),
      query('SELECT COUNT(*) FROM orders WHERE status = $1', ['shipped']),
      query('SELECT COUNT(*) FROM samples WHERE status = $1', ['processing']),
      query('SELECT COUNT(*) FROM orders WHERE status = $1', ['complete']),
      query('SELECT COUNT(*) FROM customers'),
      query('SELECT COUNT(*) FROM samples')
    ]);
    
    res.json({
      pending_orders: parseInt(stats[0].rows[0].count),
      shipped_orders: parseInt(stats[1].rows[0].count),
      processing_samples: parseInt(stats[2].rows[0].count),
      completed_orders: parseInt(stats[3].rows[0].count),
      total_customers: parseInt(stats[4].rows[0].count),
      total_samples: parseInt(stats[5].rows[0].count)
    });
    
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// User management endpoints
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT id, username, role, email, full_name
      FROM users 
      ORDER BY id DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, role, email, full_name } = req.body;
    
    if (!username || !password || !email || !full_name) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    const existingUser = await query('SELECT id FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    const existingEmail = await query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingEmail.rows.length > 0) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await query(`
      INSERT INTO users (username, password_hash, role, email, full_name)
      VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role, email, full_name
    `, [username, hashedPassword, role, email, full_name]);
    
    await logAudit(req.user.userId, 'CREATE', 'user', result.rows[0].id, `Created user: ${username}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Basic shipping endpoint
app.post('/api/shipping/manual-tracking', authenticateToken, async (req, res) => {
  try {
    const { order_id, tracking_number, carrier = 'UPS', service = 'Ground', cost = 0 } = req.body;
    
    if (!tracking_number) {
      return res.status(400).json({ error: 'Tracking number is required' });
    }
    
    await query(`
      UPDATE orders SET 
        tracking_number = $1,
        status = 'shipped'
      WHERE id = $2
    `, [tracking_number, order_id]);
    
    await logAudit(
      req.user.userId,
      'UPDATE',
      'order',
      order_id,
      `Manual tracking number added: ${tracking_number}`
    );
    
    res.json({
      message: 'Tracking number added successfully',
      tracking_number: tracking_number
    });
    
  } catch (error) {
    console.error('Manual tracking error:', error);
    res.status(500).json({ error: 'Failed to add tracking number' });
  }
});

// Barcode scanner endpoints
app.get('/api/scanner/status', authenticateToken, (req, res) => {
  res.json({
    hardware_connected: false,
    last_scan: null,
    scan_count: 0,
    scanner_type: 'Socket S700',
    manual_entry_enabled: true,
    batch_entry_enabled: true
  });
});

app.post('/api/scanner/validate', authenticateToken, async (req, res) => {
  try {
    const { barcode } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const isValid = validateBarcode(barcode);
    
    if (!isValid) {
      return res.json({
        valid: false,
        error: 'Barcode must be letters followed by numbers (e.g., BC000001)',
        format: 'BC000001 or CA123456'
      });
    }
    
    const existingSample = await query(`
      SELECT s.*, o.order_number, c.name as customer_name 
      FROM samples s 
      LEFT JOIN orders o ON s.order_id = o.id 
      LEFT JOIN customers c ON o.customer_id = c.id 
      WHERE s.barcode = $1
    `, [barcode.toUpperCase()]);
    
    res.json({
      valid: true,
      barcode: barcode.toUpperCase(),
      exists: existingSample.rows.length > 0,
      sample_info: existingSample.rows[0] || null
    });
    
  } catch (error) {
    console.error('Barcode validation error:', error);
    res.status(500).json({ error: 'Failed to validate barcode' });
  }
});

app.post('/api/scanner/validate-batch', authenticateToken, async (req, res) => {
  try {
    const { input } = req.body;
    
    if (!input || input.trim().length === 0) {
      return res.status(400).json({ error: 'Batch input is required' });
    }
    
    const lines = input.split('\n').map(line => line.trim()).filter(line => line.length > 0);
    const results = [];
    
    for (const line of lines) {
      const barcode = line.toUpperCase();
      
      if (!validateBarcode(barcode)) {
        return res.status(400).json({ 
          error: `Invalid barcode format: ${barcode}. Use format like BC000001` 
        });
      }
      
      const existingSample = await query(
        'SELECT id FROM samples WHERE barcode = $1',
        [barcode]
      );
      
      results.push({
        barcode: barcode,
        exists: existingSample.rows.length > 0
      });
    }
    
    const existingCount = results.filter(r => r.exists).length;
    const newCount = results.filter(r => !r.exists).length;
    
    res.json({
      total_barcodes: results.length,
      existing_samples: existingCount,
      new_samples: newCount,
      results: results
    });
    
  } catch (error) {
    console.error('Batch validation error:', error);
    res.status(500).json({ error: 'Failed to validate batch input' });
  }
});

app.get('/api/scanner/recent-activity', authenticateToken, async (req, res) => {
  try {
    const limit = req.query.limit || 20;
    
    const result = await query(`
      SELECT s.barcode, s.status, o.order_number, c.name as customer_name,
             'sample_received' as activity_type
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE s.status = 'received'
      ORDER BY s.id DESC
      LIMIT $1
    `, [limit]);
    
    res.json({
      activity: result.rows
    });
    
  } catch (error) {
    console.error('Recent activity fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch recent activity' });
  }
});

app.post('/api/scanner/receive-sample', authenticateToken, async (req, res) => {
  try {
    const { barcode, location = 'Main Lab', notes = '' } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const normalizedBarcode = barcode.toUpperCase();
    
    const sampleResult = await query(`
      SELECT s.*, o.order_number, c.name as customer_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE s.barcode = $1
    `, [normalizedBarcode]);

    if (sampleResult.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Sample not found',
        barcode: normalizedBarcode
      });
    }
    
    const sample = sampleResult.rows[0];
    
    if (sample.status === 'received') {
      return res.json({
        message: 'Sample was already received',
        sample,
        previously_received: true
      });
    }
    
    await query(`
      UPDATE samples SET status = 'received' WHERE id = $1
    `, [sample.id]);
    
    await logAudit(req.user.userId, 'RECEIVE', 'sample', sample.id, 
      `Received sample: ${normalizedBarcode}`);
    
    res.json({
      message: 'Sample received successfully',
      sample: { ...sample, status: 'received' },
      auto_created: false
    });
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

// Basic notifications endpoint
app.get('/api/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Return empty array for now since notifications table might not exist
    res.json([]);
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Basic audit log endpoint
app.get('/api/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Return empty array for now since audit_log table might not exist
    res.json({ logs: [] });
  } catch (error) {
    console.error('Audit log fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Version: 3.0.0 - Simplified for Basic Schema`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;