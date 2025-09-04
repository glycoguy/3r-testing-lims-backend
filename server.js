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
  origin: process.env.FRONTEND_URL || '*',
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
    const tableExists = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'audit_log'
      );
    `);
    
    if (tableExists.rows[0].exists) {
      await query(
        `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, action, entityType, entityId, details, 'system']
      );
    }
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
};

// Add these functions after your other helper functions

// WooCommerce Configuration
const WOOCOMMERCE_WEBHOOK_SECRET = process.env.WOOCOMMERCE_WEBHOOK_SECRET;

// Product mapping configuration
const PRODUCT_SAMPLE_MAPPING = {
  // Map WooCommerce product IDs/SKUs to sample types and counts
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
    // First try to find by WooCommerce ID
    if (wooCustomerData.id) {
      const existingCustomer = await query(
        'SELECT * FROM customers WHERE woocommerce_id = $1',
        [wooCustomerData.id]
      );
      
      if (existingCustomer.rows.length > 0) {
        return existingCustomer.rows[0];
      }
    }
    
    // Then try to find by email
    const existingByEmail = await query(
      'SELECT * FROM customers WHERE email = $1',
      [wooCustomerData.email]
    );
    
    if (existingByEmail.rows.length > 0) {
      // Update with WooCommerce ID if missing
      if (wooCustomerData.id && !existingByEmail.rows[0].woocommerce_id) {
        await query(
          'UPDATE customers SET woocommerce_id = $1 WHERE id = $2',
          [wooCustomerData.id, existingByEmail.rows[0].id]
        );
      }
      return existingByEmail.rows[0];
    }
    
    // Create new customer
    const customerResult = await query(`
      INSERT INTO customers (
        name, email, company_name, phone, 
        shipping_address, billing_address,
        woocommerce_id, woocommerce_username,
        created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [
      `${wooCustomerData.first_name} ${wooCustomerData.last_name}`.trim(),
      wooCustomerData.email,
      wooCustomerData.billing?.company || null,
      wooCustomerData.billing?.phone || null,
      formatAddress(wooCustomerData.shipping),
      formatAddress(wooCustomerData.billing),
      wooCustomerData.id || null,
      wooCustomerData.username || null,
      1 // System user for automated creation
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
      // Default fallback
      totalSampleCount += item.quantity;
      testTypes.add('HLVD');
    }
  });
  
  return {
    sample_count: totalSampleCount,
    test_type: testTypes.size === 1 ? Array.from(testTypes)[0] : 'MIXED'
  };
};

// Replace your addMissingColumns function with this improved version
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

// Improved addMissingColumns function
const addMissingColumns = async () => {
  try {
    console.log('Checking for missing columns...');
    
    // Define all columns that should exist
    const requiredColumns = {
      'users': [
        { name: 'full_name', type: 'VARCHAR(100)' },
        { name: 'is_active', type: 'BOOLEAN DEFAULT true' },
        { name: 'last_login', type: 'TIMESTAMP' },
        { name: 'password_changed_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' },
        { name: 'created_by', type: 'INTEGER' },
        { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
      ],
      'customers': [
        { name: 'woocommerce_id', type: 'INTEGER UNIQUE' },
        { name: 'woocommerce_username', type: 'VARCHAR(100)' },
        { name: 'created_by', type: 'INTEGER' },
        { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
      ],
      'orders': [
        { name: 'woocommerce_order_id', type: 'INTEGER UNIQUE' },
        { name: 'woocommerce_status', type: 'VARCHAR(50)' },
        { name: 'shipping_cost', type: 'DECIMAL(10,2)' },
        { name: 'shipping_service', type: 'VARCHAR(50)' },
        { name: 'shipping_carrier', type: 'VARCHAR(50)' },
        { name: 'shipping_api_used', type: 'VARCHAR(50) DEFAULT \'manual\'' },
        { name: 'label_created_at', type: 'TIMESTAMP' },
        { name: 'shipped_at', type: 'TIMESTAMP' },
        { name: 'delivered_at', type: 'TIMESTAMP' },
        { name: 'test_type', type: 'VARCHAR(100)' },
        { name: 'created_by', type: 'INTEGER' }
      ],
      'samples': [
        { name: 'batch_id', type: 'VARCHAR(50)' },
        { name: 'location', type: 'VARCHAR(100)' },
        { name: 'sample_type', type: 'VARCHAR(50) DEFAULT \'environmental\'' },
        { name: 'received_by', type: 'INTEGER' },
        { name: 'processed_by', type: 'INTEGER' }
      ]
    };
    
    // Check and add missing columns
    for (const [tableName, columns] of Object.entries(requiredColumns)) {
      for (const column of columns) {
        const exists = await columnExists(tableName, column.name);
        if (!exists) {
          try {
            await query(`ALTER TABLE ${tableName} ADD COLUMN ${column.name} ${column.type}`);
            console.log(`✅ Added column ${column.name} to ${tableName} table`);
          } catch (error) {
            if (!error.message.includes('already exists')) {
              console.error(`❌ Failed to add column ${column.name} to ${tableName}:`, error.message);
            }
          }
        }
      }
    }
    
    console.log('✅ All required columns verified/added');
  } catch (error) {
    console.error('❌ Error adding missing columns:', error);
    throw error;
  }
};

// VALIDATEBARCODE FUNCTION:
const validateBarcode = (barcode) => {
  // Allow letters followed by numbers (more flexible than the original 8-character limit)
  const pattern = /^[A-Z]+\d+$/;
  return pattern.test(barcode.toUpperCase());
};

// Add this complete initializeDatabase function to replace the incomplete one
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
    // Create users table
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        email VARCHAR(100),
        full_name VARCHAR(100),
        is_active BOOLEAN DEFAULT true,
        last_login TIMESTAMP,
        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create customers table
    await query(`
      CREATE TABLE IF NOT EXISTS customers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        company_name VARCHAR(100),
        phone VARCHAR(20),
        shipping_address TEXT,
        billing_address TEXT,
        notes TEXT,
        woocommerce_id INTEGER,
        woocommerce_username VARCHAR(100),
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create orders table
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        order_number VARCHAR(50) UNIQUE,
        sample_count INTEGER NOT NULL,
        shipping_method VARCHAR(50),
        priority VARCHAR(20) DEFAULT 'normal',
        status VARCHAR(50) DEFAULT 'pending',
        tracking_number VARCHAR(100),
        notes TEXT,
        woocommerce_order_id INTEGER,
        woocommerce_status VARCHAR(50),
        shipping_cost DECIMAL(10,2),
        shipping_service VARCHAR(50),
        shipping_carrier VARCHAR(50),
        shipping_api_used VARCHAR(50) DEFAULT 'manual',
        label_created_at TIMESTAMP,
        shipped_at TIMESTAMP,
        delivered_at TIMESTAMP,
        test_type VARCHAR(100),
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create samples table
    await query(`
      CREATE TABLE IF NOT EXISTS samples (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        barcode VARCHAR(50) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        sample_type VARCHAR(50) DEFAULT 'environmental',
        received_at TIMESTAMP,
        processed_at TIMESTAMP,
        completed_at TIMESTAMP,
        batch_id VARCHAR(50),
        location VARCHAR(100),
        notes TEXT,
        received_by INTEGER,
        processed_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create batches table
    await query(`
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY,
        batch_id VARCHAR(50) UNIQUE NOT NULL,
        test_type VARCHAR(100),
        status VARCHAR(50) DEFAULT 'active',
        sample_count INTEGER DEFAULT 0,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        notes TEXT,
        created_by INTEGER
      )
    `);

    // Create test_results table
    await query(`
      CREATE TABLE IF NOT EXISTS test_results (
        id SERIAL PRIMARY KEY,
        sample_id INTEGER REFERENCES samples(id),
        test_type VARCHAR(100) NOT NULL,
        result VARCHAR(50),
        value DECIMAL(10,3),
        units VARCHAR(20),
        detection_limit DECIMAL(10,3),
        method VARCHAR(100),
        analyst VARCHAR(100),
        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        notes TEXT
      )
    `);

    // Create email_notifications table
    await query(`
      CREATE TABLE IF NOT EXISTS email_notifications (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        notification_type VARCHAR(100),
        recipient_email VARCHAR(255),
        recipient_name VARCHAR(255),
        subject VARCHAR(500),
        body TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        sent_at TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create audit_log table
    await query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        action VARCHAR(50),
        entity_type VARCHAR(50),
        entity_id INTEGER,
        details TEXT,
        ip_address VARCHAR(50),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create shipping_labels table (for manual tracking support)
    await query(`
      CREATE TABLE IF NOT EXISTS shipping_labels (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        tracking_number VARCHAR(100),
        carrier VARCHAR(50),
        service VARCHAR(100),
        cost DECIMAL(10,2),
        label_url VARCHAR(500),
        label_data TEXT,
        api_provider VARCHAR(50) DEFAULT 'manual',
        api_response JSONB,
        status VARCHAR(50) DEFAULT 'created',
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create woocommerce_webhook_log table
    await query(`
      CREATE TABLE IF NOT EXISTS woocommerce_webhook_log (
        id SERIAL PRIMARY KEY,
        webhook_id VARCHAR(100),
        event_type VARCHAR(50),
        order_id INTEGER,
        customer_id INTEGER,
        status VARCHAR(20) DEFAULT 'received',
        payload JSONB,
        processed_at TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Fix any missing columns in existing tables
    await addMissingColumns();

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

    console.log('✅ Database tables initialized successfully');
    
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
    version: '3.0.0'
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
      'SELECT * FROM users WHERE username = $1 AND is_active = true',
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
    
    await query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );
    
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

// WooCommerce Webhook Handler
app.post('/api/webhooks/woocommerce', async (req, res) => {
  try {
    const signature = req.headers['x-wc-webhook-signature'];
    const body = req.body;
    
    // Verify webhook signature
    if (!verifyWooCommerceSignature(body, signature)) {
      console.error('Invalid WooCommerce webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    const orderData = JSON.parse(body.toString());
    console.log('Received WooCommerce webhook for order:', orderData.id);
    
    // Only process completed/processing orders
    if (!['completed', 'processing', 'paid'].includes(orderData.status)) {
      console.log(`Ignoring order ${orderData.id} with status: ${orderData.status}`);
      return res.status(200).json({ message: 'Order status not eligible for processing' });
    }
    
    // Check if order already exists
    const existingOrder = await query(
      'SELECT * FROM orders WHERE woocommerce_order_id = $1',
      [orderData.id]
    );
    
    if (existingOrder.rows.length > 0) {
      console.log(`Order ${orderData.id} already exists in LIMS`);
      return res.status(200).json({ message: 'Order already exists' });
    }
    
    // Find or create customer
    const customer = await findOrCreateCustomer({
      id: orderData.customer_id,
      email: orderData.billing.email,
      first_name: orderData.billing.first_name,
      last_name: orderData.billing.last_name,
      username: orderData.customer_id ? `customer_${orderData.customer_id}` : null,
      billing: orderData.billing,
      shipping: orderData.shipping
    });
    
    // Parse line items to determine sample count and test type
    const orderDetails = parseOrderLineItems(orderData.line_items);
    
    // Create LIMS order
    const orderResult = await query(`
      INSERT INTO orders (
        customer_id, order_number, sample_count, test_type,
        status, woocommerce_order_id, woocommerce_status,
        shipping_method, priority, notes, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *
    `, [
      customer.id,
      `WOO-${orderData.id}`,
      orderDetails.sample_count,
      orderDetails.test_type,
      'pending',
      orderData.id,
      orderData.status,
      'ups_ground',
      orderData.total > 100 ? 'high' : 'normal',
      `Auto-created from WooCommerce order #${orderData.id}. Total: $${orderData.total}`,
      1 // System user
    ]);
    
    const limsOrder = orderResult.rows[0];
    
    // Create placeholder samples with auto-generated barcodes
    for (let i = 1; i <= orderDetails.sample_count; i++) {
      const barcode = `WOO${orderData.id}S${i.toString().padStart(2, '0')}`;
      await query(`
        INSERT INTO samples (order_id, barcode, sample_type, status) 
        VALUES ($1, $2, $3, $4)
      `, [limsOrder.id, barcode, orderDetails.test_type, 'pending']);
    }
    
    // Log the webhook processing
    await query(`
      INSERT INTO woocommerce_webhook_log (
        webhook_id, event_type, order_id, customer_id, 
        status, payload, processed_at
      ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
    `, [
      orderData.id, 
      'order.completed', 
      limsOrder.id, 
      customer.id, 
      'processed', 
      JSON.stringify(orderData)
    ]);
    
    await logAudit(1, 'CREATE', 'order', limsOrder.id, `Auto-created from WooCommerce order #${orderData.id}`);
    
    console.log(`✅ Successfully processed WooCommerce order ${orderData.id} -> LIMS order ${limsOrder.order_number}`);
    
    res.status(200).json({ 
      message: 'Order processed successfully',
      lims_order_id: limsOrder.id,
      lims_order_number: limsOrder.order_number,
      sample_count: orderDetails.sample_count
    });
    
  } catch (error) {
    console.error('❌ WooCommerce webhook processing error:', error);
    
    // Log failed webhook
    try {
      await query(`
        INSERT INTO woocommerce_webhook_log (
          webhook_id, event_type, status, error_message, payload
        ) VALUES ($1, $2, $3, $4, $5)
      `, [
        req.body?.id || 'unknown',
        'order.completed',
        'failed',
        error.message,
        JSON.stringify(req.body)
      ]);
    } catch (logError) {
      console.error('Failed to log webhook error:', logError);
    }
    
    res.status(500).json({ 
      error: 'Failed to process order',
      details: error.message 
    });
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
      'UPDATE users SET password_hash = $1, password_changed_at = CURRENT_TIMESTAMP WHERE id = $2',
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
             COUNT(o.id) as total_orders,
             MAX(o.created_at) as last_order_date
      FROM customers c
      LEFT JOIN orders o ON c.id = o.customer_id
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Customers fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
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
      INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, created_by)
      VALUES ($1, $2, $3, $4, $5, $5, $6) RETURNING *
    `, [name, email, company_name, phone, shipping_address, req.user.userId]);
    
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
             COUNT(s.id) as received_samples,
             STRING_AGG(DISTINCT s.status, ', ') as sample_statuses
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN samples s ON o.id = s.order_id
      GROUP BY o.id, c.id
      ORDER BY o.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// FIXED: Remove the duplicate and fix the barcode assignment endpoint
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
      
      // Flexible validation - letters followed by numbers
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
      
      // Create new samples with assigned barcodes including ALL required fields
      for (let i = 0; i < normalizedBarcodes.length; i++) {
        const barcode = normalizedBarcodes[i];
        
        await client.query(`
          INSERT INTO samples (
            order_id, barcode, status, sample_type, 
            batch_id, location, notes, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
        `, [
          id, 
          barcode, 
          'pending',
          order.test_type || 'environmental',
          null, // batch_id starts as null
          null, // location starts as null
          null  // notes starts as null
        ]);
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

// FIXED: Order creation endpoint to handle missing customers table references
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
      INSERT INTO orders (
        customer_id, order_number, sample_count, priority, 
        shipping_method, status, notes, created_by, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP) RETURNING *
    `, [customer_id, orderNumber, sample_count, priority, shipping_method, 'pending', notes, req.user.userId]);
    
    await logAudit(req.user.userId, 'CREATE', 'order', result.rows[0].id, `Created order: ${orderNumber}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// FIXED: Samples endpoint with proper column selection
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        s.id,
        s.barcode,
        s.status,
        s.sample_type,
        s.received_at,
        s.processed_at,
        s.completed_at,
        s.batch_id,
        s.location,
        s.notes,
        s.created_at,
        s.order_id,
        o.order_number,
        c.name as customer_name,
        c.company_name,
        u1.full_name as received_by_name,
        u2.full_name as processed_by_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN users u1 ON s.received_by = u1.id
      LEFT JOIN users u2 ON s.processed_by = u2.id
      ORDER BY s.created_at DESC
    `);
    
    console.log(`Returning ${result.rows.length} samples to frontend`);
    res.json(result.rows);
  } catch (error) {
    console.error('Samples fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch samples', details: error.message });
  }
});

// FIXED: Batches endpoint with proper column selection
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        b.id,
        b.batch_id,
        b.test_type,
        b.status,
        b.sample_count,
        b.started_at,
        b.completed_at,
        b.notes,
        b.created_by,
        COUNT(s.id) as actual_sample_count,
        u.full_name as created_by_name
      FROM batches b
      LEFT JOIN samples s ON b.batch_id = s.batch_id
      LEFT JOIN users u ON b.created_by = u.id
      GROUP BY b.id, b.batch_id, b.test_type, b.status, b.sample_count, 
               b.started_at, b.completed_at, b.notes, b.created_by, u.full_name
      ORDER BY b.started_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Batches fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch batches', details: error.message });
  }
});


app.get('/api/orders/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const orderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email,
             c.company_name, c.shipping_address
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [id]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    const samplesResult = await query(`
      SELECT s.*, tr.test_type, tr.result, tr.value, tr.units
      FROM samples s
      LEFT JOIN test_results tr ON s.id = tr.sample_id
      WHERE s.order_id = $1
      ORDER BY s.barcode
    `, [id]);
    
    const samples = samplesResult.rows;
    
    const doc = new PDFDocument();
    let buffers = [];
    
    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', () => {
      const pdfBuffer = Buffer.concat(buffers);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="3R_Testing_Results_${order.order_number}.pdf"`);
      res.send(pdfBuffer);
    });
    
    doc.fontSize(20).text('3R Testing Laboratory', 50, 50);
    doc.fontSize(16).text('Pathogen Testing Results Report', 50, 80);
    doc.fontSize(12).text(`Report Generated: ${new Date().toLocaleDateString()}`, 50, 110);
    
    doc.fontSize(14).text('Order Information', 50, 150);
    doc.fontSize(10)
       .text(`Order Number: ${order.order_number}`, 50, 170)
       .text(`Customer: ${order.customer_name}`, 50, 185)
       .text(`Company: ${order.company_name || 'N/A'}`, 50, 200);
    
    let yPosition = 250;
    doc.fontSize(14).text('Test Results', 50, yPosition);
    yPosition += 25;
    
    doc.fontSize(9)
       .text('Barcode', 50, yPosition)
       .text('Test Type', 150, yPosition)
       .text('Result', 250, yPosition);
    
    yPosition += 20;
    
    samples.forEach(sample => {
      doc.text(sample.barcode, 50, yPosition)
         .text(sample.test_type || 'N/A', 150, yPosition)
         .text(sample.result || 'Pending', 250, yPosition);
      
      yPosition += 15;
    });
    
    doc.end();
    
  } catch (error) {
    console.error('PDF download error:', error);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});


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
      UPDATE samples SET 
        status = 'received',
        received_at = CURRENT_TIMESTAMP,
        received_by = $1,
        location = $2,
        notes = $3
      WHERE id = $4
    `, [req.user.userId, location, notes, sample.id]);
    
    await logAudit(req.user.userId, 'UPDATE', 'sample', sample.id, `Received sample: ${barcode}`);
    
    res.json({ 
      message: 'Sample received successfully',
      sample: { ...sample, status: 'received', location, notes }
    });
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

app.patch('/api/samples/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, batch_id, notes } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    let updateQuery = 'UPDATE samples SET status = $1';
    let params = [status];
    let paramCount = 1;
    
    if (batch_id) {
      paramCount++;
      updateQuery += `, batch_id = $${paramCount}`;
      params.push(batch_id);
    }
    
    if (notes) {
      paramCount++;
      updateQuery += `, notes = $${paramCount}`;
      params.push(notes);
    }
    
    if (status === 'processing') {
      updateQuery += ', processed_at = CURRENT_TIMESTAMP, processed_by = $' + (paramCount + 1);
      params.push(req.user.userId);
      paramCount++;
    }
    
    if (status === 'complete') {
      updateQuery += ', completed_at = CURRENT_TIMESTAMP';
    }
    
    updateQuery += ` WHERE id = $${paramCount + 1} RETURNING *`;
    params.push(id);
    
    const result = await query(updateQuery, params);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sample not found' });
    }
    
    await logAudit(req.user.userId, 'UPDATE', 'sample', id, `Updated status to: ${status}`);
    
    res.json(result.rows[0]);
    
  } catch (error) {
    console.error('Sample status update error:', error);
    res.status(500).json({ error: 'Failed to update sample status' });
  }
});

app.post('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { test_type, result, value, units, detection_limit, method, notes } = req.body;
    
    if (!test_type || !result) {
      return res.status(400).json({ error: 'Test type and result are required' });
    }
    
    const resultRecord = await query(`
      INSERT INTO test_results (
        sample_id, test_type, result, value, units, 
        detection_limit, method, analyst, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [id, test_type, result, value, units, detection_limit, method, req.user.username, notes]);
    
    await query(`
      UPDATE samples SET 
        status = 'complete',
        completed_at = CURRENT_TIMESTAMP,
        processed_by = $1
      WHERE id = $2
    `, [req.user.userId, id]);
    
    const sampleResult = await query('SELECT order_id FROM samples WHERE id = $1', [id]);
    const orderId = sampleResult.rows[0].order_id;
    
    const incompleteSamples = await query(
      'SELECT COUNT(*) FROM samples WHERE order_id = $1 AND status != $2',
      [orderId, 'complete']
    );
    
    if (parseInt(incompleteSamples.rows[0].count) === 0) {
      await query('UPDATE orders SET status = $1 WHERE id = $2', ['complete', orderId]);
    }
    
    await logAudit(req.user.userId, 'CREATE', 'test_result', resultRecord.rows[0].id, 
      `Added ${test_type} result: ${result}`);
    
    res.json({ 
      message: 'Test result added successfully',
      result: resultRecord.rows[0]
    });
    
  } catch (error) {
    console.error('Test result creation error:', error);
    res.status(500).json({ error: 'Failed to add test result' });
  }
});


app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { test_type, sample_ids, notes } = req.body;
    
    if (!test_type || !sample_ids || !Array.isArray(sample_ids)) {
      return res.status(400).json({ error: 'Test type and sample IDs are required' });
    }
    
    const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const batchId = `BATCH-${test_type}-${timestamp}-${Date.now().toString().slice(-4)}`;
    
    const batchResult = await query(`
      INSERT INTO batches (batch_id, test_type, sample_count, notes, created_by)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `, [batchId, test_type, sample_ids.length, notes, req.user.userId]);
    
    await query(`
      UPDATE samples SET 
        batch_id = $1,
        status = 'processing',
        processed_at = CURRENT_TIMESTAMP,
        processed_by = $2
      WHERE id = ANY($3::int[])
    `, [batchId, req.user.userId, sample_ids]);
    
    await logAudit(req.user.userId, 'CREATE', 'batch', batchResult.rows[0].id, 
      `Created batch ${batchId} with ${sample_ids.length} samples`);
    
    res.status(201).json({
      message: 'Batch created successfully',
      batch: batchResult.rows[0]
    });
    
  } catch (error) {
    console.error('Batch creation error:', error);
    res.status(500).json({ error: 'Failed to create batch' });
  }
});

// User management endpoints
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT id, username, role, email, full_name, is_active, 
             last_login, created_at, created_by
      FROM users 
      ORDER BY created_at DESC
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
      INSERT INTO users (username, password_hash, role, email, full_name, created_by)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, username, role, email, full_name, is_active, created_at
    `, [username, hashedPassword, role, email, full_name, req.user.userId]);
    
    await logAudit(req.user.userId, 'CREATE', 'user', result.rows[0].id, `Created user: ${username}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.patch('/api/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }
    
    const result = await query(`
      UPDATE users SET 
        is_active = NOT is_active,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1 RETURNING is_active, username
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    const action = user.is_active ? 'activated' : 'deactivated';
    
    await logAudit(req.user.userId, 'UPDATE', 'user', id, `User ${action}: ${user.username}`);
    
    res.json({ 
      message: `User ${action} successfully`,
      is_active: user.is_active 
    });
    
  } catch (error) {
    console.error('User toggle error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
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
      query('SELECT COUNT(*) FROM orders WHERE woocommerce_order_id IS NOT NULL'),
      query('SELECT COUNT(*) FROM customers'),
      query('SELECT COUNT(*) FROM samples')
    ]);
    
    res.json({
      pending_orders: parseInt(stats[0].rows[0].count),
      shipped_orders: parseInt(stats[1].rows[0].count),
      processing_samples: parseInt(stats[2].rows[0].count),
      completed_orders: parseInt(stats[3].rows[0].count),
      woocommerce_orders: parseInt(stats[4].rows[0].count),
      total_customers: parseInt(stats[5].rows[0].count),
      total_samples: parseInt(stats[6].rows[0].count)
    });
    
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// Admin endpoints
app.get('/api/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = req.query.limit || 50;
    const result = await query(`
      SELECT a.*, u.username, u.full_name
      FROM audit_log a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.timestamp DESC
      LIMIT $1
    `, [limit]);
    
    res.json({ logs: result.rows });
  } catch (error) {
    console.error('Audit log fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

app.get('/api/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT en.*, o.order_number, c.name as recipient_name
      FROM email_notifications en
      LEFT JOIN orders o ON en.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      ORDER BY en.created_at DESC
      LIMIT 100
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.post('/api/notifications/:id/resend', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const notificationResult = await query(`
      SELECT en.*, o.id as order_id
      FROM email_notifications en
      LEFT JOIN orders o ON en.order_id = o.id
      WHERE en.id = $1
    `, [id]);
    
    if (notificationResult.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    await query(
      'UPDATE email_notifications SET status = $1, sent_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['sent', id]
    );
    
    res.json({ message: 'Notification resent successfully' });
    
  } catch (error) {
    console.error('Notification resend error:', error);
    res.status(500).json({ error: 'Failed to resend notification' });
  }
});

// Backup endpoint
app.post('/api/backup/create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const tables = ['users', 'customers', 'orders', 'samples', 'test_results', 'batches'];
    const backupData = {};
    
    for (const table of tables) {
      const result = await query(`SELECT * FROM ${table}`);
      backupData[table] = result.rows;
    }
    
    await logAudit(req.user.userId, 'CREATE', 'backup', null, 'Database backup created');
    
    res.json({ 
      message: 'Backup created successfully',
      timestamp: new Date().toISOString(),
      tables: tables,
      total_records: Object.values(backupData).reduce((sum, records) => sum + records.length, 0)
    });
    
  } catch (error) {
    console.error('Backup creation error:', error);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

// Shipping endpoints
app.post('/api/shipping/manual-tracking', authenticateToken, async (req, res) => {
  try {
    const { order_id, tracking_number, carrier = 'UPS', service = 'Ground', cost = 0 } = req.body;
    
    if (!tracking_number) {
      return res.status(400).json({ error: 'Tracking number is required' });
    }
    
    await query(`
      UPDATE orders SET 
        tracking_number = $1,
        shipping_carrier = $2,
        shipping_service = $3,
        shipping_cost = $4,
        shipping_api_used = 'manual',
        label_created_at = CURRENT_TIMESTAMP,
        status = CASE WHEN status = 'pending' THEN 'shipped' ELSE status END,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
    `, [tracking_number, carrier, service, cost, order_id]);
    
    await logAudit(
      req.user.userId,
      'CREATE',
      'shipping_label',
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

// Get shipping rates for an order
app.get('/api/shipping/rates/:order_id', authenticateToken, async (req, res) => {
  try {
    const { order_id } = req.params;
    
    // Get order details
    const orderResult = await query(`
      SELECT o.*, c.shipping_address, c.billing_address, c.name as customer_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [order_id]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    // Return standard shipping rates (can be enhanced with real API calls later)
    const rates = [
      {
        service: 'ups_ground',
        name: 'UPS Ground',
        cost: 8.50,
        delivery_days: '1-5 business days',
        recommended: true,
        api_provider: 'manual'
      },
      {
        service: 'ups_2day',
        name: 'UPS 2nd Day Air',
        cost: 15.99,
        delivery_days: '2 business days',
        recommended: false,
        api_provider: 'manual'
      },
      {
        service: 'ups_next_day',
        name: 'UPS Next Day Air',
        cost: 25.99,
        delivery_days: '1 business day',
        recommended: false,
        api_provider: 'manual'
      }
    ];
    
    res.json({ 
      rates,
      order_info: {
        order_number: order.order_number,
        customer_name: order.customer_name,
        sample_count: order.sample_count
      }
    });
  } catch (error) {
    console.error('Shipping rates error:', error);
    res.status(500).json({ error: 'Failed to get shipping rates' });
  }
});

// Track shipment endpoint
app.get('/api/shipping/track/:tracking_number', authenticateToken, async (req, res) => {
  try {
    const { tracking_number } = req.params;
    
    // Get shipping info from database
    const shippingResult = await query(`
      SELECT sl.*, o.order_number, o.customer_id, c.name as customer_name
      FROM shipping_labels sl
      JOIN orders o ON sl.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE sl.tracking_number = $1
    `, [tracking_number]);
    
    if (shippingResult.rows.length === 0) {
      // Check if tracking number is directly in orders table
      const orderResult = await query(`
        SELECT o.*, c.name as customer_name
        FROM orders o
        JOIN customers c ON o.customer_id = c.id
        WHERE o.tracking_number = $1
      `, [tracking_number]);
      
      if (orderResult.rows.length === 0) {
        return res.status(404).json({ error: 'Tracking number not found' });
      }
      
      const order = orderResult.rows[0];
      
      // Return basic manual tracking info
      res.json({
        tracking_number: tracking_number,
        status: order.status === 'shipped' ? 'in_transit' : order.status,
        status_description: 'Manual tracking - check carrier website for detailed updates',
        location: 'In Transit',
        carrier: order.shipping_carrier || 'UPS',
        service: order.shipping_service || 'Ground',
        order_number: order.order_number,
        customer_name: order.customer_name,
        api_provider: 'manual'
      });
      return;
    }
    
    const shippingInfo = shippingResult.rows[0];
    
    // For manual tracking, return basic status
    const trackingResult = {
      tracking_number: tracking_number,
      status: 'in_transit',
      status_description: 'Package is in transit - check carrier website for updates',
      location: 'In Transit',
      carrier: shippingInfo.carrier,
      service: shippingInfo.service,
      order_number: shippingInfo.order_number,
      customer_name: shippingInfo.customer_name,
      api_provider: shippingInfo.api_provider || 'manual'
    };
    
    res.json(trackingResult);
    
  } catch (error) {
    console.error('Tracking error:', error);
    res.status(500).json({ error: 'Failed to track shipment' });
  }
});

// Update order status when delivered
app.patch('/api/orders/:id/delivery-status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { delivered = true } = req.body;
    
    await query(`
      UPDATE orders SET 
        status = $1,
        delivered_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
    `, [delivered ? 'delivered' : 'shipped', id]);
    
    await logAudit(req.user.userId, 'UPDATE', 'order', id, 
      `Order delivery status updated: ${delivered ? 'delivered' : 'shipped'}`);
    
    res.json({ message: 'Delivery status updated successfully' });
    
  } catch (error) {
    console.error('Delivery status update error:', error);
    res.status(500).json({ error: 'Failed to update delivery status' });
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
        error: 'Barcode must be 8 alphanumeric characters',
        format: 'AB123456 or 12345678'
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
    
    if (sample.status === 'received' || sample.received_at) {
      return res.json({
        message: 'Sample was already received',
        sample,
        previously_received: true,
        received_at: sample.received_at
      });
    }
    
    await query(`
      UPDATE samples SET 
        status = 'received',
        received_at = CURRENT_TIMESTAMP,
        received_by = $1,
        location = $2,
        notes = COALESCE(notes || ' | ', '') || $3
      WHERE id = $4
    `, [req.user.userId, location, notes, sample.id]);
    
    await logAudit(req.user.userId, 'RECEIVE', 'sample', sample.id, 
      `Received sample: ${normalizedBarcode}`);
    
    res.json({
      message: 'Sample received successfully',
      sample: { ...sample, status: 'received', location, notes },
      auto_created: false
    });
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

app.get('/api/scanner/recent-activity', authenticateToken, async (req, res) => {
  try {
    const limit = req.query.limit || 20;
    
    const result = await query(`
      SELECT s.barcode, s.status, s.received_at, s.location,
             o.order_number, c.name as customer_name,
             u.full_name as received_by_name,
             'sample_received' as activity_type
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN users u ON s.received_by = u.id
      WHERE s.received_at IS NOT NULL
      ORDER BY s.received_at DESC
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

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Version: 3.0.0 - Complete`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;