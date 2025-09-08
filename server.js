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
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const multer = require('multer');


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

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/reports';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only PDF files are allowed'), false);
    }
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be set in production');
  }
  console.warn('⚠️  Using default JWT secret - ONLY for development!');
  return '3rtesting-super-secure-secret-key';
})();

// Middleware
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', process.env.FRONTEND_URL || '*'],
  credentials: true
}));

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: 'Too many login attempts, please try again later.' }
});

app.use('/api/webhooks/woocommerce', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use('/api/', limiter);
app.use('/api/auth/login', loginLimiter);

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

// Generate proper order number
const generateOrderNumber = async () => {
  const currentYear = new Date().getFullYear();
  const result = await query(`
    SELECT COALESCE(MAX(CAST(SUBSTRING(order_number FROM 5) AS INTEGER)), 0) as max_number
    FROM orders 
    WHERE order_number ~ '^${currentYear}[0-9]{6}$'
  `);
  
  const nextNumber = (result.rows[0].max_number || 0) + 1;
  return `${currentYear}${nextNumber.toString().padStart(6, '0')}`;
};

// Generate sub-order suffix
const generateSubOrderSuffix = async (parentOrderNumber) => {
  const result = await query(`
    SELECT sub_order_suffix 
    FROM orders 
    WHERE parent_order_number = $1 
    ORDER BY sub_order_suffix DESC 
    LIMIT 1
  `, [parentOrderNumber]);
  
  if (result.rows.length === 0) {
    return 'a';
  }
  
  const lastSuffix = result.rows[0].sub_order_suffix;
  const nextCharCode = lastSuffix.charCodeAt(0) + 1;
  return String.fromCharCode(nextCharCode);
};

// Enhanced database initialization
async function initializeDatabase() {
  try {
    console.log('Initializing enhanced database schema...');
    
    // Create basic users table
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        email VARCHAR(100),
        full_name VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create enhanced customers table
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
        woocommerce_id INTEGER UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create enhanced orders table with sub-order support
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        order_number VARCHAR(50) UNIQUE NOT NULL,
        parent_order_number VARCHAR(50),
        sub_order_suffix VARCHAR(5),
        sample_count INTEGER NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        tracking_number VARCHAR(100),
        shipping_carrier VARCHAR(50),
        shipping_service VARCHAR(50),
        shipping_cost DECIMAL(10,2),
        notes TEXT,
        priority VARCHAR(20) DEFAULT 'normal',
        test_type VARCHAR(100),
        woocommerce_order_id INTEGER UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id)
      )
    `);

    // Create enhanced samples table
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
        location VARCHAR(100),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        received_by INTEGER REFERENCES users(id),
        processed_by INTEGER REFERENCES users(id)
      )
    `);

    // Create enhanced batches table
    await query(`
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY,
        batch_number VARCHAR(50) UNIQUE,
        test_type VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        completed_at TIMESTAMP
      )
    `);

    // Create batch_samples junction table
    await query(`
      CREATE TABLE IF NOT EXISTS batch_samples (
        id SERIAL PRIMARY KEY,
        batch_id INTEGER REFERENCES batches(id),
        sample_id INTEGER REFERENCES samples(id),
        position INTEGER CHECK (position >= 1 AND position <= 96),
        is_control BOOLEAN DEFAULT FALSE,
        control_type VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(batch_id, position)
      )
    `);

    // Create reports table
    await query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        report_number VARCHAR(50) UNIQUE NOT NULL,
        original_filename VARCHAR(255),
        file_path VARCHAR(500),
        file_size INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        uploaded_by INTEGER REFERENCES users(id),
        emailed_to_customer BOOLEAN DEFAULT FALSE,
        email_sent_at TIMESTAMP
      )
    `);

    // Create test_results table
    await query(`
      CREATE TABLE IF NOT EXISTS test_results (
        id SERIAL PRIMARY KEY,
        sample_id INTEGER REFERENCES samples(id),
        batch_id INTEGER REFERENCES batches(id),
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

    // Create order number sequence
    await query(`
      CREATE SEQUENCE IF NOT EXISTS order_number_seq START 1
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

    console.log('✅ Enhanced database schema initialized successfully');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Enhanced order creation with sub-order support
const createSubOrder = async (parentOrder, receivedSamples, userId) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const suffix = await generateSubOrderSuffix(parentOrder.order_number);
    const subOrderNumber = `${parentOrder.order_number}${suffix}`;
    
    // Create sub-order
    const subOrderResult = await client.query(`
      INSERT INTO orders (
        customer_id, order_number, parent_order_number, sub_order_suffix,
        sample_count, status, test_type, priority, notes, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *
    `, [
      parentOrder.customer_id,
      subOrderNumber,
      parentOrder.order_number,
      suffix,
      receivedSamples.length,
      'received',
      parentOrder.test_type,
      parentOrder.priority,
      `Sub-order created from ${parentOrder.order_number} with ${receivedSamples.length} received samples`,
      userId
    ]);
    
    const subOrder = subOrderResult.rows[0];
    
    // Update received samples to belong to sub-order
    for (const sample of receivedSamples) {
      await client.query(
        'UPDATE samples SET order_id = $1 WHERE id = $2',
        [subOrder.id, sample.id]
      );
    }
    
    // Update parent order status
    const allSamples = await client.query(
      'SELECT COUNT(*) as total FROM samples WHERE order_id = $1',
      [parentOrder.id]
    );
    
    const receivedCount = await client.query(
      'SELECT COUNT(*) as received FROM samples WHERE order_id = $1 AND status IN ($2, $3, $4)',
      [parentOrder.id, 'received', 'processing', 'complete']
    );
    
    const parentStatus = receivedCount.rows[0].received > 0 ? 'partial' : parentOrder.status;
    await client.query(
      'UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [parentStatus, parentOrder.id]
    );
    
    await client.query('COMMIT');
    return subOrder;
    
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};

// Email notification function
const sendCustomerEmail = async (customerEmail, customerName, subject, htmlContent, pdfAttachment = null) => {
  try {
    const mailOptions = {
      from: process.env.SMTP_USER,
      to: customerEmail,
      subject: subject,
      html: htmlContent
    };
    
    if (pdfAttachment) {
      mailOptions.attachments = [{
        filename: pdfAttachment.filename,
        path: pdfAttachment.path
      }];
    }
    
    await emailTransporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending failed:', error);
    return false;
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: '3R Testing LIMS Backend - Enhanced Version',
    version: '4.0.0 - Complete LIMS Implementation'
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
      'SELECT * FROM users WHERE username = $1 AND is_active = TRUE',
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

// Enhanced Customer endpoints
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT c.*, 
             COUNT(o.id) as total_orders,
             COUNT(CASE WHEN o.status = 'complete' THEN 1 END) as completed_orders
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
    const { name, email, company_name, phone, shipping_address, billing_address, notes } = req.body;
    
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
      INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
    `, [name, email, company_name, phone, shipping_address, billing_address, notes]);
    
    await logAudit(req.user.userId, 'CREATE', 'customer', result.rows[0].id, `Created customer: ${name}`);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Customer creation error:', error);
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

app.put('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, company_name, phone, shipping_address, billing_address, notes } = req.body;
    
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // Check if email exists for another customer
    const existingCustomer = await query(
      'SELECT id FROM customers WHERE email = $1 AND id != $2',
      [email, id]
    );
    
    if (existingCustomer.rows.length > 0) {
      return res.status(409).json({ error: 'Email already exists for another customer' });
    }
    
    const result = await query(`
      UPDATE customers SET 
        name = $1, email = $2, company_name = $3, phone = $4, 
        shipping_address = $5, billing_address = $6, notes = $7, 
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $8 RETURNING *
    `, [name, email, company_name, phone, shipping_address, billing_address, notes, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    await logAudit(req.user.userId, 'UPDATE', 'customer', id, `Updated customer: ${name}`);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Customer update error:', error);
    res.status(500).json({ error: 'Failed to update customer' });
  }
});

app.delete('/api/customers/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if customer has orders
    const ordersCount = await query(
      'SELECT COUNT(*) as count FROM orders WHERE customer_id = $1',
      [id]
    );
    
    if (parseInt(ordersCount.rows[0].count) > 0) {
      return res.status(400).json({ error: 'Cannot delete customer with existing orders' });
    }
    
    const result = await query('DELETE FROM customers WHERE id = $1 RETURNING *', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    await logAudit(req.user.userId, 'DELETE', 'customer', id, `Deleted customer: ${result.rows[0].name}`);
    
    res.json({ message: 'Customer deleted successfully' });
  } catch (error) {
    console.error('Customer deletion error:', error);
    res.status(500).json({ error: 'Failed to delete customer' });
  }
});

// Enhanced Order endpoints
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT o.*, 
             c.name as customer_name,
             c.email as customer_email,
             c.company_name,
             COUNT(s.id) as received_samples,
             COUNT(r.id) as report_count,
             CASE 
               WHEN o.parent_order_number IS NOT NULL THEN 'sub-order'
               ELSE 'main-order'
             END as order_type
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN samples s ON o.id = s.order_id
      LEFT JOIN reports r ON o.id = r.order_id
      GROUP BY o.id, c.id
      ORDER BY o.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { customer_id, sample_count, priority = 'normal', test_type = 'HLVD', notes = '' } = req.body;
    
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
    
    // Generate proper order number
    const orderNumber = await generateOrderNumber();
    
    const result = await query(`
      INSERT INTO orders (customer_id, order_number, sample_count, status, priority, test_type, notes, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *
    `, [customer_id, orderNumber, sample_count, 'pending', priority, test_type, notes, req.user.userId]);
    
    await logAudit(req.user.userId, 'CREATE', 'order', result.rows[0].id, `Created order: ${orderNumber}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Enhanced barcode assignment
app.post('/api/orders/:id/assign-barcodes', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { barcodes } = req.body;
    
    if (!barcodes || !Array.isArray(barcodes)) {
      return res.status(400).json({ error: 'Barcodes array is required' });
    }
    
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
    
    // Validate barcode format and uniqueness
    const normalizedBarcodes = [];
    for (let i = 0; i < barcodes.length; i++) {
      const barcode = barcodes[i].toString().trim().toUpperCase();
      
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
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Delete existing samples for this order
      await client.query('DELETE FROM samples WHERE order_id = $1', [id]);
      
      // Create new samples
      for (const barcode of normalizedBarcodes) {
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
    res.status(500).json({ error: 'Failed to assign barcodes' });
  }
});

// Enhanced sample receiving with sub-order creation
app.post('/api/samples/receive', authenticateToken, async (req, res) => {
  try {
    const { barcode, location = 'Main Lab', notes = '' } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const normalizedBarcode = barcode.toUpperCase();
    
    const sampleResult = await query(`
      SELECT s.*, o.order_number, o.parent_order_number, o.sample_count as order_sample_count,
             c.name as customer_name, c.email as customer_email
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
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
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Update sample status
      await client.query(`
        UPDATE samples SET 
          status = 'received', 
          received_at = CURRENT_TIMESTAMP, 
          received_by = $1,
          location = $2,
          notes = $3
        WHERE id = $4
      `, [req.user.userId, location, notes, sample.id]);
      
      // Check if this creates a need for sub-order
      const orderResult = await client.query('SELECT * FROM orders WHERE id = $1', [sample.order_id]);
      const order = orderResult.rows[0];
      
      // Only create sub-orders for main orders (not already sub-orders)
      if (!order.parent_order_number) {
        const receivedSamplesResult = await client.query(`
          SELECT * FROM samples WHERE order_id = $1 AND status IN ('received', 'processing', 'complete')
        `, [order.id]);
        
        const receivedSamples = receivedSamplesResult.rows;
        const totalSamples = await client.query('SELECT COUNT(*) as total FROM samples WHERE order_id = $1', [order.id]);
        
        // If this is a partial receipt, create sub-order
        if (receivedSamples.length > 0 && receivedSamples.length < parseInt(totalSamples.rows[0].total)) {
          const subOrder = await createSubOrder(order, receivedSamples, req.user.userId);
          console.log(`Created sub-order ${subOrder.order_number} for partial receipt`);
        }
        // If all samples received, update main order status
        else if (receivedSamples.length === parseInt(totalSamples.rows[0].total)) {
          await client.query(
            'UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            ['received', order.id]
          );
        }
      }
      
      await client.query('COMMIT');
      
      await logAudit(req.user.userId, 'RECEIVE', 'sample', sample.id, 
        `Received sample: ${normalizedBarcode}`);
      
      res.json({
        message: 'Sample received successfully',
        sample: { ...sample, status: 'received' }
      });
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

// Enhanced batch management
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT b.*, 
             COUNT(bs.sample_id) as sample_count,
             COUNT(CASE WHEN bs.is_control = TRUE THEN 1 END) as control_count,
             u.full_name as created_by_name
      FROM batches b
      LEFT JOIN batch_samples bs ON b.id = bs.batch_id
      LEFT JOIN users u ON b.created_by = u.id
      GROUP BY b.id, u.full_name
      ORDER BY b.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Batches fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch batches' });
  }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { test_type, sample_ids = [], controls = [], notes = '' } = req.body;
    
    if (!test_type) {
      return res.status(400).json({ error: 'Test type is required' });
    }
    
    if (sample_ids.length + controls.length > 96) {
      return res.status(400).json({ error: 'Batch cannot exceed 96 positions' });
    }
    
    if (sample_ids.length === 0 && controls.length === 0) {
      return res.status(400).json({ error: 'At least one sample or control is required' });
    }
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Generate batch number
      const batchNumber = `BATCH-${Date.now()}`;
      
      // Create batch
      const batchResult = await client.query(`
        INSERT INTO batches (batch_number, test_type, notes, created_by)
        VALUES ($1, $2, $3, $4) RETURNING *
      `, [batchNumber, test_type, notes, req.user.userId]);
      
      const batch = batchResult.rows[0];
      let position = 1;
      
      // Add samples to batch
      for (const sampleId of sample_ids) {
        await client.query(`
          INSERT INTO batch_samples (batch_id, sample_id, position, is_control)
          VALUES ($1, $2, $3, $4)
        `, [batch.id, sampleId, position, false]);
        
        // Update sample status to processing
        await client.query(`
          UPDATE samples SET 
            status = 'processing', 
            processed_at = CURRENT_TIMESTAMP,
            processed_by = $1
          WHERE id = $2
        `, [req.user.userId, sampleId]);
        
        position++;
      }
      
      // Add controls to batch
      for (const control of controls) {
        await client.query(`
          INSERT INTO batch_samples (batch_id, position, is_control, control_type)
          VALUES ($1, $2, $3, $4)
        `, [batch.id, position, true, control.type]);
        
        position++;
      }
      
      await client.query('COMMIT');
      
      await logAudit(req.user.userId, 'CREATE', 'batch', batch.id, 
        `Created batch ${batchNumber} with ${sample_ids.length} samples and ${controls.length} controls`);
      
      res.status(201).json(batch);
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Batch creation error:', error);
    res.status(500).json({ error: 'Failed to create batch' });
  }
});

// Export batch as CSV
app.get('/api/batches/:id/export/:format', authenticateToken, async (req, res) => {
  try {
    const { id, format } = req.params;
    
    const batchResult = await query(`
      SELECT b.*, bs.position, bs.is_control, bs.control_type,
             s.barcode, c.name as customer_name, o.order_number
      FROM batches b
      LEFT JOIN batch_samples bs ON b.id = bs.batch_id
      LEFT JOIN samples s ON bs.sample_id = s.id
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE b.id = $1
      ORDER BY bs.position
    `, [id]);
    
    if (batchResult.rows.length === 0) {
      return res.status(404).json({ error: 'Batch not found' });
    }
    
    const batch = batchResult.rows[0];
    let csvContent = '';
    
    switch (format.toLowerCase()) {
      case 'biorad_iq5':
        // BioRad IQ5 format: samples in column A, rows 1-96
        for (let i = 1; i <= 96; i++) {
          const batchItem = batchResult.rows.find(r => r.position === i);
          if (batchItem) {
            if (batchItem.is_control) {
              csvContent += `${batchItem.control_type}\n`;
            } else {
              csvContent += `${batchItem.barcode}\n`;
            }
          } else {
            csvContent += 'none\n';
          }
        }
        break;
        
      case 'biorad_cfx96':
        // BioRad CFX96 format (can be customized later)
        csvContent = 'Well,Sample,Type\n';
        for (let i = 1; i <= 96; i++) {
          const batchItem = batchResult.rows.find(r => r.position === i);
          const wellName = `${String.fromCharCode(65 + Math.floor((i - 1) / 12))}${((i - 1) % 12) + 1}`;
          if (batchItem) {
            if (batchItem.is_control) {
              csvContent += `${wellName},${batchItem.control_type},Control\n`;
            } else {
              csvContent += `${wellName},${batchItem.barcode},Sample\n`;
            }
          } else {
            csvContent += `${wellName},none,Empty\n`;
          }
        }
        break;
        
      default:
        return res.status(400).json({ error: 'Unsupported export format' });
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=batch_${batch.batch_number}_${format}.csv`);
    res.send(csvContent);
    
  } catch (error) {
    console.error('Batch export error:', error);
    res.status(500).json({ error: 'Failed to export batch' });
  }
});

// Reports management
app.post('/api/orders/:orderId/reports', authenticateToken, upload.single('report'), async (req, res) => {
  try {
    const { orderId } = req.params;
    
    if (!req.file) {
      return res.status(400).json({ error: 'PDF file is required' });
    }
    
    // Get order details
    const orderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [orderId]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    // Generate report number
    const existingReports = await query(
      'SELECT report_number FROM reports WHERE order_id = $1 ORDER BY report_number DESC',
      [orderId]
    );
    
    let suffix = 'a';
    if (existingReports.rows.length > 0) {
      const lastReport = existingReports.rows[0].report_number;
      const lastSuffix = lastReport.slice(-1);
      suffix = String.fromCharCode(lastSuffix.charCodeAt(0) + 1);
    }
    
    const reportNumber = `${order.order_number}${suffix}`;
    
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      
      // Create report record
      const reportResult = await client.query(`
        INSERT INTO reports (order_id, report_number, original_filename, file_path, file_size, uploaded_by)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
      `, [orderId, reportNumber, req.file.originalname, req.file.path, req.file.size, req.user.userId]);
      
      const report = reportResult.rows[0];
      
      // Update all samples in this order to complete status
      await client.query(`
        UPDATE samples SET 
          status = 'complete',
          completed_at = CURRENT_TIMESTAMP
        WHERE order_id = $1
      `, [orderId]);
      
      // Update order status to complete
      await client.query(`
        UPDATE orders SET 
          status = 'complete',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      `, [orderId]);
      
      // Send email to customer
      const emailHtml = `
        <h2>Your Test Results Are Ready</h2>
        <p>Dear ${order.customer_name},</p>
        <p>Your test results for order ${order.order_number} are now complete and attached to this email.</p>
        <p>Report Number: ${reportNumber}</p>
        <p>If you have any questions about your results, please don't hesitate to contact us.</p>
        <p>Best regards,<br>3R Testing Laboratory</p>
      `;
      
      const emailSent = await sendCustomerEmail(
        order.customer_email,
        order.customer_name,
        `Test Results Ready - Order ${order.order_number}`,
        emailHtml,
        {
          filename: `3R_Testing_Results_${reportNumber}.pdf`,
          path: req.file.path
        }
      );
      
      if (emailSent) {
        await client.query(`
          UPDATE reports SET 
            emailed_to_customer = TRUE,
            email_sent_at = CURRENT_TIMESTAMP
          WHERE id = $1
        `, [report.id]);
      }
      
      await client.query('COMMIT');
      
      await logAudit(req.user.userId, 'CREATE', 'report', report.id, 
        `Uploaded report ${reportNumber} for order ${order.order_number}`);
      
      res.status(201).json({
        ...report,
        email_sent: emailSent,
        message: `Report ${reportNumber} uploaded successfully${emailSent ? ' and emailed to customer' : ''}`
      });
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    
  } catch (error) {
    console.error('Report upload error:', error);
    res.status(500).json({ error: 'Failed to upload report' });
  }
});

// Get reports for an order
app.get('/api/orders/:orderId/reports', authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    
    const result = await query(`
      SELECT r.*, u.full_name as uploaded_by_name
      FROM reports r
      LEFT JOIN users u ON r.uploaded_by = u.id
      WHERE r.order_id = $1
      ORDER BY r.uploaded_at DESC
    `, [orderId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Reports fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Download report
app.get('/api/reports/:id/download', authenticateToken, (req, res) => {
  try {
    const { id } = req.params;
    
    query('SELECT * FROM reports WHERE id = $1', [id])
      .then(result => {
        if (result.rows.length === 0) {
          return res.status(404).json({ error: 'Report not found' });
        }
        
        const report = result.rows[0];
        
        if (!fs.existsSync(report.file_path)) {
          return res.status(404).json({ error: 'Report file not found on disk' });
        }
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${report.original_filename}"`);
        
        const fileStream = fs.createReadStream(report.file_path);
        fileStream.pipe(res);
      })
      .catch(error => {
        console.error('Report download error:', error);
        res.status(500).json({ error: 'Failed to download report' });
      });
    
  } catch (error) {
    console.error('Report download error:', error);
    res.status(500).json({ error: 'Failed to download report' });
  }
});

// Enhanced samples endpoint
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT 
        s.id,
        s.barcode,
        s.status,
        s.order_id,
        s.received_at,
        s.processed_at,
        s.completed_at,
        s.location,
        s.notes,
        o.order_number,
        o.parent_order_number,
        c.name as customer_name,
        c.company_name,
        b.batch_number,
        bs.position as batch_position
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN batch_samples bs ON s.id = bs.sample_id
      LEFT JOIN batches b ON bs.batch_id = b.id
      ORDER BY s.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Samples fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch samples' });
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
      query('SELECT COUNT(*) FROM samples'),
      query('SELECT COUNT(*) FROM batches WHERE status = $1', ['active']),
      query('SELECT COUNT(*) FROM reports')
    ]);
    
    res.json({
      pending_orders: parseInt(stats[0].rows[0].count),
      shipped_orders: parseInt(stats[1].rows[0].count),
      processing_samples: parseInt(stats[2].rows[0].count),
      completed_orders: parseInt(stats[3].rows[0].count),
      total_customers: parseInt(stats[4].rows[0].count),
      total_samples: parseInt(stats[5].rows[0].count),
      active_batches: parseInt(stats[6].rows[0].count),
      total_reports: parseInt(stats[7].rows[0].count)
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
      SELECT id, username, role, email, full_name, is_active, created_at
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
    
    const existingUser = await query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await query(`
      INSERT INTO users (username, password_hash, role, email, full_name)
      VALUES ($1, $2, $3, $4, $5) RETURNING id, username, role, email, full_name, is_active, created_at
    `, [username, hashedPassword, role, email, full_name]);
    
    await logAudit(req.user.userId, 'CREATE', 'user', result.rows[0].id, `Created user: ${username}`);
    
    res.status(201).json(result.rows[0]);
    
  } catch (error) {
    console.error('User creation error:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Toggle user active status
app.patch('/api/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }
    
    const result = await query(`
      UPDATE users SET is_active = NOT is_active WHERE id = $1 
      RETURNING id, username, is_active
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    await logAudit(req.user.userId, 'UPDATE', 'user', id, 
      `${user.is_active ? 'Activated' : 'Deactivated'} user: ${user.username}`);
    
    res.json({ message: `User ${user.is_active ? 'activated' : 'deactivated'} successfully` });
    
  } catch (error) {
    console.error('User toggle error:', error);
    res.status(500).json({ error: 'Failed to update user status' });
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
        status = 'shipped',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
    `, [tracking_number, carrier, service, cost, order_id]);
    
    await logAudit(req.user.userId, 'UPDATE', 'order', order_id, 
      `Manual tracking number added: ${tracking_number}`);
    
    res.json({
      message: 'Tracking number added successfully',
      tracking_number: tracking_number
    });
    
  } catch (error) {
    console.error('Manual tracking error:', error);
    res.status(500).json({ error: 'Failed to add tracking number' });
  }
});

// Scanner endpoints
app.post('/api/scanner/validate', authenticateToken, async (req, res) => {
  try {
    const { barcode } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const normalizedBarcode = barcode.toUpperCase();
    const isValid = /^[A-Z]+\d+$/.test(normalizedBarcode);
    
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
    `, [normalizedBarcode]);
    
    res.json({
      valid: true,
      barcode: normalizedBarcode,
      exists: existingSample.rows.length > 0,
      sample_info: existingSample.rows[0] || null
    });
    
  } catch (error) {
    console.error('Barcode validation error:', error);
    res.status(500).json({ error: 'Failed to validate barcode' });
  }
});

// Basic notifications endpoint (placeholder)
app.get('/api/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json([]);
  } catch (error) {
    console.error('Notifications fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Basic audit log endpoint (placeholder)
app.get('/api/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json({ logs: [] });
  } catch (error) {
    console.error('Audit log fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Version: 4.0.0 - Complete LIMS Implementation`);
  console.log(`Features: Order numbering, Sub-orders, Batch management, Reports, Enhanced workflow`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;