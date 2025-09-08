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
const emailTransporter = nodemailer.createTransporter({
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

// UNIFIED Sub-Order Management Functions (No Duplicates)
const getNextSubOrderLetter = async (parentOrderId) => {
  try {
    const result = await query(`
      SELECT COUNT(*) as sub_order_count 
      FROM orders 
      WHERE parent_order_id = $1
    `, [parentOrderId]);
    
    const count = parseInt(result.rows[0].sub_order_count);
    return String.fromCharCode(97 + count); // 'a', 'b', 'c', etc.
  } catch (error) {
    console.error('Error getting sub-order letter:', error);
    return 'a';
  }
};

const createSubOrder = async (parentOrderId, receivedSampleIds, userId) => {
  try {
    // Get parent order details
    const parentOrderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [parentOrderId]);
    
    if (parentOrderResult.rows.length === 0) {
      throw new Error('Parent order not found');
    }
    
    const parentOrder = parentOrderResult.rows[0];
    
    // Get next sub-order letter
    const subOrderLetter = await getNextSubOrderLetter(parentOrderId);
    const subOrderNumber = `${parentOrder.order_number}${subOrderLetter}`;
    
    // Check if sub-order already exists
    const existingSubOrder = await query(
      'SELECT id FROM orders WHERE order_number = $1',
      [subOrderNumber]
    );
    
    if (existingSubOrder.rows.length > 0) {
      console.log(`Sub-order ${subOrderNumber} already exists`);
      return null;
    }
    
    // Create sub-order
    const subOrderResult = await query(`
      INSERT INTO orders (
        customer_id, order_number, sample_count, test_type,
        status, parent_order_id, priority, notes, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [
      parentOrder.customer_id,
      subOrderNumber,
      receivedSampleIds.length,
      parentOrder.test_type,
      'processing',
      parentOrderId,
      parentOrder.priority,
      `Sub-order created from ${parentOrder.order_number} - ${receivedSampleIds.length} samples received`,
      userId
    ]);
    
    const subOrder = subOrderResult.rows[0];
    
    // Update received samples to belong to sub-order
    await query(`
      UPDATE samples 
      SET order_id = $1, status = 'processing', processed_at = CURRENT_TIMESTAMP, processed_by = $2
      WHERE id = ANY($3)
    `, [subOrder.id, userId, receivedSampleIds]);
    
    // Update parent order status
    await updateParentOrderStatus(parentOrderId);
    
    await logAudit(userId, 'CREATE', 'sub_order', subOrder.id, 
      `Created sub-order ${subOrderNumber} from parent ${parentOrder.order_number} with ${receivedSampleIds.length} samples`);
    
    return subOrder;
    
  } catch (error) {
    console.error('Error creating sub-order:', error);
    throw error;
  }
};

const updateParentOrderStatus = async (parentOrderId) => {
  try {
    // Get all samples for parent order
    const samplesResult = await query(`
      SELECT COUNT(*) as total_samples,
             COUNT(CASE WHEN status = 'received' THEN 1 END) as received_samples,
             COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing_samples,
             COUNT(CASE WHEN status = 'complete' THEN 1 END) as complete_samples
      FROM samples s1
      WHERE s1.order_id = $1 
         OR s1.order_id IN (
           SELECT id FROM orders WHERE parent_order_id = $1
         )
    `, [parentOrderId]);
    
    const stats = samplesResult.rows[0];
    const totalSamples = parseInt(stats.total_samples);
    const receivedSamples = parseInt(stats.received_samples);
    const processingSamples = parseInt(stats.processing_samples);
    const completeSamples = parseInt(stats.complete_samples);
    
    let newStatus = 'pending';
    
    if (completeSamples === totalSamples) {
      newStatus = 'complete';
    } else if (processingSamples > 0 || receivedSamples > 0) {
      newStatus = receivedSamples > 0 ? 'partial' : 'processing';
    }
    
    await query(`
      UPDATE orders 
      SET status = $1, updated_at = CURRENT_TIMESTAMP 
      WHERE id = $2
    `, [newStatus, parentOrderId]);
    
  } catch (error) {
    console.error('Error updating parent order status:', error);
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

    // Create enhanced orders table with UNIFIED sub-order support
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        order_number VARCHAR(50) UNIQUE NOT NULL,
        parent_order_id INTEGER REFERENCES orders(id),
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
        batch_id VARCHAR(50),
        well_position INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        received_by INTEGER REFERENCES users(id),
        processed_by INTEGER REFERENCES users(id)
      )
    `);

    // Create enhanced batches table
    await query(`
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY,
        batch_id VARCHAR(50) UNIQUE,
        test_type VARCHAR(100) NOT NULL,
        status VARCHAR(50) DEFAULT 'created',
        plate_layout VARCHAR(20) DEFAULT '96-well',
        export_format VARCHAR(50) DEFAULT 'biorad_iq5',
        sample_count INTEGER DEFAULT 0,
        control_count INTEGER DEFAULT 0,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        completed_at TIMESTAMP
      )
    `);

    // Create batch_controls table
    await query(`
      CREATE TABLE IF NOT EXISTS batch_controls (
        id SERIAL PRIMARY KEY,
        batch_id VARCHAR(50) NOT NULL,
        control_type VARCHAR(100) NOT NULL,
        control_name VARCHAR(100) NOT NULL,
        well_position INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: '3R Testing LIMS Backend - Phase 2 Enhanced',
    version: '5.0.0 - Clean Sub-Order Implementation',
    features: [
      'sub_order_management',
      'enhanced_batch_processing', 
      'pdf_reports',
      'enhanced_workflow'
    ]
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
               WHEN o.parent_order_id IS NOT NULL THEN true
               ELSE false
             END as is_sub_order
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

// UNIFIED Enhanced Sample Receiving (Single Implementation)
app.post('/api/samples/receive-enhanced', authenticateToken, async (req, res) => {
  try {
    const { barcodes, location = 'Main Lab', notes = '' } = req.body;
    
    if (!barcodes || !Array.isArray(barcodes)) {
      return res.status(400).json({ error: 'Barcodes array is required' });
    }
    
    const receivedSamples = [];
    const ordersToProcess = new Map();
    
    // Process each barcode
    for (const barcode of barcodes) {
      // Find sample
      const sampleResult = await query(`
        SELECT s.*, o.id as order_id, o.order_number, o.customer_id,
               c.name as customer_name, c.email as customer_email
        FROM samples s
        JOIN orders o ON s.order_id = o.id
        JOIN customers c ON o.customer_id = c.id
        WHERE s.barcode = $1
      `, [barcode]);
      
      if (sampleResult.rows.length === 0) {
        console.warn(`Sample not found for barcode: ${barcode}`);
        continue;
      }
      
      const sample = sampleResult.rows[0];
      
      // Update sample status to received
      await query(`
        UPDATE samples 
        SET status = 'received', 
            received_at = CURRENT_TIMESTAMP, 
            received_by = $1,
            location = $2,
            notes = COALESCE(notes || E'\n' || $3, $3)
        WHERE id = $4
      `, [req.user.userId, location, notes, sample.id]);
      
      sample.status = 'received';
      receivedSamples.push(sample);
      
      // Group samples by order for sub-order processing
      if (!ordersToProcess.has(sample.order_id)) {
        ordersToProcess.set(sample.order_id, []);
      }
      ordersToProcess.get(sample.order_id).push(sample.id);
    }
    
    // Process sub-orders for each parent order
    const createdSubOrders = [];
    
    for (const [orderId, sampleIds] of ordersToProcess) {
      // Check if this is a partial order (not all samples received)
      const orderSamplesResult = await query(`
        SELECT COUNT(*) as total_samples,
               COUNT(CASE WHEN status = 'received' THEN 1 END) as received_samples
        FROM samples 
        WHERE order_id = $1
      `, [orderId]);
      
      const orderStats = orderSamplesResult.rows[0];
      const totalSamples = parseInt(orderStats.total_samples);
      const receivedSamples = parseInt(orderStats.received_samples);
      
      // If partial order, create sub-order
      if (receivedSamples < totalSamples && receivedSamples > 0) {
        const subOrder = await createSubOrder(orderId, sampleIds, req.user.userId);
        if (subOrder) {
          createdSubOrders.push(subOrder);
        }
      } else if (receivedSamples === totalSamples) {
        // All samples received, update order status
        await query(`
          UPDATE orders 
          SET status = 'received', updated_at = CURRENT_TIMESTAMP 
          WHERE id = $1
        `, [orderId]);
      }
    }
    
    // Log audit entries
    for (const sample of receivedSamples) {
      await logAudit(req.user.userId, 'UPDATE', 'sample', sample.id, 
        `Sample received: ${sample.barcode} at ${location}`);
    }
    
    res.json({
      message: `Successfully received ${receivedSamples.length} samples`,
      received_samples: receivedSamples,
      sub_orders_created: createdSubOrders,
      total_processed: barcodes.length,
      location: location
    });
    
  } catch (error) {
    console.error('Enhanced sample receiving error:', error);
    res.status(500).json({ 
      error: 'Failed to receive samples',
      details: error.message 
    });
  }
});

// Get Order with Sub-Orders
app.get('/api/orders/:id/with-suborders', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get parent order
    const parentOrderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email,
             c.company_name, c.phone, c.shipping_address
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [id]);
    
    if (parentOrderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const parentOrder = parentOrderResult.rows[0];
    
    // Get sub-orders
    const subOrdersResult = await query(`
      SELECT * FROM orders 
      WHERE parent_order_id = $1 
      ORDER BY order_number
    `, [id]);
    
    // Get all samples (parent and sub-orders)
    const samplesResult = await query(`
      SELECT s.*, o.order_number, 
             CASE WHEN o.parent_order_id IS NOT NULL THEN true ELSE false END as is_sub_order
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      WHERE o.id = $1 OR o.parent_order_id = $1
      ORDER BY s.barcode
    `, [id]);
    
    res.json({
      parent_order: parentOrder,
      sub_orders: subOrdersResult.rows,
      all_samples: samplesResult.rows
    });
    
  } catch (error) {
    console.error('Error fetching order with sub-orders:', error);
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// Batch Management with 96-well Support
app.post('/api/batches/create-enhanced', authenticateToken, async (req, res) => {
  try {
    const { 
      test_type, 
      sample_ids = [], 
      controls = {},
      plate_layout = '96-well',
      notes = '',
      export_format = 'biorad_iq5'
    } = req.body;
    
    // Validate plate capacity
    const maxSamples = plate_layout === '96-well' ? 96 : 384;
    const totalWells = sample_ids.length + Object.keys(controls).length;
    
    if (totalWells > maxSamples) {
      return res.status(400).json({ 
        error: `Batch exceeds ${plate_layout} capacity (${maxSamples} wells)` 
      });
    }
    
    // Generate batch ID
    const batchId = `BATCH-${Date.now()}-${test_type}`;
    
    // Create batch record
    const batchResult = await query(`
      INSERT INTO batches (
        batch_id, test_type, plate_layout, export_format,
        sample_count, control_count, status, notes, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [
      batchId, test_type, plate_layout, export_format,
      sample_ids.length, Object.keys(controls).length,
      'created', notes, req.user.userId
    ]);
    
    const batch = batchResult.rows[0];
    
    // Add samples to batch
    for (let i = 0; i < sample_ids.length; i++) {
      await query(`
        UPDATE samples 
        SET batch_id = $1, status = 'processing', well_position = $2
        WHERE id = $3
      `, [batchId, i + 1, sample_ids[i]]);
    }
    
    // Add controls to batch
    for (const [controlType, controlData] of Object.entries(controls)) {
      await query(`
        INSERT INTO batch_controls (
          batch_id, control_type, control_name, well_position
        ) VALUES ($1, $2, $3, $4)
      `, [
        batchId,
        controlType,
        controlData.name || controlType,
        controlData.position || (sample_ids.length + Object.keys(controls).indexOf(controlType) + 1)
      ]);
    }
    
    await logAudit(req.user.userId, 'CREATE', 'batch', batch.id, 
      `Created ${plate_layout} batch ${batchId} with ${sample_ids.length} samples and ${Object.keys(controls).length} controls`);
    
    res.json({
      message: 'Enhanced batch created successfully',
      batch: batch,
      batch_id: batchId,
      total_wells_used: totalWells,
      plate_capacity: maxSamples
    });
    
  } catch (error) {
    console.error('Enhanced batch creation error:', error);
    res.status(500).json({ error: 'Failed to create batch' });
  }
});

// Export Batch as CSV
app.get('/api/batches/:batch_id/export-csv', authenticateToken, async (req, res) => {
  try {
    const { batch_id } = req.params;
    const { format = 'biorad_iq5' } = req.query;
    
    // Get batch details
    const batchResult = await query(`
      SELECT * FROM batches WHERE batch_id = $1
    `, [batch_id]);
    
    if (batchResult.rows.length === 0) {
      return res.status(404).json({ error: 'Batch not found' });
    }
    
    const batch = batchResult.rows[0];
    
    // Get samples in batch
    const samplesResult = await query(`
      SELECT s.barcode, s.well_position
      FROM samples s
      WHERE s.batch_id = $1
      ORDER BY s.well_position
    `, [batch_id]);
    
    // Get controls in batch
    const controlsResult = await query(`
      SELECT control_name, well_position
      FROM batch_controls
      WHERE batch_id = $1
      ORDER BY well_position
    `, [batch_id]);
    
    // Generate CSV based on format
    let csvContent = '';
    const maxWells = batch.plate_layout === '96-well' ? 96 : 384;
    const wells = new Array(maxWells).fill('none');
    
    // Fill in samples
    samplesResult.rows.forEach(sample => {
      if (sample.well_position && sample.well_position <= maxWells) {
        wells[sample.well_position - 1] = sample.barcode;
      }
    });
    
    // Fill in controls
    controlsResult.rows.forEach(control => {
      if (control.well_position && control.well_position <= maxWells) {
        wells[control.well_position - 1] = control.control_name;
      }
    });
    
    // Format based on instrument type
    switch (format) {
      case 'biorad_iq5':
        csvContent = wells.join('\n');
        break;
      case 'biorad_cfx96':
        csvContent = 'Well,Sample\n' + wells.map((well, index) => `${index + 1},${well}`).join('\n');
        break;
      case 'ariamx':
        csvContent = 'Position,Name\n' + wells.map((well, index) => `${String.fromCharCode(65 + Math.floor(index / 12))}${(index % 12) + 1},${well}`).join('\n');
        break;
      default:
        csvContent = wells.join('\n');
    }
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${batch_id}_${format}.csv"`);
    res.send(csvContent);
    
  } catch (error) {
    console.error('Batch CSV export error:', error);
    res.status(500).json({ error: 'Failed to export batch' });
  }
});

// Enhanced batch management
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT b.*, 
             u.full_name as created_by_name
      FROM batches b
      LEFT JOIN users u ON b.created_by = u.id
      ORDER BY b.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Batches fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch batches' });
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
        s.batch_id,
        s.well_position,
        o.order_number,
        o.parent_order_id,
        c.name as customer_name,
        c.company_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
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
      query('SELECT COUNT(*) FROM batches WHERE status = $1', ['created']),
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

// Basic placeholders for remaining endpoints
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

app.get('/api/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

app.get('/api/reports', authenticateToken, async (req, res) => {
  try {
    res.json([]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Version: 5.0.0 - Clean Sub-Order Implementation`);
  console.log(`Features: Unified sub-order management, enhanced batch processing, clean architecture`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;