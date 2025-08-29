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

// Auto Order Creation
const AUTO_CREATE_CONFIG = {
  enabled: process.env.AUTO_CREATE_ORDERS === 'true',
  default_customer: {
    name: process.env.DEFAULT_CUSTOMER_NAME || 'Walk-in Customer',
    email: process.env.DEFAULT_CUSTOMER_EMAIL || 'walkin@3rtesting.com',
    company: process.env.DEFAULT_CUSTOMER_COMPANY || 'Walk-in'
  },
  require_approval: process.env.AUTO_CREATE_REQUIRE_APPROVAL === 'true'
};

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

// Shipping Configuration
const SHIPPING_CONFIG = {
  default_carrier: 'UPS',
  default_service: 'Ground',
  shipengine_api_key: process.env.SHIPENGINE_API_KEY,
  easypost_api_key: process.env.EASYPOST_API_KEY,
  ups_api_key: process.env.UPS_API_KEY,
  fedex_api_key: process.env.FEDEX_API_KEY,
  from_address: {
    name: '3R Testing Laboratory',
    company: '3R Testing',
    address_line_1: process.env.LAB_ADDRESS_LINE1 || '123 Lab Street',
    city: process.env.LAB_CITY || 'Science City',
    state: process.env.LAB_STATE || 'SC',
    postal_code: process.env.LAB_ZIP || '12345',
    country: 'US',
    phone: process.env.LAB_PHONE || '555-123-4567'
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
  'combo-test': { sample_count: 1, test_type: 'Fus+Pyth' }
};

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
    return false;
  }
};

// Barcode validation helper
const validateBarcode = (barcode) => {
  const pattern = /^[A-Z0-9]{8}$/;
  return pattern.test(barcode.toUpperCase());
};

// Parse barcode ranges
const parseBarcodeInput = (input) => {
  const barcodes = [];
  const parts = input.split(',').map(s => s.trim());
  
  for (const part of parts) {
    if (part.includes('-')) {
      const [start, end] = part.split('-').map(s => s.trim());
      
      if (!validateBarcode(start) || !validateBarcode(end)) {
        throw new Error(`Invalid barcode range: ${part}`);
      }
      
      const startPrefix = start.substring(0, 2);
      const endPrefix = end.substring(0, 2);
      
      if (startPrefix !== endPrefix) {
        throw new Error(`Range prefixes must match: ${start} to ${end}`);
      }
      
      const startNum = parseInt(start.substring(2));
      const endNum = parseInt(end.substring(2));
      
      if (startNum > endNum) {
        throw new Error(`Invalid range: start number must be less than end number`);
      }
      
      for (let i = startNum; i <= endNum; i++) {
        const barcode = startPrefix + i.toString().padStart(6, '0');
        barcodes.push(barcode);
      }
    } else {
      if (!validateBarcode(part)) {
        throw new Error(`Invalid barcode format: ${part}`);
      }
      barcodes.push(part.toUpperCase());
    }
  }
  
  return barcodes;
};

// Helper functions for WooCommerce
const findOrCreateCustomer = async (wooCustomerData) => {
  try {
    if (wooCustomerData.id) {
      const existingCustomer = await query(
        'SELECT * FROM customers WHERE woocommerce_id = $1',
        [wooCustomerData.id]
      );
      
      if (existingCustomer.rows.length > 0) {
        return existingCustomer.rows[0];
      }
    }
    
    const existingByEmail = await query(
      'SELECT * FROM customers WHERE email = $1',
      [wooCustomerData.email]
    );
    
    if (existingByEmail.rows.length > 0) {
      return existingByEmail.rows[0];
    }
    
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
      1
    ]);
    
    return customerResult.rows[0];
  } catch (error) {
    console.error('Error finding/creating customer:', error);
    throw error;
  }
};

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

// PDF Generation Function
const generateResultsPDF = async (orderId) => {
  try {
    // Get order details with all samples and results
    const orderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email,
             c.company_name, c.shipping_address
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [orderId]);
    
    if (orderResult.rows.length === 0) {
      throw new Error('Order not found');
    }
    
    const order = orderResult.rows[0];
    
    // Get samples with results
    const samplesResult = await query(`
      SELECT s.*, tr.test_type, tr.result, tr.value, tr.units, 
             tr.detection_limit, tr.method, tr.analyst, tr.analyzed_at
      FROM samples s
      LEFT JOIN test_results tr ON s.id = tr.sample_id
      WHERE s.order_id = $1
      ORDER BY s.barcode
    `, [orderId]);
    
    const samples = samplesResult.rows;
    
    // Create PDF
    const doc = new PDFDocument();
    let buffers = [];
    
    doc.on('data', buffers.push.bind(buffers));
    
    return new Promise((resolve, reject) => {
      doc.on('end', () => {
        const pdfBuffer = Buffer.concat(buffers);
        resolve(pdfBuffer);
      });
      
      // PDF Header
      doc.fontSize(20).text('3R Testing Laboratory', 50, 50);
      doc.fontSize(16).text('Pathogen Testing Results Report', 50, 80);
      doc.fontSize(12).text(`Report Generated: ${new Date().toLocaleDateString()}`, 50, 110);
      
      // Order Information
      doc.fontSize(14).text('Order Information', 50, 150);
      doc.fontSize(10)
         .text(`Order Number: ${order.order_number}`, 50, 170)
         .text(`Customer: ${order.customer_name}`, 50, 185)
         .text(`Company: ${order.company_name || 'N/A'}`, 50, 200)
         .text(`Test Type: ${order.test_type || 'Various'}`, 50, 215);
      
      // Results Table
      let yPosition = 250;
      doc.fontSize(14).text('Test Results', 50, yPosition);
      yPosition += 25;
      
      // Table headers
      doc.fontSize(9)
         .text('Barcode', 50, yPosition)
         .text('Test Type', 150, yPosition)
         .text('Result', 250, yPosition)
         .text('Value', 320, yPosition)
         .text('Method', 400, yPosition);
      
      yPosition += 20;
      
      // Results data
      samples.forEach(sample => {
        if (yPosition > 700) {
          doc.addPage();
          yPosition = 50;
        }
        
        doc.text(sample.barcode, 50, yPosition)
           .text(sample.test_type || 'N/A', 150, yPosition)
           .text(sample.result || 'Pending', 250, yPosition)
           .text(sample.value ? `${sample.value} ${sample.units || ''}` : 'N/A', 320, yPosition)
           .text(sample.method || 'N/A', 400, yPosition);
        
        yPosition += 15;
      });
      
      // Footer
      doc.fontSize(8)
         .text('3R Testing Laboratory - Certified Pathogen Testing', 50, 750)
         .text('This report is confidential and intended for the named recipient only.', 50, 765);
      
      doc.end();
    });
    
  } catch (error) {
    console.error('PDF generation error:', error);
    throw error;
  }
};

// Initialize database tables
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
    // Users table
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

    // Customers table
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
        woocommerce_username VARCHAR(100),
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Orders table
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
        woocommerce_order_id INTEGER UNIQUE,
        woocommerce_status VARCHAR(50),
        shipping_cost DECIMAL(10,2),
        shipping_service VARCHAR(50),
        shipping_carrier VARCHAR(50),
        shipping_api_used VARCHAR(50) DEFAULT 'manual',
        label_created_at TIMESTAMP,
        shipped_at TIMESTAMP,
        delivered_at TIMESTAMP,
        test_type VARCHAR(100),
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Samples table
    await query(`
      CREATE TABLE IF NOT EXISTS samples (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        barcode VARCHAR(50) UNIQUE NOT NULL,
        sample_type VARCHAR(50) DEFAULT 'environmental',
        status VARCHAR(50) DEFAULT 'pending',
        received_at TIMESTAMP,
        processed_at TIMESTAMP,
        completed_at TIMESTAMP,
        batch_id VARCHAR(50),
        location VARCHAR(100),
        notes TEXT,
        received_by INTEGER REFERENCES users(id),
        processed_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Test results table
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

    // Batches table
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
        created_by INTEGER REFERENCES users(id)
      )
    `);

    // Email notifications table
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

    // Audit log table
    await query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(50),
        entity_type VARCHAR(50),
        entity_id INTEGER,
        details TEXT,
        ip_address VARCHAR(50),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    version: '3.0.0 - Complete Integration',
    features: [
      'email_notifications', 
      'pdf_reports', 
      'customer_portal',
      'woocommerce_integration',
      'flexible_shipping',
      'barcode_scanning',
      'batch_processing'
    ]
  });
});

// ===== AUTHENTICATION ENDPOINTS =====

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
      message: 'Sample received successfully',
      sample: updatedSampleResult.rows[0],
      auto_created: false
    });
    
  } catch (error) {
    console.error('Sample receive error:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

app.get('/api/scanner/search', authenticateToken, async (req, res) => {
  try {
    const { q, limit = 20, status } = req.query;
    
    if (!q || q.length < 2) {
      return res.json({ samples: [] });
    }
    
    let query_text = `
      SELECT s.*, o.order_number, c.name as customer_name, c.company_name,
             u.full_name as received_by_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN users u ON s.received_by = u.id
      WHERE s.barcode ILIKE $1
    `;
    
    const params = [`%${q.toUpperCase()}%`];
    
    if (status) {
      query_text += ` AND s.status = ${params.length + 1}`;
      params.push(status);
    }
    
    query_text += ` ORDER BY s.created_at DESC LIMIT ${params.length + 1}`;
    params.push(limit);
    
    const result = await query(query_text, params);
    
    res.json({
      samples: result.rows,
      count: result.rows.length
    });
    
  } catch (error) {
    console.error('Sample search error:', error);
    res.status(500).json({ error: 'Failed to search samples' });
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

// ===== EMAIL FUNCTIONS =====

const sendResultsEmail = async (orderId) => {
  try {
    // Get order and customer details
    const orderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [orderId]);
    
    if (orderResult.rows.length === 0) {
      throw new Error('Order not found');
    }
    
    const order = orderResult.rows[0];
    
    // Generate PDF
    const pdfBuffer = await generateResultsPDF(orderId);
    
    // Send email with PDF attachment
    const mailOptions = {
      from: process.env.SMTP_USER || 'noreply@3rtesting.com',
      to: order.customer_email,
      subject: `Test Results Ready - Order ${order.order_number}`,
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Test Results Ready</h2>
          <p>Dear ${order.customer_name},</p>
          <p>Your pathogen testing results for order <strong>${order.order_number}</strong> are now complete.</p>
          <p>Please find your detailed results report attached as a PDF.</p>
          <p>If you have any questions about your results, please don't hesitate to contact us.</p>
          <br>
          <p>Best regards,<br>3R Testing Laboratory</p>
        </div>
      `,
      attachments: [
        {
          filename: `3R_Testing_Results_${order.order_number}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf'
        }
      ]
    };
    
    await emailTransporter.sendMail(mailOptions);
    
    // Log notification
    await query(`
      INSERT INTO email_notifications (
        order_id, notification_type, recipient_email, recipient_name,
        subject, status, sent_at
      ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
    `, [
      orderId,
      'results_ready',
      order.customer_email,
      order.customer_name,
      `Test Results Ready - Order ${order.order_number}`,
      'sent'
    ]);
    
    console.log(`Results email sent for order ${order.order_number}`);
    
  } catch (error) {
    console.error('Email sending error:', error);
    
    // Log failed notification
    try {
      await query(`
        INSERT INTO email_notifications (
          order_id, notification_type, recipient_email, recipient_name,
          subject, status, error_message
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        orderId,
        'results_ready',
        'unknown@error.com',
        'Unknown Customer',
        `Test Results Ready - Order ${orderId}`,
        'failed',
        error.message
      ]);
    } catch (logError) {
      console.error('Failed to log email error:', logError);
    }
    
    throw error;
  }
};

// ===== WOOCOMMERCE WEBHOOK =====

app.post('/api/webhooks/woocommerce', async (req, res) => {
  try {
    const signature = req.headers['x-wc-webhook-signature'];
    const body = req.body;
    
    // Skip signature verification in development
    if (WOOCOMMERCE_WEBHOOK_SECRET) {
      const expectedSignature = crypto
        .createHmac('sha256', WOOCOMMERCE_WEBHOOK_SECRET)
        .update(body)
        .digest('base64');
      
      if (signature !== expectedSignature) {
        console.error('Invalid WooCommerce webhook signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }
    
    const orderData = JSON.parse(body.toString());
    
    // Only process completed/processing orders
    if (!['completed', 'processing', 'paid'].includes(orderData.status)) {
      return res.status(200).json({ message: 'Order status not eligible for processing' });
    }
    
    // Check if order already exists
    const existingOrder = await query(
      'SELECT * FROM orders WHERE woocommerce_order_id = $1',
      [orderData.id]
    );
    
    if (existingOrder.rows.length > 0) {
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
    
    // Parse line items
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
      `Auto-created from WooCommerce order #${orderData.id}. Total: ${orderData.total}`,
      1
    ]);
    
    const limsOrder = orderResult.rows[0];
    
    // Create placeholder samples
    for (let i = 1; i <= orderDetails.sample_count; i++) {
      const barcode = `WOO-${orderData.id}-S${i.toString().padStart(2, '0')}`;
      await query(
        'INSERT INTO samples (order_id, barcode, sample_type, status) VALUES ($1, $2, $3, $4)',
        [limsOrder.id, barcode, orderDetails.test_type, 'pending']
      );
    }
    
    await logAudit(1, 'CREATE', 'order', limsOrder.id, `Auto-created from WooCommerce order #${orderData.id}`);
    
    res.status(200).json({ 
      message: 'Order processed successfully',
      lims_order_id: limsOrder.id,
      lims_order_number: limsOrder.order_number
    });
    
  } catch (error) {
    console.error('WooCommerce webhook processing error:', error);
    res.status(500).json({ error: 'Failed to process order' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Database type: PostgreSQL`);
  console.log(`Version: 3.0.0 - Complete Integration`);
  console.log(`WooCommerce webhook: ${WOOCOMMERCE_WEBHOOK_SECRET ? 'Configured' : 'Not configured'}`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;
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

// MISSING ENDPOINT: Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    
    // Verify current password
    const userResult = await query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Update password
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

// ===== CUSTOMER ENDPOINTS =====

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

// ===== ORDER ENDPOINTS =====

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

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { customer_id, sample_count, priority = 'normal', shipping_method = 'ups_ground', notes } = req.body;
    
    if (!customer_id || !sample_count) {
      return res.status(400).json({ error: 'Customer ID and sample count are required' });
    }
    
    const orderCountResult = await query('SELECT COUNT(*) FROM orders');
    const orderNumber = `ORD-${(parseInt(orderCountResult.rows[0].count) + 1).toString().padStart(3, '0')}`;
    
    const result = await query(`
      INSERT INTO orders (customer_id, order_number, sample_count, priority, shipping_method, notes, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
    `, [customer_id, orderNumber, sample_count, priority, shipping_method, notes, req.user.userId]);
    
    const order = result.rows[0];
    
    // Create placeholder samples
    for (let i = 1; i <= sample_count; i++) {
      const barcode = `${orderNumber}-S${i.toString().padStart(2, '0')}`;
      await query(
        'INSERT INTO samples (order_id, barcode) VALUES ($1, $2)',
        [order.id, barcode]
      );
    }
    
    await logAudit(req.user.userId, 'CREATE', 'order', order.id, `Created order: ${orderNumber}`);
    
    res.status(201).json(order);
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// MISSING ENDPOINT: Assign barcodes to order
app.post('/api/orders/:id/assign-barcodes', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { barcodes } = req.body;
    
    if (!barcodes || !Array.isArray(barcodes)) {
      return res.status(400).json({ error: 'Barcodes array is required' });
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
    
    // Delete existing samples for this order
    await query('DELETE FROM samples WHERE order_id = $1', [id]);
    
    // Create new samples with assigned barcodes
    for (let i = 0; i < barcodes.length; i++) {
      const barcode = barcodes[i].toUpperCase().trim();
      
      if (!validateBarcode(barcode)) {
        return res.status(400).json({ error: `Invalid barcode format: ${barcode}` });
      }
      
      await query(
        'INSERT INTO samples (order_id, barcode, sample_type, status) VALUES ($1, $2, $3, $4)',
        [id, barcode, order.test_type || 'environmental', 'pending']
      );
    }
    
    await logAudit(req.user.userId, 'UPDATE', 'order', id, `Assigned ${barcodes.length} barcodes`);
    
    res.json({ message: 'Barcodes assigned successfully' });
    
  } catch (error) {
    console.error('Barcode assignment error:', error);
    res.status(500).json({ error: 'Failed to assign barcodes' });
  }
});

// MISSING ENDPOINT: Download PDF report
app.get('/api/orders/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const pdfBuffer = await generateResultsPDF(id);
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="3R_Testing_Results_${id}.pdf"`);
    res.send(pdfBuffer);
    
  } catch (error) {
    console.error('PDF download error:', error);
    res.status(500).json({ error: 'Failed to generate PDF' });
  }
});

// ===== SAMPLE ENDPOINTS =====

app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT s.*, 
             o.order_number,
             c.name as customer_name,
             c.company_name,
             u.full_name as received_by_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN users u ON s.received_by = u.id
      ORDER BY s.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Samples fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch samples' });
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

// MISSING ENDPOINT: Update sample status
app.patch('/api/samples/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, batch_id, notes } = req.body;
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
    let updateQuery = 'UPDATE samples SET status = $1, updated_at = CURRENT_TIMESTAMP';
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

// MISSING ENDPOINT: Add test results
app.post('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { test_type, result, value, units, detection_limit, method, notes } = req.body;
    
    if (!test_type || !result) {
      return res.status(400).json({ error: 'Test type and result are required' });
    }
    
    // Add test result
    const resultRecord = await query(`
      INSERT INTO test_results (
        sample_id, test_type, result, value, units, 
        detection_limit, method, analyst, notes
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [id, test_type, result, value, units, detection_limit, method, req.user.username, notes]);
    
    // Update sample status to complete
    await query(`
      UPDATE samples SET 
        status = 'complete',
        completed_at = CURRENT_TIMESTAMP,
        processed_by = $1
      WHERE id = $2
    `, [req.user.userId, id]);
    
    // Check if all samples in order are complete
    const sampleResult = await query('SELECT order_id FROM samples WHERE id = $1', [id]);
    const orderId = sampleResult.rows[0].order_id;
    
    const incompleteSamples = await query(
      'SELECT COUNT(*) FROM samples WHERE order_id = $1 AND status != $2',
      [orderId, 'complete']
    );
    
    if (parseInt(incompleteSamples.rows[0].count) === 0) {
      // All samples complete - update order status and send email
      await query('UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', 
        ['complete', orderId]);
      
      // Send results email
      try {
        await sendResultsEmail(orderId);
      } catch (emailError) {
        console.error('Failed to send results email:', emailError);
      }
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

// ===== BATCH ENDPOINTS =====

app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT b.*, 
             COUNT(s.id) as actual_sample_count,
             u.full_name as created_by_name
      FROM batches b
      LEFT JOIN samples s ON b.batch_id = s.batch_id
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

// MISSING ENDPOINT: Create batch
app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { test_type, sample_ids, notes } = req.body;
    
    if (!test_type || !sample_ids || !Array.isArray(sample_ids)) {
      return res.status(400).json({ error: 'Test type and sample IDs are required' });
    }
    
    // Generate batch ID
    const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const batchId = `BATCH-${test_type}-${timestamp}-${Date.now().toString().slice(-4)}`;
    
    // Create batch record
    const batchResult = await query(`
      INSERT INTO batches (batch_id, test_type, sample_count, notes, created_by)
      VALUES ($1, $2, $3, $4, $5) RETURNING *
    `, [batchId, test_type, sample_ids.length, notes, req.user.userId]);
    
    // Update samples with batch ID and status
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

// ===== USER MANAGEMENT ENDPOINTS =====

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

// MISSING ENDPOINT: Create user
app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, role, email, full_name } = req.body;
    
    if (!username || !password || !email || !full_name) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check for existing username
    const existingUser = await query('SELECT id FROM users WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    // Check for existing email
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

// MISSING ENDPOINT: Toggle user status
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

// ===== DASHBOARD STATS =====

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

// ===== ADMIN ENDPOINTS =====

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

// MISSING ENDPOINT: Resend notification
app.post('/api/notifications/:id/resend', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get notification details
    const notificationResult = await query(`
      SELECT en.*, o.id as order_id
      FROM email_notifications en
      LEFT JOIN orders o ON en.order_id = o.id
      WHERE en.id = $1
    `, [id]);
    
    if (notificationResult.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    const notification = notificationResult.rows[0];
    
    // Resend email
    if (notification.order_id) {
      await sendResultsEmail(notification.order_id);
    } else {
      // Send custom notification
      await emailTransporter.sendMail({
        from: process.env.SMTP_USER,
        to: notification.recipient_email,
        subject: notification.subject,
        html: notification.body
      });
      
      await query(
        'UPDATE email_notifications SET status = $1, sent_at = CURRENT_TIMESTAMP WHERE id = $2',
        ['sent', id]
      );
    }
    
    res.json({ message: 'Notification resent successfully' });
    
  } catch (error) {
    console.error('Notification resend error:', error);
    res.status(500).json({ error: 'Failed to resend notification' });
  }
});

// Database backup endpoint
app.post('/api/backup/create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Simple backup - in production you'd use pg_dump
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

// ===== SHIPPING ENDPOINTS =====

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

// ===== BARCODE SCANNER ENDPOINTS =====

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

app.post('/api/scanner/validate-batch', authenticateToken, async (req, res) => {
  try {
    const { input } = req.body;
    
    if (!input) {
      return res.status(400).json({ error: 'Input is required' });
    }
    
    const barcodes = parseBarcodeInput(input);
    const results = [];
    
    for (const barcode of barcodes) {
      const existingSample = await query(`
        SELECT s.*, o.order_number, c.name as customer_name 
        FROM samples s 
        LEFT JOIN orders o ON s.order_id = o.id 
        LEFT JOIN customers c ON o.customer_id = c.id 
        WHERE s.barcode = $1
      `, [barcode]);
      
      results.push({
        barcode,
        valid: true,
        exists: existingSample.rows.length > 0,
        sample_info: existingSample.rows[0] || null
      });
    }
    
    res.json({
      total_barcodes: barcodes.length,
      valid_barcodes: barcodes.length,
      existing_samples: results.filter(r => r.exists).length,
      new_samples: results.filter(r => !r.exists).length,
      results
    });
    
  } catch (error) {
    console.error('Batch barcode validation error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/scanner/receive-sample', authenticateToken, async (req, res) => {
  try {
    const { barcode, location = 'Main Lab', notes = '', auto_create_order = false } = req.body;
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
    const normalizedBarcode = barcode.toUpperCase();
    
    let sampleResult = await query(`
      SELECT s.*, o.order_number, o.customer_id, c.name as customer_name, c.company_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE s.barcode = $1
    `, [normalizedBarcode]);

    if (sampleResult.rows.length === 0) {
      if (auto_create_order) {
        if (!AUTO_CREATE_CONFIG.enabled) {
          return res.status(403).json({ 
            error: 'Auto-create orders is disabled',
            suggestion: 'Contact administrator to enable this feature'
          });
        }

        let defaultCustomer = await query(`
          SELECT id FROM customers 
          WHERE email = $1
          LIMIT 1
        `, [AUTO_CREATE_CONFIG.default_customer.email]);
        
        let customerId;
        if (defaultCustomer.rows.length === 0) {
          const customerResult = await query(`
            INSERT INTO customers (name, email, company_name, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id
          `, [
            AUTO_CREATE_CONFIG.default_customer.name,
            AUTO_CREATE_CONFIG.default_customer.email,
            AUTO_CREATE_CONFIG.default_customer.company,
            req.user.userId
          ]);
          customerId = customerResult.rows[0].id;
        } else {
          customerId = defaultCustomer.rows[0].id;
        }

        const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
        const orderNumber = `AUTO-${timestamp}-${normalizedBarcode}`;
        
        const orderResult = await query(`
          INSERT INTO orders (
            customer_id, order_number, sample_count, status, 
            priority, notes, created_by
          ) VALUES ($1, $2, 1, $3, $4, $5, $6)
          RETURNING *
        `, [
          customerId, 
          orderNumber, 
          AUTO_CREATE_CONFIG.require_approval ? 'pending_approval' : 'received_customer',
          'urgent',
          `Auto-created for unknown barcode: ${normalizedBarcode}. Received by: ${req.user.username}`,
          req.user.userId
        ]);

        const newSampleResult = await query(`
          INSERT INTO samples (order_id, barcode, sample_type, status, location, notes, received_at, received_by)
          VALUES ($1, $2, 'environmental', 'received', $3, $4, CURRENT_TIMESTAMP, $5)
          RETURNING *
        `, [orderResult.rows[0].id, normalizedBarcode, location, notes, req.user.userId]);
        
        await logAudit(req.user.userId, 'CREATE', 'sample', newSampleResult.rows[0].id, 
          `Auto-created sample for unknown barcode: ${normalizedBarcode}`);
        
        return res.json({
          message: 'Sample received and auto-created',
          sample: newSampleResult.rows[0],
          order: orderResult.rows[0],
          auto_created: true
        });
      } else {
        return res.status(404).json({ 
          error: 'Sample not found',
          barcode: normalizedBarcode,
          suggestion: 'Enable auto-create mode or assign barcode to an order first'
        });
      }
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
    
    const updatedSampleResult = await query(`
      SELECT s.*, o.order_number, c.name as customer_name, c.company_name,
             u.full_name as received_by_name
      FROM samples s
      LEFT JOIN orders o ON s.order_id = o.id
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN users u ON s.received_by = u.id
      WHERE s.id = $1
    `, [sample.id]);
    
    res.json({