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

// Email configuration - FIXED: createTransport not createTransporter
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER || 'your-email@gmail.com',
    pass: process.env.SMTP_PASS || 'your-app-password'
  }
});

// Shipping Configuration (Multiple Options)
const SHIPPING_CONFIG = {
  // Option 1: Manual tracking (no API required)
  default_carrier: 'UPS',
  default_service: 'Ground',
  
  // Option 2: ShipEngine (alternative to PirateShip)
  shipengine_api_key: process.env.SHIPENGINE_API_KEY,
  
  // Option 3: EasyPost (another alternative)
  easypost_api_key: process.env.EASYPOST_API_KEY,
  
  // Option 4: Direct UPS/FedEx APIs
  ups_api_key: process.env.UPS_API_KEY,
  fedex_api_key: process.env.FEDEX_API_KEY,
  
  // Lab shipping address
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

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Raw body parser for webhook signature verification
app.use('/api/webhooks/woocommerce', express.raw({ type: 'application/json' }));

// Regular JSON parser for other routes
app.use(express.json());

// JWT Secret
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

// Admin-only middleware
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

// WooCommerce webhook signature verification
const verifyWooCommerceSignature = (body, signature) => {
  if (!WOOCOMMERCE_WEBHOOK_SECRET) {
    console.warn('WooCommerce webhook secret not configured');
    return true; // Allow for development
  }
  
  const expectedSignature = crypto
    .createHmac('sha256', WOOCOMMERCE_WEBHOOK_SECRET)
    .update(body)
    .digest('base64');
  
  return signature === expectedSignature;
};

// Generic Shipping API helper (can be adapted for different services)
const createShippingAPI = (service = 'manual') => {
  return {
    // Manual shipping (no API - user enters tracking manually)
    manual: {
      createLabel: async (shipmentData) => {
        // Generate a manual tracking number
        const trackingNumber = `3RT${Date.now()}`;
        return {
          tracking_number: trackingNumber,
          label_url: null,
          cost: shipmentData.estimated_cost || 8.50,
          service: shipmentData.service || 'UPS Ground',
          carrier: 'UPS'
        };
      },
      
      trackShipment: async (trackingNumber) => {
        // For manual mode, return basic status
        return {
          tracking_number: trackingNumber,
          status: 'in_transit',
          status_description: 'Manual tracking - check carrier website',
          location: 'In Transit',
          carrier: 'UPS'
        };
      }
    },
    
    // ShipEngine integration (alternative to PirateShip)
    shipengine: {
      createLabel: async (shipmentData) => {
        if (!SHIPPING_CONFIG.shipengine_api_key) {
          throw new Error('ShipEngine API key not configured');
        }
        
        const response = await axios.post('https://api.shipengine.com/v1/labels', {
          rate_id: shipmentData.rate_id,
          validate_address: 'validate_and_clean',
          label_layout: 'letter',
          label_format: 'pdf'
        }, {
          headers: {
            'API-Key': SHIPPING_CONFIG.shipengine_api_key,
            'Content-Type': 'application/json'
          }
        });
        
        return {
          tracking_number: response.data.tracking_number,
          label_url: response.data.label_download.pdf,
          cost: response.data.shipment_cost.amount,
          service: response.data.service_type,
          carrier: response.data.carrier_id
        };
      },
      
      trackShipment: async (trackingNumber) => {
        const response = await axios.get(`https://api.shipengine.com/v1/tracking?tracking_number=${trackingNumber}`, {
          headers: {
            'API-Key': SHIPPING_CONFIG.shipengine_api_key
          }
        });
        
        return response.data;
      }
    }
  };
};

// Product mapping configuration
const PRODUCT_SAMPLE_MAPPING = {
  // Map WooCommerce product IDs/SKUs to sample types and counts
  'pathogen-test-single': { sample_count: 1, test_type: 'HLVD' },
  'pathogen-test-5pack': { sample_count: 5, test_type: 'HLVD' },
  'pathogen-test-10pack': { sample_count: 10, test_type: 'HLVD' },
  'fusarium-test': { sample_count: 1, test_type: 'Fusarium' },
  'pythium-test': { sample_count: 1, test_type: 'Pythium' },
  'combo-test': { sample_count: 1, test_type: 'Fus+Pyth' }
};

// Initialize database tables
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
    // Create default admin user if not exists
    const defaultUsers = [
      { username: 'admin', password: 'admin123', role: 'admin', email: 'admin@3rtesting.com', full_name: 'System Administrator' },
      { username: 'technician', password: 'tech123', role: 'technician', email: 'tech@3rtesting.com', full_name: 'Lab Technician' }
    ];

    // Create basic users table if it doesn't exist
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        email VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add user columns
    const userColumns = [
      { name: 'full_name', type: 'VARCHAR(100)' },
      { name: 'is_active', type: 'BOOLEAN DEFAULT true' },
      { name: 'last_login', type: 'TIMESTAMP' },
      { name: 'password_changed_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' },
      { name: 'created_by', type: 'INTEGER' },
      { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
    ];

    for (const column of userColumns) {
      const exists = await columnExists('users', column.name);
      if (!exists) {
        await query(`ALTER TABLE users ADD COLUMN ${column.name} ${column.type}`);
        console.log(`Added column ${column.name} to users table`);
      }
    }

    // Create default users
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add WooCommerce fields to customers
    const customerWooColumns = [
      { name: 'woocommerce_id', type: 'INTEGER UNIQUE' },
      { name: 'woocommerce_username', type: 'VARCHAR(100)' },
      { name: 'created_by', type: 'INTEGER REFERENCES users(id)' },
      { name: 'updated_at', type: 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' }
    ];

    for (const column of customerWooColumns) {
      const exists = await columnExists('customers', column.name);
      if (!exists) {
        await query(`ALTER TABLE customers ADD COLUMN ${column.name} ${column.type}`);
      }
    }

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add enhanced fields to orders
    const orderColumns = [
      { name: 'woocommerce_order_id', type: 'INTEGER UNIQUE' },
      { name: 'woocommerce_status', type: 'VARCHAR(50)' },
      { name: 'shipping_cost', type: 'DECIMAL(10,2)' },
      { name: 'shipping_service', type: 'VARCHAR(50)' },
      { name: 'shipping_carrier', type: 'VARCHAR(50)' },
      { name: 'shipping_api_used', type: 'VARCHAR(50) DEFAULT \'manual\'' },
      { name: 'label_created_at', type: 'TIMESTAMP' },
      { name: 'shipped_at', type: 'TIMESTAMP' },
      { name: 'delivered_at', type: 'TIMESTAMP' },
      { name: 'created_by', type: 'INTEGER REFERENCES users(id)' },
      { name: 'test_type', type: 'VARCHAR(100)' }
    ];

    for (const column of orderColumns) {
      const exists = await columnExists('orders', column.name);
      if (!exists) {
        await query(`ALTER TABLE orders ADD COLUMN ${column.name} ${column.type}`);
      }
    }

    // Create flexible shipping labels table
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

    // Create samples table
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const sampleUserCols = ['received_by', 'processed_by'];
    for (const col of sampleUserCols) {
      const exists = await columnExists('samples', col);
      if (!exists) {
        await query(`ALTER TABLE samples ADD COLUMN ${col} INTEGER REFERENCES users(id)`);
      }
    }

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
        created_by INTEGER REFERENCES users(id)
      )
    `);

    // Create WooCommerce webhook log table
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

    // Create audit log table
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

    // Create email notifications table
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

    console.log('✅ Database tables initialized successfully');
    
    // Create sample data for demonstration
    await createSampleData();
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Create sample data for demonstration
async function createSampleData() {
  try {
    // Check if sample customers exist
    const customerCount = await query('SELECT COUNT(*) FROM customers');
    if (parseInt(customerCount.rows[0].count) === 0) {
      console.log('Creating sample customers...');
      
      const sampleCustomers = [
        {
          name: 'John Smith',
          email: 'john.smith@example.com',
          company_name: 'Green Valley Farms',
          phone: '555-123-4567',
          shipping_address: '123 Farm Road, Green Valley, CA 90210',
          billing_address: '123 Farm Road, Green Valley, CA 90210'
        },
        {
          name: 'Sarah Johnson',
          email: 'sarah.johnson@hydroponics.com',
          company_name: 'Advanced Hydroponics Inc',
          phone: '555-987-6543',
          shipping_address: '456 Tech Boulevard, Innovation City, CA 94102',
          billing_address: '456 Tech Boulevard, Innovation City, CA 94102'
        }
      ];

      for (const customer of sampleCustomers) {
        await query(`
          INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, created_by)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [customer.name, customer.email, customer.company_name, customer.phone, customer.shipping_address, customer.billing_address, 1]);
      }
      
      console.log('✅ Sample customers created');
    }

    // Create sample orders
    const orderCount = await query('SELECT COUNT(*) FROM orders');
    if (parseInt(orderCount.rows[0].count) === 0) {
      console.log('Creating sample orders...');
      
      const sampleOrders = [
        {
          customer_id: 1,
          order_number: 'ORD-001',
          sample_count: 5,
          test_type: 'HLVD',
          status: 'pending',
          priority: 'normal',
          shipping_method: 'ups_ground'
        },
        {
          customer_id: 2,
          order_number: 'ORD-002',
          sample_count: 10,
          test_type: 'Fusarium',
          status: 'shipped',
          priority: 'high',
          shipping_method: 'ups_2day',
          tracking_number: '1Z999AA1234567890'
        }
      ];

      for (const order of sampleOrders) {
        const orderResult = await query(`
          INSERT INTO orders (customer_id, order_number, sample_count, test_type, status, priority, shipping_method, tracking_number, created_by)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id
        `, [order.customer_id, order.order_number, order.sample_count, order.test_type, order.status, order.priority, order.shipping_method, order.tracking_number || null, 1]);
        
        // Create sample barcodes for each order
        for (let i = 1; i <= order.sample_count; i++) {
          const barcode = `${order.order_number}-S${i.toString().padStart(2, '0')}`;
          await query(`
            INSERT INTO samples (order_id, barcode, sample_type, status)
            VALUES ($1, $2, $3, $4)
          `, [orderResult.rows[0].id, barcode, order.test_type, order.status === 'shipped' ? 'received' : 'pending']);
        }
      }
      
      console.log('✅ Sample orders and samples created');
    }

  } catch (error) {
    console.log('Sample data creation failed (this is okay for existing databases):', error.message);
  }
}

// Helper functions
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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: '3R Testing LIMS Backend is running',
    database: 'PostgreSQL',
    version: '3.0.0 - Enhanced Shipping Integration',
    features: [
      'email_notifications', 
      'pdf_reports', 
      'customer_portal',
      'woocommerce_integration',
      'flexible_shipping'
    ],
    shipping_options: ['manual', 'shipengine', 'easypost', 'ups_direct'],
    current_shipping_mode: SHIPPING_CONFIG.shipengine_api_key ? 'shipengine' : 'manual'
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
    
    // Update last login
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

// Customers endpoints
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
    
    // Check for duplicate email
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

// Orders endpoints
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
    
    // Generate order number
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

// Samples endpoints
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT s.*, 
             o.order_number,
             c.name as customer_name,
             c.company_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
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
    
    // Find sample
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
    
    // Update sample status
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

// WooCommerce Webhook
app.post('/api/webhooks/woocommerce', async (req, res) => {
  try {
    const signature = req.headers['x-wc-webhook-signature'];
    const body = req.body;
    
    if (!verifyWooCommerceSignature(body, signature)) {
      console.error('Invalid WooCommerce webhook signature');
      return res.status(401).json({ error: 'Invalid signature' });
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
      `Auto-created from WooCommerce order #${orderData.id}. Total: $${orderData.total}`,
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

// Manual shipping endpoints
app.post('/api/shipping/manual-tracking', authenticateToken, async (req, res) => {
  try {
    const { order_id, tracking_number, carrier = 'UPS', service = 'Ground', cost = 0 } = req.body;
    
    if (!tracking_number) {
      return res.status(400).json({ error: 'Tracking number is required' });
    }
    
    // Update order with manual tracking info
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
    
    // Create shipping label record
    await query(`
      INSERT INTO shipping_labels (
        order_id, tracking_number, carrier, service, cost,
        api_provider, status, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [
      order_id, tracking_number, carrier, service, cost,
      'manual', 'created', req.user.userId
    ]);
    
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

// Get all batches
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

// Get all users (admin only)
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

// Get audit log (admin only)
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

// Get email notifications (admin only)
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

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Database type: PostgreSQL`);
  console.log(`Version: 3.0.0 - Enhanced Shipping Integration`);
  console.log(`WooCommerce webhook: ${WOOCOMMERCE_WEBHOOK_SECRET ? '✅ Configured' : '❌ Not configured'}`);
  console.log(`Shipping mode: ${SHIPPING_CONFIG.shipengine_api_key ? 'ShipEngine API' : 'Manual'}`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;