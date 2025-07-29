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
const emailTransporter = nodemailer.createTransporter({
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

// Initialize database tables (same as before but with flexible shipping schema)
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
    // [Previous database initialization code remains the same until shipping tables]
    
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

    // Create other tables (customers, orders, samples, etc. - same as before)
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

    // Create other tables (test_results, batches, etc. - same as before)
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

    // [Continue with other table creation - audit_log, email_notifications, etc.]

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Helper functions (same as before for customer creation, address formatting, etc.)
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

// WooCommerce Webhook (same as before)
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

// Flexible Shipping Endpoints

// Get shipping rates (manual or API-based)
app.get('/api/shipping/rates/:order_id', authenticateToken, async (req, res) => {
  try {
    const { order_id } = req.params;
    
    // Get order details
    const orderResult = await query(`
      SELECT o.*, c.shipping_address, c.billing_address
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [order_id]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Return standard rates (can be enhanced with real API calls)
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
    
    res.json({ rates });
  } catch (error) {
    console.error('Shipping rates error:', error);
    res.status(500).json({ error: 'Failed to get shipping rates' });
  }
});

// Create shipping label (flexible)
app.post('/api/shipping/create-label', authenticateToken, async (req, res) => {
  try {
    const { order_id, service_type = 'ups_ground', api_provider = 'manual' } = req.body;
    
    // Get order and customer details
    const orderResult = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email,
             c.shipping_address, c.billing_address, c.phone
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [order_id]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    // Use the appropriate shipping API
    const shippingAPI = createShippingAPI();
    const labelResult = await shippingAPI[api_provider].createLabel({
      order: order,
      service: service_type,
      estimated_cost: service_type === 'ups_ground' ? 8.50 : 
                     service_type === 'ups_2day' ? 15.99 : 25.99
    });
    
    // Save shipping label info
    const labelRecord = await query(`
      INSERT INTO shipping_labels (
        order_id, tracking_number, carrier, service,
        cost, label_url, api_provider, status, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *
    `, [
      order_id,
      labelResult.tracking_number,
      labelResult.carrier,
      service_type,
      labelResult.cost,
      labelResult.label_url,
      api_provider,
      'created',
      req.user.userId
    ]);
    
    // Update order with tracking info
    await query(`
      UPDATE orders SET 
        tracking_number = $1, 
        shipping_cost = $2,
        shipping_service = $3,
        shipping_carrier = $4,
        shipping_api_used = $5,
        label_created_at = CURRENT_TIMESTAMP,
        status = CASE WHEN status = 'pending' THEN 'label_created' ELSE status END,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
    `, [
      labelResult.tracking_number,
      labelResult.cost,
      service_type,
      labelResult.carrier,
      api_provider,
      order_id
    ]);
    
    await logAudit(
      req.user.userId, 
      'CREATE', 
      'shipping_label', 
      labelRecord.rows[0].id, 
      `Created ${service_type} label using ${api_provider} for order ${order.order_number}`
    );
    
    res.json({
      message: 'Shipping label created successfully',
      tracking_number: labelResult.tracking_number,
      label_url: labelResult.label_url,
      cost: labelResult.cost,
      api_provider: api_provider
    });
    
  } catch (error) {
    console.error('Shipping label creation error:', error);
    res.status(500).json({ 
      error: 'Failed to create shipping label',
      details: error.message
    });
  }
});

// Manual tracking number entry
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

// Track shipment (flexible)
app.get('/api/shipping/track/:tracking_number', authenticateToken, async (req, res) => {
  try {
    const { tracking_number } = req.params;
    
    // Get shipping info from database
    const shippingResult = await query(`
      SELECT sl.*, o.order_number 
      FROM shipping_labels sl
      JOIN orders o ON sl.order_id = o.id
      WHERE sl.tracking_number = $1
    `, [tracking_number]);
    
    if (shippingResult.rows.length === 0) {
      return res.status(404).json({ error: 'Tracking number not found' });
    }
    
    const shippingInfo = shippingResult.rows[0];
    
    // Use appropriate tracking API or return manual status
    const shippingAPI = createShippingAPI();
    const trackingResult = await shippingAPI[shippingInfo.api_provider].trackShipment(tracking_number);
    
    res.json({
      ...trackingResult,
      order_number: shippingInfo.order_number,
      api_provider: shippingInfo.api_provider
    });
    
  } catch (error) {
    console.error('Tracking error:', error);
    res.status(500).json({ error: 'Failed to track shipment' });
  }
});

// [Continue with all other existing routes - authentication, customers, orders, samples, etc.]
// [The rest of your existing API endpoints remain the same]

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