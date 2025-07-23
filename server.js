// Enhanced server.js - Full LIMS Backend for 3R Testing
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// Database connection - Works with PostgreSQL or MySQL
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
};

// Use pg for PostgreSQL (Render's default) or mysql2 for MySQL
let pool;
const isPostgreSQL = process.env.DATABASE_URL || process.env.DB_PORT == 5432;

if (isPostgreSQL) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
} else {
  pool = mysql.createPool(dbConfig);
}

// Database query wrapper to handle both PostgreSQL and MySQL
async function query(sql, params = []) {
  if (isPostgreSQL) {
    // Convert MySQL-style ? placeholders to PostgreSQL $1, $2, etc.
    let paramIndex = 1;
    const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
    const result = await pool.query(pgSql, params);
    return result.rows;
  } else {
    const [rows] = await pool.execute(sql, params);
    return rows;
  }
}

// Initialize database tables
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
    // Users table
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id ${isPostgreSQL ? 'SERIAL PRIMARY KEY' : 'INT AUTO_INCREMENT PRIMARY KEY'},
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255),
        first_name VARCHAR(50),
        last_name VARCHAR(50),
        role VARCHAR(20) DEFAULT 'technician',
        is_active BOOLEAN DEFAULT TRUE,
        created_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'},
        updated_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'}
      )
    `);

    // Customers table
    await query(`
      CREATE TABLE IF NOT EXISTS customers (
        id ${isPostgreSQL ? 'SERIAL PRIMARY KEY' : 'INT AUTO_INCREMENT PRIMARY KEY'},
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        company_name VARCHAR(100),
        phone VARCHAR(20),
        shipping_address TEXT,
        billing_address TEXT,
        notes TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'},
        updated_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'}
      )
    `);

    // Orders table
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id ${isPostgreSQL ? 'SERIAL PRIMARY KEY' : 'INT AUTO_INCREMENT PRIMARY KEY'},
        order_number VARCHAR(20) UNIQUE,
        customer_id INTEGER REFERENCES customers(id),
        sample_count INTEGER NOT NULL DEFAULT 0,
        status VARCHAR(30) DEFAULT 'pending',
        shipping_method VARCHAR(50) DEFAULT 'ups_ground',
        tracking_number VARCHAR(100),
        notes TEXT,
        priority VARCHAR(20) DEFAULT 'normal',
        created_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'},
        shipped_at TIMESTAMP NULL,
        delivered_at TIMESTAMP NULL,
        received_at TIMESTAMP NULL,
        completed_at TIMESTAMP NULL,
        updated_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'}
      )
    `);

    // Samples table
    await query(`
      CREATE TABLE IF NOT EXISTS samples (
        id ${isPostgreSQL ? 'SERIAL PRIMARY KEY' : 'INT AUTO_INCREMENT PRIMARY KEY'},
        order_id INTEGER REFERENCES orders(id),
        barcode VARCHAR(8) NOT NULL UNIQUE,
        status VARCHAR(30) DEFAULT 'assigned',
        well_position VARCHAR(10),
        assigned_at ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'},
        received_at TIMESTAMP NULL,
        tested_at TIMESTAMP NULL,
        notes TEXT
      )
    `);

    // Results table
    await query(`
      CREATE TABLE IF NOT EXISTS results (
        id ${isPostgreSQL ? 'SERIAL PRIMARY KEY' : 'INT AUTO_INCREMENT PRIMARY KEY'},
        order_id INTEGER REFERENCES orders(id),
        file_path VARCHAR(500),
        file_name VARCHAR(255),
        version INTEGER DEFAULT 1,
        upload_date ${isPostgreSQL ? 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP' : 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'},
        notes TEXT
      )
    `);

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
  }
}

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// ==================
// HEALTH & AUTH ROUTES
// ==================

app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    if (isPostgreSQL) {
      await pool.query('SELECT 1');
    } else {
      await pool.execute('SELECT 1');
    }
    
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      message: '3R Testing LIMS Backend is running',
      database: isPostgreSQL ? 'PostgreSQL' : 'MySQL'
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'ERROR', 
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    // Default admin login
    if (username === 'admin' && password === 'admin123') {
      const token = jwt.sign(
        { id: 1, username: 'admin', role: 'admin' },
        process.env.JWT_SECRET || 'fallback_secret',
        { expiresIn: '24h' }
      );
      
      res.json({ 
        token,
        user: { id: 1, username: 'admin', role: 'admin' }
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================
// CUSTOMERS ROUTES
// ==================

app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const customers = await query(`
      SELECT c.*, 
             COUNT(o.id) as total_orders
      FROM customers c 
      LEFT JOIN orders o ON c.id = o.customer_id 
      WHERE c.is_active = true
      GROUP BY c.id 
      ORDER BY c.created_at DESC
    `);
    res.json(customers);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  const { name, email, company_name, phone, shipping_address, billing_address, notes } = req.body;
  
  try {
    // Check for duplicate customer
    const existing = await query(
      'SELECT id, name, email, company_name FROM customers WHERE email = ? OR (company_name = ? AND company_name IS NOT NULL)',
      [email, company_name]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        error: 'Customer already exists',
        existing_customer: existing[0]
      });
    }

    const result = await query(`
      INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ${isPostgreSQL ? 'RETURNING id' : ''}
    `, [name, email, company_name, phone, shipping_address, billing_address, notes]);

    const customerId = isPostgreSQL ? result[0].id : result.insertId;

    res.status(201).json({
      id: customerId,
      message: 'Customer created successfully'
    });
  } catch (error) {
    console.error('Error creating customer:', error);
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

// ==================
// ORDERS ROUTES
// ==================

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name,
             COUNT(s.id) as total_samples,
             COUNT(CASE WHEN s.status = 'received' THEN 1 END) as received_samples
      FROM orders o 
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN samples s ON o.id = s.order_id
      GROUP BY o.id, c.id
      ORDER BY o.created_at DESC
    `);
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { customer_id, sample_count, shipping_method, notes, priority = 'normal' } = req.body;

  try {
    // Create order
    const orderResult = await query(`
      INSERT INTO orders (customer_id, sample_count, status, shipping_method, notes, priority)
      VALUES (?, ?, 'pending', ?, ?, ?)
      ${isPostgreSQL ? 'RETURNING id' : ''}
    `, [customer_id, sample_count, shipping_method, notes, priority]);

    const orderId = isPostgreSQL ? orderResult[0].id : orderResult.insertId;

    // Generate order number (format: year + sequential number)
    const year = new Date().getFullYear();
    const orderNumber = `${year}${orderId.toString().padStart(4, '0')}`;
    
    await query('UPDATE orders SET order_number = ? WHERE id = ?', [orderNumber, orderId]);

    res.status(201).json({
      id: orderId,
      order_number: orderNumber,
      message: 'Order created successfully'
    });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

app.patch('/api/orders/:id/status', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, tracking_number, notes } = req.body;

  try {
    let updateQuery = 'UPDATE orders SET status = ?';
    let params = [status];

    if (tracking_number) {
      updateQuery += ', tracking_number = ?';
      params.push(tracking_number);
    }

    if (status === 'shipped') {
      updateQuery += ', shipped_at = ' + (isPostgreSQL ? 'CURRENT_TIMESTAMP' : 'NOW()');
    } else if (status === 'received_customer') {
      updateQuery += ', delivered_at = ' + (isPostgreSQL ? 'CURRENT_TIMESTAMP' : 'NOW()');
    } else if (status === 'processing') {
      updateQuery += ', received_at = ' + (isPostgreSQL ? 'CURRENT_TIMESTAMP' : 'NOW()');
    } else if (status === 'complete') {
      updateQuery += ', completed_at = ' + (isPostgreSQL ? 'CURRENT_TIMESTAMP' : 'NOW()');
    }

    updateQuery += ' WHERE id = ?';
    params.push(id);

    await query(updateQuery, params);

    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// ==================
// SAMPLES ROUTES
// ==================

app.post('/api/orders/:orderId/samples', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { barcodes } = req.body; // Array of barcode strings

  try {
    for (const barcode of barcodes) {
      // Check if barcode already exists
      const existing = await query('SELECT id FROM samples WHERE barcode = ?', [barcode]);

      if (existing.length > 0) {
        return res.status(400).json({ error: `Barcode ${barcode} already assigned` });
      }

      // Insert sample
      await query(`
        INSERT INTO samples (order_id, barcode, status)
        VALUES (?, ?, 'assigned')
      `, [orderId, barcode]);
    }

    res.json({ message: 'Barcodes assigned successfully' });
  } catch (error) {
    console.error('Error assigning barcodes:', error);
    res.status(500).json({ error: 'Failed to assign barcodes' });
  }
});

app.post('/api/samples/receive', authenticateToken, async (req, res) => {
  const { barcode } = req.body;

  try {
    const samples = await query(`
      SELECT s.*, o.order_number, c.name as customer_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE s.barcode = ?
    `, [barcode]);

    if (samples.length === 0) {
      return res.status(404).json({ error: 'Barcode not found' });
    }

    const sample = samples[0];

    // Update sample status
    await query(
      'UPDATE samples SET status = ?, received_at = ' + (isPostgreSQL ? 'CURRENT_TIMESTAMP' : 'NOW()') + ' WHERE barcode = ?',
      ['received', barcode]
    );

    res.json({
      message: 'Sample received successfully',
      sample: sample
    });
  } catch (error) {
    console.error('Error receiving sample:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

// ==================
// DASHBOARD STATS
// ==================

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await query(`
      SELECT 
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_orders,
        COUNT(CASE WHEN status = 'shipped' THEN 1 END) as shipped_orders,
        COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing_orders,
        COUNT(CASE WHEN status = 'complete' THEN 1 END) as complete_orders,
        COUNT(*) as total_orders
      FROM orders
      WHERE created_at >= ${isPostgreSQL ? "CURRENT_DATE - INTERVAL '30 days'" : 'DATE_SUB(NOW(), INTERVAL 30 DAY)'}
    `);

    res.json(stats[0] || {
      pending_orders: 0,
      shipped_orders: 0, 
      processing_orders: 0,
      complete_orders: 0,
      total_orders: 0
    });
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Error handling
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Initialize database and start server
initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log('3R Testing LIMS Server running on port ' + PORT);
    console.log('Database type: ' + (isPostgreSQL ? 'PostgreSQL' : 'MySQL'));
  });
});

module.exports = app;