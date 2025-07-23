const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Samples table (NEW)
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

    // Test Results table (NEW)
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

    // Batches table (NEW)
    await query(`
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY,
        batch_number VARCHAR(50) UNIQUE NOT NULL,
        test_type VARCHAR(100),
        status VARCHAR(50) DEFAULT 'pending',
        created_by INTEGER REFERENCES users(id),
        sample_count INTEGER DEFAULT 0,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Quality Control table (NEW)
    await query(`
      CREATE TABLE IF NOT EXISTS quality_control (
        id SERIAL PRIMARY KEY,
        batch_id INTEGER REFERENCES batches(id),
        control_type VARCHAR(50),
        expected_result VARCHAR(50),
        actual_result VARCHAR(50),
        passed BOOLEAN,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Check if admin user exists, create if not
    const adminCheck = await query('SELECT * FROM users WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await query(
        'INSERT INTO users (username, password_hash, role, email) VALUES ($1, $2, $3, $4)',
        ['admin', hashedPassword, 'admin', 'admin@3rtesting.com']
      );
      console.log('Admin user created');
    }

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    message: '3R Testing LIMS Backend is running',
    database: 'PostgreSQL'
  });
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
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
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Customer routes
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT c.*, COUNT(o.id) as total_orders 
      FROM customers c 
      LEFT JOIN orders o ON c.id = o.customer_id 
      GROUP BY c.id 
      ORDER BY c.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
    const { name, email, company_name, phone, shipping_address, billing_address, notes } = req.body;
    
    const result = await query(
      `INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [name, email, company_name, phone, shipping_address, billing_address, notes]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating customer:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Customer with this email already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create customer' });
    }
  }
});

// Order routes
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name,
             COUNT(s.id) as received_samples
      FROM orders o 
      JOIN customers c ON o.customer_id = c.id 
      LEFT JOIN samples s ON o.id = s.order_id AND s.status != 'pending'
      GROUP BY o.id, c.name, c.email, c.company_name
      ORDER BY o.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { customer_id, sample_count, shipping_method, priority, notes } = req.body;
    
    // Generate order number
    const orderNumber = 'ORD-' + Date.now();
    
    const result = await query(
      `INSERT INTO orders (customer_id, order_number, sample_count, shipping_method, priority, notes) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [customer_id, orderNumber, sample_count, shipping_method, priority, notes]
    );
    
    // Generate sample barcodes for this order
    const order = result.rows[0];
    for (let i = 1; i <= sample_count; i++) {
      const barcode = `${orderNumber}-S${i.toString().padStart(2, '0')}`;
      await query(
        'INSERT INTO samples (order_id, barcode) VALUES ($1, $2)',
        [order.id, barcode]
      );
    }
    
    res.json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Sample routes (NEW)
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT s.*, o.order_number, c.name as customer_name, c.company_name,
             COUNT(tr.id) as test_count
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN test_results tr ON s.id = tr.sample_id
      GROUP BY s.id, o.order_number, c.name, c.company_name
      ORDER BY s.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching samples:', error);
    res.status(500).json({ error: 'Failed to fetch samples' });
  }
});

app.post('/api/samples/receive', authenticateToken, async (req, res) => {
  try {
    const { barcode, location = 'Main Lab', notes = '' } = req.body;
    
    const result = await query(
      `UPDATE samples 
       SET status = 'received', received_at = CURRENT_TIMESTAMP, location = $2, notes = $3
       WHERE barcode = $1 
       RETURNING *`,
      [barcode, location, notes]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sample not found' });
    }
    
    // Get customer info
    const sampleInfo = await query(`
      SELECT s.*, o.order_number, c.name as customer_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE s.id = $1
    `, [result.rows[0].id]);
    
    res.json({ 
      message: 'Sample received successfully',
      sample: sampleInfo.rows[0]
    });
  } catch (error) {
    console.error('Error receiving sample:', error);
    res.status(500).json({ error: 'Failed to receive sample' });
  }
});

app.patch('/api/samples/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, batch_id, notes } = req.body;
    
    let updateQuery = 'UPDATE samples SET status = $1';
    let params = [status];
    let paramCount = 1;
    
    if (status === 'processing') {
      updateQuery += ', processed_at = CURRENT_TIMESTAMP';
    } else if (status === 'complete') {
      updateQuery += ', completed_at = CURRENT_TIMESTAMP';
    }
    
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
    
    paramCount++;
    updateQuery += ` WHERE id = $${paramCount} RETURNING *`;
    params.push(id);
    
    const result = await query(updateQuery, params);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Sample not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating sample status:', error);
    res.status(500).json({ error: 'Failed to update sample status' });
  }
});

// Batch routes (NEW)
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT b.*, u.username as created_by_name,
             COUNT(s.id) as actual_sample_count
      FROM batches b
      LEFT JOIN users u ON b.created_by = u.id
      LEFT JOIN samples s ON b.batch_number = s.batch_id
      GROUP BY b.id, u.username
      ORDER BY b.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching batches:', error);
    res.status(500).json({ error: 'Failed to fetch batches' });
  }
});

app.post('/api/batches', authenticateToken, async (req, res) => {
  try {
    const { test_type, sample_ids, notes } = req.body;
    
    // Generate batch number
    const batchNumber = 'BATCH-' + Date.now();
    
    const result = await query(
      `INSERT INTO batches (batch_number, test_type, created_by, sample_count, notes) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [batchNumber, test_type, req.user.userId, sample_ids.length, notes]
    );
    
    // Update samples with batch ID
    for (const sampleId of sample_ids) {
      await query(
        'UPDATE samples SET batch_id = $1, status = $2 WHERE id = $3',
        [batchNumber, 'processing', sampleId]
      );
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating batch:', error);
    res.status(500).json({ error: 'Failed to create batch' });
  }
});

// Test Results routes (NEW)
app.post('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { test_type, result, value, units, detection_limit, method, notes } = req.body;
    
    const resultData = await query(
      `INSERT INTO test_results (sample_id, test_type, result, value, units, detection_limit, method, analyst, notes) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [id, test_type, result, value, units, detection_limit, method, req.user.username, notes]
    );
    
    // Update sample status to complete
    await query(
      'UPDATE samples SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['complete', id]
    );
    
    res.json(resultData.rows[0]);
  } catch (error) {
    console.error('Error adding test result:', error);
    res.status(500).json({ error: 'Failed to add test result' });
  }
});

app.get('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await query(
      'SELECT * FROM test_results WHERE sample_id = $1 ORDER BY analyzed_at DESC',
      [id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching test results:', error);
    res.status(500).json({ error: 'Failed to fetch test results' });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [orders, samples, batches] = await Promise.all([
      query('SELECT status, COUNT(*) as count FROM orders GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM samples GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM batches GROUP BY status')
    ]);
    
    const stats = {
      pending_orders: 0,
      shipped_orders: 0,
      processing_orders: 0,
      complete_orders: 0,
      pending_samples: 0,
      received_samples: 0,
      processing_samples: 0,
      complete_samples: 0,
      active_batches: 0,
      complete_batches: 0
    };
    
    orders.rows.forEach(row => {
      stats[`${row.status}_orders`] = parseInt(row.count);
    });
    
    samples.rows.forEach(row => {
      stats[`${row.status}_samples`] = parseInt(row.count);
    });
    
    batches.rows.forEach(row => {
      if (row.status === 'complete') {
        stats.complete_batches = parseInt(row.count);
      } else {
        stats.active_batches += parseInt(row.count);
      }
    });
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`3R Testing LIMS Server running on port ${PORT}`);
  console.log(`Database type: PostgreSQL`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;