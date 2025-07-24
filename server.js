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

// Admin-only middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Audit logging function
const logAudit = async (userId, action, entityType, entityId, details = null) => {
  try {
    await query(
      `INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address) 
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, action, entityType, entityId, details, 'system']
    );
  } catch (error) {
    console.error('Audit logging failed:', error);
  }
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
    
    // Users table (ENHANCED)
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'technician',
        email VARCHAR(100),
        full_name VARCHAR(100),
        is_active BOOLEAN DEFAULT true,
        last_login TIMESTAMP,
        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Audit Log table (NEW)
    await query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(50) NOT NULL,
        entity_type VARCHAR(50),
        entity_id INTEGER,
        details TEXT,
        ip_address VARCHAR(45),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Database Backups table (NEW)
    await query(`
      CREATE TABLE IF NOT EXISTS database_backups (
        id SERIAL PRIMARY KEY,
        backup_name VARCHAR(100) NOT NULL,
        backup_type VARCHAR(20) DEFAULT 'manual',
        created_by INTEGER REFERENCES users(id),
        file_size BIGINT,
        status VARCHAR(20) DEFAULT 'completed',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Session Log table (NEW)
    await query(`
      CREATE TABLE IF NOT EXISTS session_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(20), -- 'login', 'logout', 'timeout'
        ip_address VARCHAR(45),
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        received_by INTEGER REFERENCES users(id),
        processed_by INTEGER REFERENCES users(id)
      )
    `);

    // Test Results table
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
        analyst_id INTEGER REFERENCES users(id),
        reviewed_by INTEGER REFERENCES users(id),
        analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP,
        notes TEXT
      )
    `);

    // Batches table
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

    // Quality Control table
    await query(`
      CREATE TABLE IF NOT EXISTS quality_control (
        id SERIAL PRIMARY KEY,
        batch_id INTEGER REFERENCES batches(id),
        control_type VARCHAR(50),
        expected_result VARCHAR(50),
        actual_result VARCHAR(50),
        passed BOOLEAN,
        tested_by INTEGER REFERENCES users(id),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Check if admin user exists, create if not
    const adminCheck = await query('SELECT * FROM users WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const adminResult = await query(
        'INSERT INTO users (username, password_hash, role, email, full_name) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        ['admin', hashedPassword, 'admin', 'admin@3rtesting.com', 'System Administrator']
      );
      console.log('Admin user created');
      
      // Log admin creation
      await logAudit(adminResult.rows[0].id, 'CREATE', 'user', adminResult.rows[0].id, 'System admin user created');
    }

    // Create default technician if not exists
    const techCheck = await query('SELECT * FROM users WHERE username = $1', ['technician']);
    if (techCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('tech123', 10);
      const techResult = await query(
        'INSERT INTO users (username, password_hash, role, email, full_name, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        ['technician', hashedPassword, 'technician', 'tech@3rtesting.com', 'Lab Technician', 1]
      );
      console.log('Default technician user created');
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
    database: 'PostgreSQL',
    version: '2.0.0'
  });
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await query('SELECT * FROM users WHERE username = $1 AND is_active = true', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    
    // Log session
    await query(
      'INSERT INTO session_log (user_id, action, ip_address) VALUES ($1, $2, $3)',
      [user.id, 'login', req.ip || 'unknown']
    );
    
    // Log audit
    await logAudit(user.id, 'LOGIN', 'session', null, `User ${username} logged in`);
    
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

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    // Log session
    await query(
      'INSERT INTO session_log (user_id, action, ip_address) VALUES ($1, $2, $3)',
      [req.user.userId, 'logout', req.ip || 'unknown']
    );
    
    // Log audit
    await logAudit(req.user.userId, 'LOGOUT', 'session', null, `User ${req.user.username} logged out`);
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// User Management routes (NEW)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT u.*, c.username as created_by_name 
      FROM users u 
      LEFT JOIN users c ON u.created_by = c.id 
      ORDER BY u.created_at DESC
    `);
    
    // Remove password hashes from response
    const users = result.rows.map(user => {
      const { password_hash, ...userWithoutPassword } = user;
      return userWithoutPassword;
    });
    
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, role, email, full_name } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await query(
      `INSERT INTO users (username, password_hash, role, email, full_name, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [username, hashedPassword, role, email, full_name, req.user.userId]
    );
    
    const newUser = result.rows[0];
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'user', newUser.id, `Created user: ${username} (${role})`);
    
    // Remove password hash from response
    const { password_hash, ...userWithoutPassword } = newUser;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create user' });
    }
  }
});

app.patch('/api/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await query(
      'UPDATE users SET is_active = NOT is_active WHERE id = $1 RETURNING *',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    const action = user.is_active ? 'activated' : 'deactivated';
    
    // Log audit
    await logAudit(req.user.userId, 'UPDATE', 'user', id, `User ${user.username} ${action}`);
    
    res.json({ message: `User ${action} successfully` });
  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Get current user
    const userResult = await query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password
    await query(
      'UPDATE users SET password_hash = $1, password_changed_at = CURRENT_TIMESTAMP WHERE id = $2',
      [hashedNewPassword, req.user.userId]
    );
    
    // Log audit
    await logAudit(req.user.userId, 'UPDATE', 'user', req.user.userId, 'Password changed');
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Audit Log routes (NEW)
app.get('/api/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, user_id, action, entity_type } = req.query;
    const offset = (page - 1) * limit;
    
    let whereClause = '';
    let params = [];
    let paramCount = 0;
    
    if (user_id) {
      paramCount++;
      whereClause += ` AND al.user_id = $${paramCount}`;
      params.push(user_id);
    }
    
    if (action) {
      paramCount++;
      whereClause += ` AND al.action = $${paramCount}`;
      params.push(action);
    }
    
    if (entity_type) {
      paramCount++;
      whereClause += ` AND al.entity_type = $${paramCount}`;
      params.push(entity_type);
    }
    
    params.push(limit, offset);
    
    const result = await query(`
      SELECT al.*, u.username, u.full_name
      FROM audit_log al
      LEFT JOIN users u ON al.user_id = u.id
      WHERE 1=1 ${whereClause}
      ORDER BY al.timestamp DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `, params);
    
    // Get total count
    const countResult = await query(`
      SELECT COUNT(*) as total
      FROM audit_log al
      WHERE 1=1 ${whereClause}
    `, params.slice(0, paramCount));
    
    res.json({
      logs: result.rows,
      total: parseInt(countResult.rows[0].total),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  } catch (error) {
    console.error('Error fetching audit log:', error);
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Database Backup routes (NEW)
app.post('/api/backup/create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { backup_name, notes } = req.body;
    
    // Create backup record
    const result = await query(
      `INSERT INTO database_backups (backup_name, backup_type, created_by, notes) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [backup_name || `backup_${Date.now()}`, 'manual', req.user.userId, notes]
    );
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'backup', result.rows[0].id, `Database backup created: ${backup_name}`);
    
    res.json({
      message: 'Backup created successfully',
      backup: result.rows[0]
    });
  } catch (error) {
    console.error('Error creating backup:', error);
    res.status(500).json({ error: 'Failed to create backup' });
  }
});

app.get('/api/backup/list', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT db.*, u.username as created_by_name
      FROM database_backups db
      LEFT JOIN users u ON db.created_by = u.id
      ORDER BY db.created_at DESC
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching backups:', error);
    res.status(500).json({ error: 'Failed to fetch backups' });
  }
});

// Enhanced existing routes with audit logging

// Customer routes (ENHANCED)
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT c.*, COUNT(o.id) as total_orders, u.username as created_by_name
      FROM customers c 
      LEFT JOIN orders o ON c.id = o.customer_id 
      LEFT JOIN users u ON c.created_by = u.id
      GROUP BY c.id, u.username
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
      `INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, email, company_name, phone, shipping_address, billing_address, notes, req.user.userId]
    );
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'customer', result.rows[0].id, `Created customer: ${name}`);
    
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

// Order routes (ENHANCED)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name,
             COUNT(s.id) as received_samples, u.username as created_by_name
      FROM orders o 
      JOIN customers c ON o.customer_id = c.id 
      LEFT JOIN samples s ON o.id = s.order_id AND s.status != 'pending'
      LEFT JOIN users u ON o.created_by = u.id
      GROUP BY o.id, c.name, c.email, c.company_name, u.username
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
      `INSERT INTO orders (customer_id, order_number, sample_count, shipping_method, priority, notes, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [customer_id, orderNumber, sample_count, shipping_method, priority, notes, req.user.userId]
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
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'order', order.id, `Created order: ${orderNumber} (${sample_count} samples)`);
    
    res.json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Sample routes (ENHANCED)
app.get('/api/samples', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT s.*, o.order_number, c.name as customer_name, c.company_name,
             COUNT(tr.id) as test_count,
             rb.username as received_by_name,
             pb.username as processed_by_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN test_results tr ON s.id = tr.sample_id
      LEFT JOIN users rb ON s.received_by = rb.id
      LEFT JOIN users pb ON s.processed_by = pb.id
      GROUP BY s.id, o.order_number, c.name, c.company_name, rb.username, pb.username
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
       SET status = 'received', received_at = CURRENT_TIMESTAMP, location = $2, notes = $3, received_by = $4
       WHERE barcode = $1 
       RETURNING *`,
      [barcode, location, notes, req.user.userId]
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
    
    // Log audit
    await logAudit(req.user.userId, 'UPDATE', 'sample', result.rows[0].id, `Sample received: ${barcode}`);
    
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
      updateQuery += ', processed_at = CURRENT_TIMESTAMP, processed_by = $2';
      params.push(req.user.userId);
      paramCount = 2;
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
    
    // Log audit
    await logAudit(req.user.userId, 'UPDATE', 'sample', id, `Sample status changed to: ${status}`);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating sample status:', error);
    res.status(500).json({ error: 'Failed to update sample status' });
  }
});

// Batch routes (ENHANCED)
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
        'UPDATE samples SET batch_id = $1, status = $2, processed_by = $3 WHERE id = $4',
        [batchNumber, 'processing', req.user.userId, sampleId]
      );
    }
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'batch', result.rows[0].id, `Created batch: ${batchNumber} (${sample_ids.length} samples)`);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating batch:', error);
    res.status(500).json({ error: 'Failed to create batch' });
  }
});

// Test Results routes (ENHANCED)
app.post('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { test_type, result, value, units, detection_limit, method, notes } = req.body;
    
    const resultData = await query(
      `INSERT INTO test_results (sample_id, test_type, result, value, units, detection_limit, method, analyst_id, notes) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [id, test_type, result, value, units, detection_limit, method, req.user.userId, notes]
    );
    
    // Update sample status to complete
    await query(
      'UPDATE samples SET status = $1, completed_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['complete', id]
    );
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'test_result', resultData.rows[0].id, `Added ${test_type} result: ${result}`);
    
    res.json(resultData.rows[0]);
  } catch (error) {
    console.error('Error adding test result:', error);
    res.status(500).json({ error: 'Failed to add test result' });
  }
});

// Dashboard stats (ENHANCED)
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [orders, samples, batches, users, recentActivity] = await Promise.all([
      query('SELECT status, COUNT(*) as count FROM orders GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM samples GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM batches GROUP BY status'),
      query('SELECT role, COUNT(*) as count FROM users WHERE is_active = true GROUP BY role'),
      query(`
        SELECT al.*, u.username 
        FROM audit_log al 
        LEFT JOIN users u ON al.user_id = u.id 
        ORDER BY al.timestamp DESC 
        LIMIT 10
      `)
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
      complete_batches: 0,
      active_users: 0,
      admin_users: 0,
      technician_users: 0,
      recent_activity: recentActivity.rows
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
    
    users.rows.forEach(row => {
      stats[`${row.role}_users`] = parseInt(row.count);
      stats.active_users += parseInt(row.count);
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
  console.log(`Version: 2.0.0 - Enhanced User Management & Security`);
  
  try {
    await initializeDatabase();
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
});

module.exports = app;