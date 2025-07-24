const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

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

// Email notification functions
const sendResultsReadyEmail = async (customerEmail, customerName, orderNumber, pdfBuffer = null) => {
  try {
    const subject = `3R Testing - Results Ready for Order ${orderNumber}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #059669; color: white; padding: 20px; text-align: center;">
          <h1>3R Testing Laboratory</h1>
          <p>Test Results Ready</p>
        </div>
        
        <div style="padding: 30px; background-color: #f9fafb;">
          <h2>Your Test Results Are Ready!</h2>
          <p>Dear ${customerName},</p>
          
          <div style="background-color: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3>Order: ${orderNumber}</h3>
            <p>We're pleased to inform you that your test results are now available.</p>
            <p>Please find your detailed test report attached to this email.</p>
          </div>
          
          <div style="background-color: #ecfccb; padding: 15px; border-radius: 8px; border-left: 4px solid #65a30d;">
            <p><strong>Next Steps:</strong></p>
            <ul>
              <li>Review your test results in the attached PDF report</li>
              <li>Log into your customer portal to view additional details</li>
              <li>Contact us if you have any questions about your results</li>
            </ul>
          </div>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
            <p style="color: #6b7280; font-size: 14px;">
              Questions about your results? Contact our lab team:<br>
              Email: lab@3rtesting.com<br>
              Phone: (555) 123-4567
            </p>
          </div>
        </div>
      </div>
    `;

    const mailOptions = {
      from: process.env.SMTP_FROM || '"3R Testing Lab" <results@3rtesting.com>',
      to: customerEmail,
      subject: subject,
      html: html
    };

    if (pdfBuffer) {
      mailOptions.attachments = [{
        filename: `3R_Testing_Results_${orderNumber}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf'
      }];
    }

    await emailTransporter.sendMail(mailOptions);
    console.log(`Results email sent to ${customerEmail} for order ${orderNumber}`);
    return true;
  } catch (error) {
    console.error('Results email sending failed:', error);
    return false;
  }
};

// PDF generation function
const generateTestResultsPDF = async (orderData, samplesData, resultsData) => {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument();
      const buffers = [];
      
      doc.on('data', buffers.push.bind(buffers));
      doc.on('end', () => {
        const pdfBuffer = Buffer.concat(buffers);
        resolve(pdfBuffer);
      });

      // Header
      doc.fontSize(20).fillColor('#2563eb').text('3R Testing Laboratory', 50, 50);
      doc.fontSize(12).fillColor('#6b7280').text('Plant Pathology Testing Services', 50, 75);
      doc.fontSize(10).text('123 Lab Street, Science City, SC 12345', 50, 90);
      doc.text('Phone: (555) 123-4567 | Email: lab@3rtesting.com', 50, 105);

      // Line separator
      doc.moveTo(50, 130).lineTo(550, 130).stroke();

      // Report title
      doc.fontSize(16).fillColor('#000').text('TEST RESULTS REPORT', 50, 150);
      
      // Order information
      doc.fontSize(12).text(`Order Number: ${orderData.order_number}`, 50, 180);
      doc.text(`Customer: ${orderData.customer_name}`, 50, 200);
      doc.text(`Company: ${orderData.company_name || 'N/A'}`, 50, 220);
      doc.text(`Report Date: ${new Date().toLocaleDateString()}`, 50, 240);

      // Sample information
      let yPosition = 280;
      doc.fontSize(14).text('SAMPLE RESULTS', 50, yPosition);
      yPosition += 30;

      samplesData.forEach((sample, index) => {
        if (yPosition > 700) {
          doc.addPage();
          yPosition = 50;
        }

        doc.fontSize(12).fillColor('#1f2937').text(`Sample ${index + 1}: ${sample.barcode}`, 50, yPosition);
        yPosition += 20;
        
        doc.fontSize(10).fillColor('#6b7280').text(`Status: ${sample.status}`, 70, yPosition);
        doc.text(`Received: ${sample.received_at ? new Date(sample.received_at).toLocaleDateString() : 'N/A'}`, 70, yPosition + 12);
        doc.text(`Completed: ${sample.completed_at ? new Date(sample.completed_at).toLocaleDateString() : 'N/A'}`, 70, yPosition + 24);
        yPosition += 50;

        // Test results for this sample
        const sampleResults = resultsData.filter(r => r.sample_id === sample.id);
        if (sampleResults.length > 0) {
          doc.fontSize(11).fillColor('#374151').text('Test Results:', 70, yPosition);
          yPosition += 20;

          sampleResults.forEach(result => {
            doc.fontSize(10).fillColor('#000');
            doc.text(`• ${result.test_type}: ${result.result}`, 90, yPosition);
            if (result.value) {
              doc.text(`  Value: ${result.value} ${result.units || ''}`, 90, yPosition + 12);
            }
            if (result.method) {
              doc.text(`  Method: ${result.method}`, 90, yPosition + 24);
            }
            yPosition += 40;
          });
        } else {
          doc.fontSize(10).fillColor('#ef4444').text('No test results available', 70, yPosition);
          yPosition += 20;
        }

        yPosition += 20;
      });

      // Footer
      if (yPosition > 650) {
        doc.addPage();
        yPosition = 50;
      }

      doc.fontSize(8).fillColor('#6b7280').text(
        'This report contains confidential information. Results are valid only for the samples tested.',
        50, yPosition + 50
      );
      
      doc.text(
        `Report generated on ${new Date().toLocaleString()} by 3R Testing Laboratory`,
        50, yPosition + 65
      );

      doc.end();
    } catch (error) {
      reject(error);
    }
  });
};

// Initialize database tables (same as before with migration-safe approach)
async function initializeDatabase() {
  try {
    console.log('Initializing database tables...');
    
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

    // Add new columns to users table if they don't exist
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

    // Create audit log table
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

    // Create other tables
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

    await query(`
      CREATE TABLE IF NOT EXISTS session_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        action VARCHAR(20),
        ip_address VARCHAR(45),
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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

    const customerCreatedByExists = await columnExists('customers', 'created_by');
    if (!customerCreatedByExists) {
      await query('ALTER TABLE customers ADD COLUMN created_by INTEGER REFERENCES users(id)');
      await query('ALTER TABLE customers ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
    }

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

    const orderCreatedByExists = await columnExists('orders', 'created_by');
    if (!orderCreatedByExists) {
      await query('ALTER TABLE orders ADD COLUMN created_by INTEGER REFERENCES users(id)');
    }

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

    const analystIdExists = await columnExists('test_results', 'analyst_id');
    if (!analystIdExists) {
      await query('ALTER TABLE test_results ADD COLUMN analyst_id INTEGER REFERENCES users(id)');
      await query('ALTER TABLE test_results ADD COLUMN reviewed_by INTEGER REFERENCES users(id)');
      await query('ALTER TABLE test_results ADD COLUMN reviewed_at TIMESTAMP');
    }

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

    const testedByExists = await columnExists('quality_control', 'tested_by');
    if (!testedByExists) {
      await query('ALTER TABLE quality_control ADD COLUMN tested_by INTEGER REFERENCES users(id)');
    }

    // Email notifications table
    await query(`
      CREATE TABLE IF NOT EXISTS email_notifications (
        id SERIAL PRIMARY KEY,
        recipient_email VARCHAR(100) NOT NULL,
        recipient_name VARCHAR(100),
        subject VARCHAR(200) NOT NULL,
        order_id INTEGER REFERENCES orders(id),
        notification_type VARCHAR(50),
        status VARCHAR(20) DEFAULT 'pending',
        sent_at TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id)
      )
    `);

    // PDF reports table
    await query(`
      CREATE TABLE IF NOT EXISTS pdf_reports (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        report_type VARCHAR(50) DEFAULT 'test_results',
        filename VARCHAR(200),
        file_size INTEGER,
        generated_by INTEGER REFERENCES users(id),
        generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        download_count INTEGER DEFAULT 0
      )
    `);

    // Customer portal access table
    await query(`
      CREATE TABLE IF NOT EXISTS customer_portal_access (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        access_token VARCHAR(255) UNIQUE,
        expires_at TIMESTAMP,
        last_accessed TIMESTAMP,
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
      await logAudit(adminResult.rows[0].id, 'CREATE', 'user', adminResult.rows[0].id, 'System admin user created');
    } else {
      const fullNameExists = await columnExists('users', 'full_name');
      if (fullNameExists) {
        await query(
          'UPDATE users SET full_name = $1 WHERE username = $2 AND full_name IS NULL',
          ['System Administrator', 'admin']
        );
      }
    }

    const techCheck = await query('SELECT * FROM users WHERE username = $1', ['technician']);
    if (techCheck.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('tech123', 10);
      const techResult = await query(
        'INSERT INTO users (username, password_hash, role, email, full_name, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        ['technician', hashedPassword, 'technician', 'tech@3rtesting.com', 'Lab Technician', 1]
      );
      console.log('Default technician user created');
    } else {
      const fullNameExists = await columnExists('users', 'full_name');
      if (fullNameExists) {
        await query(
          'UPDATE users SET full_name = $1 WHERE username = $2 AND full_name IS NULL',
          ['Lab Technician', 'technician']
        );
      }
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
    version: '2.1.0 - Communication & Notifications',
    features: ['email_notifications', 'pdf_reports', 'customer_portal']
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
    
    const isActiveExists = await columnExists('users', 'is_active');
    if (isActiveExists && user.is_active === false) {
      return res.status(401).json({ error: 'Account is disabled' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const lastLoginExists = await columnExists('users', 'last_login');
    if (lastLoginExists) {
      await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    }
    
    const sessionTableExists = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'session_log'
      );
    `);
    
    if (sessionTableExists.rows[0].exists) {
      await query(
        'INSERT INTO session_log (user_id, action, ip_address) VALUES ($1, $2, $3)',
        [user.id, 'login', req.ip || 'unknown']
      );
    }
    
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
        full_name: user.full_name || user.username
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const sessionTableExists = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'session_log'
      );
    `);
    
    if (sessionTableExists.rows[0].exists) {
      await query(
        'INSERT INTO session_log (user_id, action, ip_address) VALUES ($1, $2, $3)',
        [req.user.userId, 'logout', req.ip || 'unknown']
      );
    }
    
    await logAudit(req.user.userId, 'LOGOUT', 'session', null, `User ${req.user.username} logged out`);
    
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// User Management routes
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    let userQuery = 'SELECT u.* FROM users u ORDER BY u.created_at DESC';
    let queryParams = [];
    
    const createdByExists = await columnExists('users', 'created_by');
    if (createdByExists) {
      userQuery = `
        SELECT u.*, c.username as created_by_name 
        FROM users u 
        LEFT JOIN users c ON u.created_by = c.id 
        ORDER BY u.created_at DESC
      `;
    }
    
    const result = await query(userQuery, queryParams);
    
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
    
    if (!username || !password || !role || !email) {
      return res.status(400).json({ error: 'Username, password, role, and email are required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const fullNameExists = await columnExists('users', 'full_name');
    const createdByExists = await columnExists('users', 'created_by');
    
    let insertQuery = 'INSERT INTO users (username, password_hash, role, email';
    let values = [username, hashedPassword, role, email];
    let paramCount = 4;
    
    if (fullNameExists) {
      insertQuery += ', full_name';
      values.push(full_name || username);
      paramCount++;
    }
    
    if (createdByExists) {
      insertQuery += ', created_by';
      values.push(req.user.userId);
      paramCount++;
    }
    
    insertQuery += ') VALUES (';
    for (let i = 1; i <= paramCount; i++) {
      insertQuery += '$' + i + (i < paramCount ? ', ' : '');
    }
    insertQuery += ') RETURNING *';
    
    const result = await query(insertQuery, values);
    const newUser = result.rows[0];
    
    await logAudit(req.user.userId, 'CREATE', 'user', newUser.id, `Created user: ${username} (${role})`);
    
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
    
    const isActiveExists = await columnExists('users', 'is_active');
    if (!isActiveExists) {
      return res.status(400).json({ error: 'User activation not supported in current database version' });
    }
    
    const result = await query(
      'UPDATE users SET is_active = NOT is_active WHERE id = $1 RETURNING *',
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    const action = user.is_active ? 'activated' : 'deactivated';
    
    await logAudit(req.user.userId, 'UPDATE', 'user', id, `User ${user.username} ${action}`);
    
    res.json({ message: `User ${action} successfully` });
  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// NEW: Delete user permanently (admin only)
app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Prevent admin from deleting themselves
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    // Get user info before deletion for audit log
    const userResult = await query('SELECT * FROM users WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userToDelete = userResult.rows[0];
    
    // Delete the user
    await query('DELETE FROM users WHERE id = $1', [id]);
    
    // Log audit
    await logAudit(req.user.userId, 'DELETE', 'user', id, `Permanently deleted user: ${userToDelete.username}`);
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    
    const userResult = await query('SELECT * FROM users WHERE id = $1', [req.user.userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    
    const passwordChangedExists = await columnExists('users', 'password_changed_at');
    let updateQuery = 'UPDATE users SET password_hash = $1';
    const params = [hashedNewPassword];
    
    if (passwordChangedExists) {
      updateQuery += ', password_changed_at = CURRENT_TIMESTAMP';
    }
    
    updateQuery += ' WHERE id = $2';
    params.push(req.user.userId);
    
    await query(updateQuery, params);
    
    await logAudit(req.user.userId, 'UPDATE', 'user', req.user.userId, 'Password changed');
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Audit Log routes
app.get('/api/audit-log', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const tableExists = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'audit_log'
      );
    `);
    
    if (!tableExists.rows[0].exists) {
      return res.json({ logs: [], total: 0, page: 1, limit: 50 });
    }
    
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

// Database Backup routes
app.post('/api/backup/create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { backup_name, notes } = req.body;
    
    const tableExists = await query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'database_backups'
      );
    `);
    
    if (!tableExists.rows[0].exists) {
      return res.status(400).json({ error: 'Backup functionality not available' });
    }
    
    const result = await query(
      `INSERT INTO database_backups (backup_name, backup_type, created_by, notes) 
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [backup_name || `backup_${Date.now()}`, 'manual', req.user.userId, notes]
    );
    
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

// Customer routes
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const createdByExists = await columnExists('customers', 'created_by');
    
    let customerQuery = `
      SELECT c.*, COUNT(o.id) as total_orders
      FROM customers c 
      LEFT JOIN orders o ON c.id = o.customer_id 
      GROUP BY c.id 
      ORDER BY c.created_at DESC
    `;
    
    if (createdByExists) {
      customerQuery = `
        SELECT c.*, COUNT(o.id) as total_orders, u.username as created_by_name
        FROM customers c 
        LEFT JOIN orders o ON c.id = o.customer_id 
        LEFT JOIN users u ON c.created_by = u.id
        GROUP BY c.id, u.username
        ORDER BY c.created_at DESC
      `;
    }
    
    const result = await query(customerQuery);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
  try {
    const { name, email, company_name, phone, shipping_address, billing_address, notes } = req.body;
    
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    const createdByExists = await columnExists('customers', 'created_by');
    
    let insertQuery = `
      INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes
    `;
    let values = [name, email, company_name, phone, shipping_address, billing_address, notes];
    let paramCount = 7;
    
    if (createdByExists) {
      insertQuery += ', created_by';
      values.push(req.user.userId);
      paramCount++;
    }
    
    insertQuery += ') VALUES (';
    for (let i = 1; i <= paramCount; i++) {
      insertQuery += '$' + i + (i < paramCount ? ', ' : '');
    }
    insertQuery += ') RETURNING *';
    
    const result = await query(insertQuery, values);
    
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

// Order routes (UPDATED - No email notifications)
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
    
    if (!customer_id || !sample_count) {
      return res.status(400).json({ error: 'Customer ID and sample count are required' });
    }

    // Generate order number
    const orderNumber = 'ORD-' + Date.now();
    
    const result = await query(
      `INSERT INTO orders (customer_id, order_number, sample_count, shipping_method, priority, notes, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [customer_id, orderNumber, sample_count, shipping_method, priority, notes, req.user.userId]
    );
    
    // Generate sample barcodes for this order (placeholder - will be assigned later)
    const order = result.rows[0];
    for (let i = 1; i <= sample_count; i++) {
      const barcode = `${orderNumber}-S${i.toString().padStart(2, '0')}`;
      await query(
        'INSERT INTO samples (order_id, barcode) VALUES ($1, $2)',
        [order.id, barcode]
      );
    }
    
    // Log audit (NO EMAIL NOTIFICATION)
    await logAudit(req.user.userId, 'CREATE', 'order', order.id, `Created order: ${orderNumber} (${sample_count} samples)`);
    
    res.json(order);
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// NEW: Assign barcodes to an order
app.post('/api/orders/:id/assign-barcodes', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { barcodes } = req.body;
    
    if (!barcodes || !Array.isArray(barcodes)) {
      return res.status(400).json({ error: 'Barcodes array is required' });
    }
    
    // Get order info
    const orderResult = await query('SELECT * FROM orders WHERE id = $1', [id]);
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const order = orderResult.rows[0];
    
    // Validate barcode count matches sample count
    if (barcodes.length !== order.sample_count) {
      return res.status(400).json({ 
        error: `Expected ${order.sample_count} barcodes, received ${barcodes.length}` 
      });
    }
    
    // Check for duplicate barcodes in database
    const existingBarcodes = await query(
      'SELECT barcode FROM samples WHERE barcode = ANY($1)',
      [barcodes]
    );
    
    if (existingBarcodes.rows.length > 0) {
      const duplicates = existingBarcodes.rows.map(row => row.barcode);
      return res.status(400).json({ 
        error: `Barcodes already exist: ${duplicates.join(', ')}` 
      });
    }
    
    // Delete existing samples for this order (if any)
    await query('DELETE FROM samples WHERE order_id = $1', [id]);
    
    // Create new samples with the provided barcodes
    for (const barcode of barcodes) {
      await query(
        'INSERT INTO samples (order_id, barcode, status) VALUES ($1, $2, $3)',
        [id, barcode, 'pending']
      );
    }
    
    // Log audit
    await logAudit(
      req.user.userId, 
      'UPDATE', 
      'order', 
      id, 
      `Assigned ${barcodes.length} barcodes to order ${order.order_number}`
    );
    
    res.json({ 
      message: 'Barcodes assigned successfully',
      assigned_count: barcodes.length 
    });
  } catch (error) {
    console.error('Error assigning barcodes:', error);
    res.status(500).json({ error: 'Failed to assign barcodes' });
  }
});

// Sample routes (UPDATED - No email notifications except for test results)
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
    
    if (!barcode) {
      return res.status(400).json({ error: 'Barcode is required' });
    }
    
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
      SELECT s.*, o.order_number, o.id as order_id, c.name as customer_name, c.email as customer_email
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE s.id = $1
    `, [result.rows[0].id]);

    // Log audit (NO EMAIL NOTIFICATION)
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
    
    if (!status) {
      return res.status(400).json({ error: 'Status is required' });
    }
    
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
    
    // Log audit (NO EMAIL NOTIFICATION)
    await logAudit(req.user.userId, 'UPDATE', 'sample', id, `Sample status changed to: ${status}`);
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating sample status:', error);
    res.status(500).json({ error: 'Failed to update sample status' });
  }
});

// Batch routes
app.get('/api/batches', authenticateToken, async (req, res) => {
  try {
    const result = await query(`
      SELECT b.*, u.username as created_by_name,
             COUNT(s.id) as actual_sample_count
      FROM batches b
      LEFT JOIN users u ON b.created_by = u.id
      LEFT JOIN samples s ON s.batch_id = b.batch_number
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
    
    if (!test_type || !sample_ids || sample_ids.length === 0) {
      return res.status(400).json({ error: 'Test type and sample IDs are required' });
    }
    
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

// Test Results routes (KEEP EMAIL FUNCTIONALITY - This is where PDF is generated)
app.post('/api/samples/:id/results', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { test_type, result, value, units, detection_limit, method, notes } = req.body;
    
    if (!test_type || !result) {
      return res.status(400).json({ error: 'Test type and result are required' });
    }
    
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

    // Get order and customer info
    const orderInfo = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      JOIN customers c ON o.customer_id = c.id
      WHERE s.id = $1
    `, [id]);

    if (orderInfo.rows.length > 0) {
      const order = orderInfo.rows[0];
      
      // Check if all samples in this order are complete
      const incompleteSamples = await query(
        'SELECT COUNT(*) as count FROM samples WHERE order_id = $1 AND status != $2',
        [order.id, 'complete']
      );

      if (incompleteSamples.rows[0].count === '0') {
        // All samples complete - generate PDF and send results email
        try {
          const samplesData = await query(
            'SELECT * FROM samples WHERE order_id = $1 ORDER BY barcode',
            [order.id]
          );
          
          const resultsData = await query(`
            SELECT tr.* FROM test_results tr
            JOIN samples s ON tr.sample_id = s.id
            WHERE s.order_id = $1
            ORDER BY s.barcode, tr.test_type
          `, [order.id]);

          const pdfBuffer = await generateTestResultsPDF(order, samplesData.rows, resultsData.rows);
          
          // Save PDF record
          const pdfRecord = await query(
            'INSERT INTO pdf_reports (order_id, report_type, filename, file_size, generated_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [order.id, 'test_results', `3R_Testing_Results_${order.order_number}.pdf`, pdfBuffer.length, req.user.userId]
          );

          // Send results email with PDF attachment
          const emailSent = await sendResultsReadyEmail(
            order.customer_email,
            order.customer_name,
            order.order_number,
            pdfBuffer
          );

          // Log email notification
          await query(
            `INSERT INTO email_notifications (recipient_email, recipient_name, subject, order_id, notification_type, status, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
              order.customer_email,
              order.customer_name,
              `3R Testing - Results Ready for Order ${order.order_number}`,
              order.id,
              'results_ready',
              emailSent ? 'sent' : 'failed',
              req.user.userId
            ]
          );

          // Update order status to complete
          await query('UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', ['complete', order.id]);
          
        } catch (pdfError) {
          console.error('PDF generation failed:', pdfError);
          // Continue without PDF/email
        }
      }
    }
    
    // Log audit
    await logAudit(req.user.userId, 'CREATE', 'test_result', resultData.rows[0].id, `Added ${test_type} result: ${result}`);
    
    res.json(resultData.rows[0]);
  } catch (error) {
    console.error('Error adding test result:', error);
    res.status(500).json({ error: 'Failed to add test result' });
  }
});

// Download PDF report
app.get('/api/orders/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get order info
    const orderInfo = await query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [id]);

    if (orderInfo.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orderInfo.rows[0];

    // Get samples and results
    const samplesData = await query(
      'SELECT * FROM samples WHERE order_id = $1 ORDER BY barcode',
      [id]
    );
    
    const resultsData = await query(`
      SELECT tr.* FROM test_results tr
      JOIN samples s ON tr.sample_id = s.id
      WHERE s.order_id = $1
      ORDER BY s.barcode, tr.test_type
    `, [id]);

    // Generate PDF
    const pdfBuffer = await generateTestResultsPDF(order, samplesData.rows, resultsData.rows);
    
    // Update download count
    await query(
      'UPDATE pdf_reports SET download_count = download_count + 1 WHERE order_id = $1',
      [id]
    );

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="3R_Testing_Results_${order.order_number}.pdf"`);
    res.send(pdfBuffer);
    
  } catch (error) {
    console.error('Error generating PDF:', error);
    res.status(500).json({ error: 'Failed to generate PDF report' });
  }
});

// Email notifications history
app.get('/api/notifications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(`
      SELECT en.*, o.order_number, u.username as sent_by
      FROM email_notifications en
      LEFT JOIN orders o ON en.order_id = o.id
      LEFT JOIN users u ON en.created_by = u.id
      ORDER BY en.created_at DESC
      LIMIT 100
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Resend notification
app.post('/api/notifications/:id/resend', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const notification = await query(
      'SELECT * FROM email_notifications WHERE id = $1',
      [id]
    );
    
    if (notification.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    const notif = notification.rows[0];
    
    // Get order info if needed
    let emailSent = false;
    if (notif.order_id) {
      const orderInfo = await query(`
        SELECT o.*, c.name as customer_name
        FROM orders o
        JOIN customers c ON o.customer_id = c.id
        WHERE o.id = $1
      `, [notif.order_id]);
      
      if (orderInfo.rows.length > 0) {
        const order = orderInfo.rows[0];
        
        // For results_ready notifications, need to regenerate PDF
        if (notif.notification_type === 'results_ready') {
          try {
            const samplesData = await query(
              'SELECT * FROM samples WHERE order_id = $1 ORDER BY barcode',
              [order.id]
            );
            
            const resultsData = await query(`
              SELECT tr.* FROM test_results tr
              JOIN samples s ON tr.sample_id = s.id
              WHERE s.order_id = $1
              ORDER BY s.barcode, tr.test_type
            `, [order.id]);

            const pdfBuffer = await generateTestResultsPDF(order, samplesData.rows, resultsData.rows);
            
            emailSent = await sendResultsReadyEmail(
              notif.recipient_email,
              notif.recipient_name,
              order.order_number,
              pdfBuffer
            );
          } catch (pdfError) {
            console.error('PDF regeneration failed:', pdfError);
            emailSent = false;
          }
        }
      }
    }

    // Update notification status
    await query(
      'UPDATE email_notifications SET status = $1, sent_at = CURRENT_TIMESTAMP WHERE id = $2',
      [emailSent ? 'sent' : 'failed', id]
    );

    res.json({ message: emailSent ? 'Notification resent successfully' : 'Failed to resend notification' });
  } catch (error) {
    console.error('Error resending notification:', error);
    res.status(500).json({ error: 'Failed to resend notification' });
  }
});

// Dashboard stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [orders, samples, batches, users, recentActivity] = await Promise.all([
      query('SELECT status, COUNT(*) as count FROM orders GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM samples GROUP BY status'),
      query('SELECT status, COUNT(*) as count FROM batches GROUP BY status'),
      query(`
        SELECT role, COUNT(*) as count 
        FROM users 
        WHERE ${await columnExists('users', 'is_active') ? 'is_active = true' : '1=1'}
        GROUP BY role
      `),
      query(`
        SELECT al.*, u.username 
        FROM audit_log al 
        LEFT JOIN users u ON al.user_id = u.id 
        ORDER BY al.timestamp DESC 
        LIMIT 10
      `).catch(() => ({ rows: [] })) // Handle case where audit_log doesn't exist
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