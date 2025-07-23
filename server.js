// server.js - Main Express server
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'lims_3r_testing',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// Test database connection
pool.getConnection()
  .then(connection => {
    console.log('✅ Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err);
    process.exit(1);
  });

// Middleware to verify JWT token
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

// =====================
// CUSTOMERS API ROUTES
// =====================

// Get all customers
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT c.*, 
             COUNT(o.id) as total_orders,
             MAX(o.created_at) as last_order_date
      FROM customers c 
      LEFT JOIN orders o ON c.id = o.customer_id 
      GROUP BY c.id 
      ORDER BY c.created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Create new customer
app.post('/api/customers', authenticateToken, async (req, res) => {
  const {
    name, email, company_name, phone, 
    shipping_address, billing_address, notes
  } = req.body;

  try {
    // Check for duplicate customer
    const [existing] = await pool.execute(
      'SELECT id, name, email, company_name FROM customers WHERE email = ? OR company_name = ?',
      [email, company_name]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        error: 'Customer already exists',
        existing_customer: existing[0]
      });
    }

    const [result] = await pool.execute(`
      INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [name, email, company_name, phone, shipping_address, billing_address, notes]);

    res.status(201).json({
      id: result.insertId,
      message: 'Customer created successfully'
    });
  } catch (error) {
    console.error('Error creating customer:', error);
    res.status(500).json({ error: 'Failed to create customer' });
  }
});

// ==================
// ORDERS API ROUTES
// ==================

// Get all orders with customer information
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.execute(`
      SELECT o.*, c.name as customer_name, c.email as customer_email, c.company_name,
             COUNT(s.id) as total_samples,
             COUNT(CASE WHEN s.status = 'received' THEN 1 END) as received_samples
      FROM orders o 
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN samples s ON o.id = s.order_id
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `);
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Create new order (manual or from WooCommerce)
app.post('/api/orders', authenticateToken, async (req, res) => {
  const {
    customer_id, woocommerce_order_id, sample_count, 
    shipping_method, notes, source = 'manual'
  } = req.body;

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Create order
      const [orderResult] = await connection.execute(`
        INSERT INTO orders (customer_id, woocommerce_order_id, sample_count, 
                           status, shipping_method, notes, source)
        VALUES (?, ?, ?, 'pending', ?, ?, ?)
      `, [customer_id, woocommerce_order_id, sample_count, shipping_method, notes, source]);

      const orderId = orderResult.insertId;

      // Generate order number (format: year + sequential number)
      const year = new Date().getFullYear();
      const orderNumber = `${year}${orderId.toString().padStart(4, '0')}`;
      
      await connection.execute(
        'UPDATE orders SET order_number = ? WHERE id = ?',
        [orderNumber, orderId]
      );

      await connection.commit();
      connection.release();

      res.status(201).json({
        id: orderId,
        order_number: orderNumber,
        message: 'Order created successfully'
      });
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Update order status
app.patch('/api/orders/:id/status', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, tracking_number, notes } = req.body;

  try {
    const updateFields = ['status = ?'];
    const values = [status];

    if (tracking_number) {
      updateFields.push('tracking_number = ?');
      values.push(tracking_number);
    }

    if (status === 'shipped') {
      updateFields.push('shipped_at = NOW()');
    } else if (status === 'received_customer') {
      updateFields.push('delivered_at = NOW()');
    } else if (status === 'processing') {
      updateFields.push('received_at = NOW()');
    } else if (status === 'complete') {
      updateFields.push('completed_at = NOW()');
    }

    values.push(id);

    await pool.execute(`
      UPDATE orders SET ${updateFields.join(', ')} WHERE id = ?
    `, values);

    // Log status change
    await pool.execute(`
      INSERT INTO order_status_log (order_id, old_status, new_status, notes, changed_by)
      VALUES (?, (SELECT status FROM orders WHERE id = ? LIMIT 1), ?, ?, ?)
    `, [id, id, status, notes, req.user.id]);

    res.json({ message: 'Order status updated successfully' });
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// ===================
// SAMPLES API ROUTES
// ===================

// Assign barcode to order
app.post('/api/orders/:orderId/samples', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { barcodes } = req.body; // Array of barcode strings

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      for (const barcode of barcodes) {
        // Check if barcode already exists
        const [existing] = await connection.execute(
          'SELECT id FROM samples WHERE barcode = ?',
          [barcode]
        );

        if (existing.length > 0) {
          throw new Error(`Barcode ${barcode} already assigned`);
        }

        // Insert sample
        await connection.execute(`
          INSERT INTO samples (order_id, barcode, status, created_by)
          VALUES (?, ?, 'assigned', ?)
        `, [orderId, barcode, req.user.id]);
      }

      await connection.commit();
      connection.release();

      res.json({ message: 'Barcodes assigned successfully' });
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error assigning barcodes:', error);
    res.status(500).json({ error: error.message || 'Failed to assign barcodes' });
  }
});

// Receive sample by barcode scan
app.post('/api/samples/receive', authenticateToken, async (req, res) => {
  const { barcode } = req.body;

  try {
    const [samples] = await pool.execute(`
      SELECT s.*, o.order_number, o.customer_id, c.name as customer_name
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
    await pool.execute(
      'UPDATE samples SET status = ?, received_at = NOW() WHERE barcode = ?',
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

// Generate Excel export for batch processing
app.get('/api/samples/export/:orderId', authenticateToken, async (req, res) => {
  const { orderId } = req.params;

  try {
    const [samples] = await pool.execute(`
      SELECT s.barcode, s.status, o.order_number
      FROM samples s
      JOIN orders o ON s.order_id = o.id
      WHERE s.order_id = ? AND s.status = 'received'
      ORDER BY s.created_at
      LIMIT 92
    `, [orderId]);

    // Generate Excel-compatible data structure
    const excelData = samples.map((sample, index) => ({
      well_position: `${String.fromCharCode(65 + Math.floor(index / 12))}${(index % 12) + 1}`,
      barcode: sample.barcode,
      order_number: sample.order_number,
      sample_id: sample.barcode
    }));

    res.json({
      data: excelData,
      total_samples: samples.length,
      max_samples: 92
    });
  } catch (error) {
    console.error('Error generating export:', error);
    res.status(500).json({ error: 'Failed to generate export' });
  }
});

// ==================
// RESULTS API ROUTES
// ==================

// Upload results file
app.post('/api/orders/:orderId/results', authenticateToken, upload.single('results'), async (req, res) => {
  const { orderId } = req.params;
  const { notes, version } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const [result] = await pool.execute(`
      INSERT INTO results (order_id, file_path, file_name, file_size, 
                          version, notes, uploaded_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      orderId, 
      req.file.path, 
      req.file.originalname, 
      req.file.size,
      version || 1,
      notes,
      req.user.id
    ]);

    // Update order status to results_pending
    await pool.execute(
      'UPDATE orders SET status = ? WHERE id = ?',
      ['results_pending', orderId]
    );

    res.json({
      id: result.insertId,
      message: 'Results uploaded successfully'
    });
  } catch (error) {
    console.error('Error uploading results:', error);
    res.status(500).json({ error: 'Failed to upload results' });
  }
});

// Send results via email
app.post('/api/orders/:orderId/send-results', authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { email_message, send_sms } = req.body;

  try {
    // Get order and customer details
    const [orders] = await pool.execute(`
      SELECT o.*, c.name, c.email, c.phone, r.file_path, r.file_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      LEFT JOIN results r ON o.id = r.order_id
      WHERE o.id = ?
      ORDER BY r.version DESC
      LIMIT 1
    `, [orderId]);

    if (orders.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orders[0];

    // TODO: Implement actual email sending (see email integration section)
    console.log(`Sending results email to: ${order.email}`);
    console.log(`Message: ${email_message}`);

    if (send_sms && order.phone) {
      // TODO: Implement SMS sending
      console.log(`Sending SMS notification to: ${order.phone}`);
    }

    // Log email sent
    await pool.execute(`
      INSERT INTO email_log (order_id, recipient_email, subject, message, sent_by)
      VALUES (?, ?, ?, ?, ?)
    `, [orderId, order.email, `Test Results - Order ${order.order_number}`, email_message, req.user.id]);

    // Update order status to complete
    await pool.execute(
      'UPDATE orders SET status = ?, completed_at = NOW() WHERE id = ?',
      ['complete', orderId]
    );

    res.json({ message: 'Results sent successfully' });
  } catch (error) {
    console.error('Error sending results:', error);
    res.status(500).json({ error: 'Failed to send results' });
  }
});

// ==========================
// WOOCOMMERCE WEBHOOK ROUTE
// ==========================

app.post('/api/webhooks/woocommerce', async (req, res) => {
  try {
    const orderData = req.body;
    
    // Verify webhook signature (implement based on WooCommerce settings)
    // const signature = req.headers['x-wc-webhook-signature'];
    
    console.log('Received WooCommerce webhook:', orderData.id);

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // Create or find customer
      let customerId;
      const [existingCustomer] = await connection.execute(
        'SELECT id FROM customers WHERE email = ?',
        [orderData.billing.email]
      );

      if (existingCustomer.length > 0) {
        customerId = existingCustomer[0].id;
      } else {
        const [customerResult] = await connection.execute(`
          INSERT INTO customers (name, email, company_name, phone, shipping_address, billing_address)
          VALUES (?, ?, ?, ?, ?, ?)
        `, [
          `${orderData.billing.first_name} ${orderData.billing.last_name}`,
          orderData.billing.email,
          orderData.billing.company || '',
          orderData.billing.phone || '',
          `${orderData.shipping.address_1} ${orderData.shipping.address_2}, ${orderData.shipping.city}, ${orderData.shipping.state} ${orderData.shipping.postcode}`,
          `${orderData.billing.address_1} ${orderData.billing.address_2}, ${orderData.billing.city}, ${orderData.billing.state} ${orderData.billing.postcode}`
        ]);
        customerId = customerResult.insertId;
      }

      // Calculate total sample count from line items
      const sampleCount = orderData.line_items.reduce((total, item) => {
        return total + item.quantity;
      }, 0);

      // Create order
      const [orderResult] = await connection.execute(`
        INSERT INTO orders (customer_id, woocommerce_order_id, sample_count, status, source)
        VALUES (?, ?, ?, 'pending', 'woocommerce')
      `, [customerId, orderData.id, sampleCount]);

      const orderId = orderResult.insertId;
      const year = new Date().getFullYear();
      const orderNumber = `${year}${orderId.toString().padStart(4, '0')}`;
      
      await connection.execute(
        'UPDATE orders SET order_number = ? WHERE id = ?',
        [orderNumber, orderId]
      );

      await connection.commit();
      connection.release();

      res.json({ message: 'Order created from WooCommerce', order_id: orderId });
    } catch (error) {
      await connection.rollback();
      connection.release();
      throw error;
    }
  } catch (error) {
    console.error('Error processing WooCommerce webhook:', error);
    res.status(500).json({ error: 'Failed to process webhook' });
  }
});

// ===============
// UTILITY ROUTES
// ===============

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Get dashboard statistics
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [stats] = await pool.execute(`
      SELECT 
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_orders,
        COUNT(CASE WHEN status = 'shipped' THEN 1 END) as shipped_orders,
        COUNT(CASE WHEN status = 'processing' THEN 1 END) as processing_orders,
        COUNT(CASE WHEN status = 'complete' THEN 1 END) as complete_orders,
        COUNT(*) as total_orders
      FROM orders
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    `);

    res.json(stats[0]);
  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 3R Testing LIMS Server running on port ${PORT}`);
});

module.exports = app;