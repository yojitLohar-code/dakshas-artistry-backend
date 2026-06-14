const express = require('express');
const cors = require('cors');
const pool = require('./db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
const nodemailer = require('nodemailer'); // 🔥 NEW: Email Engine
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET; 

// ─────────────────────────────────────────
//  EMAIL CONFIGURATION (NODEMAILER)
// ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Temporary memory vault to hold OTPs for 10 minutes
const otpStore = new Map();

// 🛡️ AUTHENTICATION BOUNCER
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access Denied. Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session.' });
    req.user = user; 
    next();
  });
}
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const [existing] = await pool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({
        error: 'Email already registered.'
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await pool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    res.status(201).json({
      message: 'Account created successfully.'
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: 'Account creation failed.'
    });
  }
});
// ─────────────────────────────────────────
//  CUSTOMER SECURITY: OTP SIGNUP & LOGIN
// ─────────────────────────────────────────

// STEP 1: SEND THE OTP
app.post('/api/auth/signup/send-otp', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) return res.status(400).json({ error: 'Email already registered.' });

    // Generate a secure 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Lock the data in our memory vault (expires in 10 mins)
    otpStore.set(email, {
      otp,
      name,
      password,
      expiresAt: Date.now() + 10 * 60 * 1000 
    });

    // Send the Email
    const mailOptions = {
      from: '"Daksha\'s Artistry" <28@gmail.com>', // ⚠️ CHANGE THIS to your studio's gmail
      to: email,
      subject: 'Verify your Daksha\'s Artistry Account',
      html: `
        <div style="font-family: sans-serif; text-align: center; padding: 40px; background-color: #F6F0E8; color: #4B302A;">
           <h2 style="margin-bottom: 20px;">Welcome to Daksha's Artistry!</h2>
           <p style="font-size: 16px;">To complete your registration, please use the verification code below:</p>
           <h1 style="font-size: 40px; letter-spacing: 8px; color: #C6A27A; background: #fff; padding: 20px; border-radius: 12px; display: inline-block;">${otp}</h1>
           <p style="font-size: 14px; margin-top: 20px; opacity: 0.7;">This code expires in 10 minutes. Do not share it with anyone.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Verification code sent to your email.' });

  } catch (err) {
    console.error("Email Error:", err);
    res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
  }
});

// STEP 2: VERIFY OTP & CREATE ACCOUNT
app.post('/api/auth/signup/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    // Fetch their data from the vault
    const storedData = otpStore.get(email);

    if (!storedData) return res.status(400).json({ error: 'OTP not found. Please request a new one.' });
    if (Date.now() > storedData.expiresAt) {
        otpStore.delete(email);
        return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }
    if (storedData.otp !== otp) return res.status(400).json({ error: 'Incorrect verification code.' });

    // The code matches! Hash the password and officially create the account in MySQL
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(storedData.password, salt);

    await pool.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [storedData.name, email, hashedPassword]);

    // Delete the OTP from memory so it can't be reused
    otpStore.delete(email);

    res.status(201).json({ message: 'Account successfully verified and created!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Account creation failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Admin bypass
    if (email === 'yojit@admin.com' && password === 'admin123') {
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
      return res.json({ token, role: 'admin', name: 'Yojit' });
    }

    const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (user.length === 0) return res.status(401).json({ error: 'Invalid email or password.' });

    const validPassword = await bcrypt.compare(password, user[0].password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: user[0].id, role: user[0].role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user[0].role, name: user[0].name });
  } catch (err) {
    res.status(500).json({ error: 'Login verification engine error.' });
  }
});

// ─────────────────────────────────────────
//  PUBLIC PRODUCTS & REVIEWS ROUTES
// ─────────────────────────────────────────

// 1. GET ALL PRODUCTS
app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT p.*, 
                   COALESCE(AVG(r.rating), 5.0) AS rating, 
                   COUNT(r.id) AS reviews 
            FROM products p 
            LEFT JOIN reviews r ON p.id = r.product_id 
            GROUP BY p.id
        `);
        res.json(rows);
    } catch (err) {
        console.error("Database fetch error:", err);
        res.status(500).json({ error: 'Failed to retrieve products.' });
    }
});

// 2. GET A SINGLE PRODUCT + ITS REVIEWS
app.get('/api/products/:id', async (req, res) => {
    try {
        const [prodRows] = await pool.query(`
            SELECT p.*, 
                   COALESCE(AVG(r.rating), 5.0) AS rating, 
                   COUNT(r.id) AS reviews 
            FROM products p 
            LEFT JOIN reviews r ON p.id = r.product_id 
            WHERE p.id = ? 
            GROUP BY p.id
        `, [req.params.id]);
        
        if (prodRows.length === 0) return res.status(404).json({ error: 'Product not found' });
        
        const [reviewRows] = await pool.query(`
            SELECT r.rating, r.comment, r.created_at, u.name AS user_name 
            FROM reviews r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.product_id = ? 
            ORDER BY r.created_at DESC
        `, [req.params.id]);

        const productData = prodRows[0];
        productData.reviewList = reviewRows; 
        
        res.json(productData);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to retrieve product details.' });
    }
});

// 3. POST A NEW REVIEW
app.post('/api/products/:id/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const productId = req.params.id;
        const userId = req.user.id;

        if (!rating || rating < 1 || rating > 5) {
            return res.status(400).json({ error: 'Valid rating (1-5) is required.' });
        }

        await pool.query(
            `INSERT INTO reviews (product_id, user_id, rating, comment) 
             VALUES (?, ?, ?, ?) 
             ON DUPLICATE KEY UPDATE rating = ?, comment = ?`,
            [productId, userId, rating, comment, rating, comment]
        );

        res.status(201).json({ message: 'Review published!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to submit review.' });
    }
});

// ─────────────────────────────────────────
//  SECURED ADMINISTRATIVE ROUTES (INVENTORY)
// ─────────────────────────────────────────

app.post('/api/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    
    try {
        const { name, category, price, oldPrice, badge, finish, occasion, shape, img, itemsIncluded, description, perfectFor } = req.body;
        
        await pool.query(
            `INSERT INTO products (name, category, price, old_price, badge, finish, occasion, shape, img, items_included, description, perfect_for) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, category, price, oldPrice, badge, finish, occasion, shape, img, itemsIncluded, description, perfectFor]
        );
        res.status(201).json({ message: 'Product successfully added.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add product.' });
    }
});

app.put('/api/products/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    
    try {
        const { name, category, price, oldPrice, badge, finish, occasion, shape, img, itemsIncluded, description, perfectFor } = req.body;
        
        await pool.query(
            `UPDATE products 
             SET name=?, category=?, price=?, old_price=?, badge=?, finish=?, occasion=?, shape=?, img=?, items_included=?, description=?, perfect_for=? 
             WHERE id=?`,
            [name, category, price, oldPrice, badge, finish, occasion, shape, img, itemsIncluded, description, perfectFor, req.params.id]
        );
        res.json({ message: 'Product successfully updated.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update product.' });
    }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    
    try {
        await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
        res.json({ message: 'Product permanently deleted.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete product.' });
    }
});

// ─────────────────────────────────────────
//  LIVE PERSISTENT DATABASE CART ROUTES 
// ─────────────────────────────────────────
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const [cartItems] = await pool.query(
      `SELECT c.product_id AS id, p.name, p.price, p.img, p.shape, c.qty 
       FROM cart_items c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?`,
      [req.user.id]
    );
    res.json(cartItems);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve cloud cart data.' });
  }
});

app.post('/api/cart', authenticateToken, async (req, res) => {
  try {
    const { product_id, qty } = req.body;
    await pool.query(
      `INSERT INTO cart_items (user_id, product_id, qty) VALUES (?, ?, ?) 
       ON DUPLICATE KEY UPDATE qty = qty + ?`,
      [req.user.id, product_id, qty, qty]
    );
    res.json({ message: 'Cart database synchronized seamlessly.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to sync bag state.' });
  }
});

app.delete('/api/cart/:productId', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
    res.json({ message: 'Item permanently cleared from cloud storage.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete item from database.' });
  }
});

app.delete('/api/cart', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM cart_items WHERE user_id = ?', [req.user.id]);
    res.json({ message: 'Cart wiped from database successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to clear database cart.' });
  }
});

// ─────────────────────────────────────────
//  LIVE PERSISTENT WISHLIST ROUTES
// ─────────────────────────────────────────
app.get('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const [wishlistItems] = await pool.query(
      `SELECT w.product_id AS id, p.name, p.price, p.img, p.shape 
       FROM wishlist_items w 
       JOIN products p ON w.product_id = p.id 
       WHERE w.user_id = ?`,
      [req.user.id]
    );
    res.json(wishlistItems);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve cloud wishlist data.' });
  }
});

app.post('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const { product_id } = req.body;
    await pool.query('INSERT IGNORE INTO wishlist_items (user_id, product_id) VALUES (?, ?)', [req.user.id, product_id]);
    res.json({ message: 'Added to secure wishlist.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save to wishlist.' });
  }
});

app.delete('/api/wishlist/:productId', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM wishlist_items WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
    res.json({ message: 'Removed from secure wishlist.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove from wishlist.' });
  }
});

// ─────────────────────────────────────────
//  LIVE ORDER MANAGEMENT ROUTES
// ─────────────────────────────────────────

// 1. PLACE AN ORDER
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { items, total, paymentMethod, shippingDetails } = req.body;
        
        // Generate a random luxury order number (e.g., DA-849201)
        const orderNumber = 'DA-' + Math.floor(100000 + Math.random() * 900000);
        
        await pool.query(
            `INSERT INTO orders (user_id, order_number, total, payment_method, items, shipping_details) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.id, orderNumber, total, paymentMethod, JSON.stringify(items), JSON.stringify(shippingDetails || {})]
        );
        
        res.status(201).json({ message: 'Order saved securely.', orderId: orderNumber });
    } catch (err) {
        console.error("Order Save Error:", err);
        res.status(500).json({ error: 'Failed to save order to database.' });
    }
});

// 2. FETCH USER ORDERS (For dashboard.html)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.query(
            'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', 
            [req.user.id]
        );
        
        const formattedOrders = orders.map(o => ({
            orderId: o.order_number,
            date: o.created_at,
            total: parseFloat(o.total),
            status: o.status,
            method: o.payment_method,
            items: typeof o.items === 'string' ? JSON.parse(o.items) : o.items,
            shippingDetails: o.shipping_details ? (typeof o.shipping_details === 'string' ? JSON.parse(o.shipping_details) : o.shipping_details) : null
        }));
        
        res.json(formattedOrders);
    } catch (err) {
        console.error("Order Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch orders.' });
    }
});

// ─────────────────────────────────────────
//  DIGITAL VAULT ACCESS ROUTE (1-Year Expiry)
// ─────────────────────────────────────────
app.get('/api/check-course-access', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.query(
            `SELECT id FROM orders 
             WHERE user_id = ? 
             AND items LIKE '%Masterclass%' 
             AND created_at >= DATE_SUB(NOW(), INTERVAL 1 YEAR)`,
            [req.user.id]
        );
        
        if (orders.length > 0) {
            res.json({ hasAccess: true });
        } else {
            res.json({ hasAccess: false });
        }
    } catch (err) {
        console.error("Access Check Error:", err);
        res.status(500).json({ error: 'Failed to verify course access.' });
    }
});

// ─────────────────────────────────────────
//  ADMIN COMMAND CENTER ROUTES
// ─────────────────────────────────────────

// 1. GET ALL ORDERS (Admin Only)
app.get('/api/admin/orders', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
    
    try {
        const [orders] = await pool.query(`
            SELECT o.*, u.name as customer_name, u.email as customer_email 
            FROM orders o 
            JOIN users u ON o.user_id = u.id 
            ORDER BY o.created_at DESC
        `);
        
        const formattedOrders = orders.map(o => ({
            orderId: o.order_number,
            customer: o.customer_name,
            email: o.customer_email,
            date: o.created_at,
            total: parseFloat(o.total),
            status: o.status,
            method: o.payment_method,
            items: typeof o.items === 'string' ? JSON.parse(o.items) : o.items,
            shippingDetails: o.shipping_details ? (typeof o.shipping_details === 'string' ? JSON.parse(o.shipping_details) : o.shipping_details) : null
        }));
        
        res.json(formattedOrders);
    } catch (err) {
        console.error("Admin Order Fetch Error:", err);
        res.status(500).json({ error: 'Failed to fetch all orders.' });
    }
});

// 2. UPDATE ORDER STATUS
app.put('/api/admin/orders/:orderId/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
    
    try {
        const { status } = req.body;
        await pool.query('UPDATE orders SET status = ? WHERE order_number = ?', [status, req.params.orderId]);
        res.json({ message: 'Order status updated successfully.' });
    } catch (err) {
        console.error("Status Update Error:", err);
        res.status(500).json({ error: 'Failed to update status.' });
    }
});

app.listen(PORT, () => {
  console.log(`=========================================`);
  console.log(`🚀 RELATIONAL ENTERPRISE ENGINE LIVE ON PORT ${PORT}`);
  console.log(`=========================================`);
});