const cors = require('cors');
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
require('dotenv').config();






//new code from hapa
const { createClient } = require('@supabase/supabase-js');


const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Missing Supabase credentials in .env');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);




const multer = require('multer');


// Configure multer (store in memory, not on disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});




const app = express();
app.set('trust proxy', 1);

// Allow requests from your Netlify site
app.use(cors({
    origin: 'https://marketcoremultivendor.netlify.app', 
    credentials: true
}));


// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'frontend')));;



// View engine setup (if using EJS)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'frontend', 'views'));


// MySQL connection pool (for queries)

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('✅ Connected to MySQL database.');
    connection.release();
});

// Session store using MySQL (separate pool for sessions)
const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-strong-secret-key-change-this',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax'
    }
}));

// Create users table if not exists
const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('buyer','seller','admin') DEFAULT 'buyer',
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`;

pool.query(createTableQuery, (err) => {
    if (err) {
        console.error('❌ Error creating users table:', err.message);
    } else {
        console.log('✅ Users table ready.');
    }
});






// POST /api/upload - upload an image to Supabase
app.post('/api/upload', upload.single('image'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    // Generate a unique filename
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 10);
    const fileExt = req.file.originalname.split('.').pop();
    const fileName = `seller-${req.session.userId}/${timestamp}-${randomString}.${fileExt}`;

    // Upload to Supabase
    const { data, error } = await supabase.storage
      .from(process.env.SUPABASE_BUCKET)
      .upload(fileName, req.file.buffer, {
        contentType: req.file.mimetype,
        cacheControl: '3600'
      });

    if (error) {
      console.error('Supabase upload error:', error);
      return res.status(500).json({ error: 'Failed to upload image' });
    }

    // Get public URL
    const { data: urlData } = supabase.storage
      .from(process.env.SUPABASE_BUCKET)
      .getPublicUrl(fileName);

    const publicUrl = urlData.publicUrl;

    res.json({ 
      message: 'Upload successful',
      url: publicUrl,
      path: fileName
    });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
//new code ya hapo juu







// Signup endpoint
app.post('/api/signup', async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    try {
        const [existing] = await pool.promise().query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Email already registered.' });
        }

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        await pool.promise().query(
            'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
            [fullName, email, passwordHash]
        );

        res.status(201).json({ message: 'User registered successfully.' });

    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    try {
        // Fetch user by email
        const [rows] = await pool.promise().query(
            'SELECT id, full_name, email, password_hash, role FROM users WHERE email = ? AND is_active = 1',
            [email]
        );

        if (rows.length === 0) {
            console.log(`Login attempt for unknown email: ${email}`);
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            console.log(`Invalid password for email: ${email}`);
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Set session data
        req.session.userId = user.id;
        req.session.userEmail = user.email;
        req.session.userRole = user.role;
        req.session.userName = user.full_name;

        console.log(`User logged in: ${user.email}`);

        res.json({ 
            message: 'Login successful',
            user: {
                id: user.id,
                name: user.full_name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error('❌ Login error:', error); // This will print the actual error
        res.status(500).json({ error: 'Internal server error.' });
    }
});



// Serve login page explicitly (though static should handle it)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'login.html'));
});



// GET /api/user - get current logged-in user
app.get('/api/user', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({
        id: req.session.userId,
        full_name: req.session.userName,
        email: req.session.userEmail,
        role: req.session.userRole
    });
});

// GET /api/seller/application - check current user's seller application
app.get('/api/seller/application', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const [rows] = await pool.promise().query(
            'SELECT id, store_name, store_slug, store_description, business_address, tax_id, status, created_at FROM sellers WHERE user_id = ?',
            [req.session.userId]
        );
        if (rows.length === 0) {
            return res.json(null);
        }
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching seller application:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/seller/apply - submit seller application
app.post('/api/seller/apply', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { storeName, storeDescription, businessAddress, taxId, storeImage } = req.body;

    if (!storeName || !businessAddress) {
        return res.status(400).json({ error: 'Store name and business address are required.' });
    }

    try {
        // Check if user already has a seller record
        const [existing] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'You have already applied to become a seller.' });
        }

        // Generate a unique slug from store name
        const baseSlug = storeName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
        let slug = baseSlug;
        let counter = 1;
        while (true) {
            const [slugCheck] = await pool.promise().query('SELECT id FROM sellers WHERE store_slug = ?', [slug]);
            if (slugCheck.length === 0) break;
            slug = `${baseSlug}-${counter++}`;
        }

        // Insert seller record with status 'pending' including store_logo_url
        await pool.promise().query(
            'INSERT INTO sellers (user_id, store_name, store_slug, store_description, business_address, tax_id, store_logo_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [req.session.userId, storeName, slug, storeDescription || null, businessAddress, taxId || null, storeImage || null]
        );

        res.status(201).json({ message: 'Application submitted successfully. Pending admin approval.' });

    } catch (err) {
        console.error('Error submitting seller application:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});






// GET /api/admin/sellers - list all sellers (admin only)
app.get('/api/admin/sellers', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    try {
        const [rows] = await pool.promise().query(`
            SELECT s.id, s.user_id, u.email, u.full_name, s.store_name, s.store_slug,
                   s.business_address, s.tax_id, s.status, s.created_at
            FROM sellers s
            JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching sellers:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/admin/sellers/:id/approve - approve a seller (admin only)
app.post('/api/admin/sellers/:id/approve', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    const sellerId = req.params.id;
    try {
        // Update seller status
        await pool.promise().query('UPDATE sellers SET status = ? WHERE id = ?', ['approved', sellerId]);

        // Get user_id from seller
        const [seller] = await pool.promise().query('SELECT user_id FROM sellers WHERE id = ?', [sellerId]);
        if (seller.length > 0) {
            const userId = seller[0].user_id;
            // Update user role to 'seller'
            await pool.promise().query('UPDATE users SET role = ? WHERE id = ?', ['seller', userId]);
        }

        res.json({ message: 'Seller approved successfully.' });
    } catch (err) {
        console.error('Error approving seller:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// POST /api/admin/sellers/:id/reject - reject (delete) a seller application (admin only)
app.post('/api/admin/sellers/:id/reject', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    const sellerId = req.params.id;
    try {
        // Option: delete the seller record (you could also mark as rejected)
        await pool.promise().query('DELETE FROM sellers WHERE id = ?', [sellerId]);
        res.json({ message: 'Seller application rejected and removed.' });
    } catch (err) {
        console.error('Error rejecting seller:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.get('/admin/sellers', (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, '..', 'frontend', 'admin-sellers.html'));
});



// GET /api/seller/products - get all products for the logged-in seller
app.get('/api/seller/products', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    try {
        // Get seller_id from sellers table using user_id
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        const [products] = await pool.promise().query(`
			SELECT p.id, p.name, p.description, p.price, p.quantity, p.image_url,
				   p.category_id, c.name as category_name
			FROM products p
			LEFT JOIN categories c ON p.category_id = c.id
			WHERE p.seller_id = ?
			ORDER BY p.created_at DESC
		`, [sellerId]);
        res.json(products);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: 'Database error' });
    }
});



// GET /api/seller/products/:id - get a single product
app.get('/api/seller/products/:id', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    const productId = req.params.id;
    try {
        // Get seller_id
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        const [productRows] = await pool.promise().query(
            'SELECT id, name, description, price, quantity, category, image_url FROM products WHERE id = ? AND seller_id = ?',
            [productId, sellerId]
        );
        if (productRows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(productRows[0]);
    } catch (err) {
        console.error('Error fetching product:', err);
        res.status(500).json({ error: 'Database error' });
    }
});



// POST /api/seller/products - create a new product
app.post('/api/seller/products', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    const { name, description, price, quantity, category_id, image_url } = req.body;
    if (!name || !price) {
        return res.status(400).json({ error: 'Name and price are required' });
    }
    try {
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        const [result] = await pool.promise().query(
            'INSERT INTO products (seller_id, name, description, price, quantity, category_id, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [sellerId, name, description || null, price, quantity || 0, category_id || null, image_url || null]
        );
        res.status(201).json({ message: 'Product created', productId: result.insertId });
    } catch (err) {
        console.error('Error creating product:', err);
        res.status(500).json({ error: 'Database error' });
    }
});





// PUT /api/seller/products/:id - update a product
app.put('/api/seller/products/:id', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    const productId = req.params.id;
    const { name, description, price, quantity, category_id, image_url } = req.body;
    try {
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        // Ensure product belongs to this seller
        const [productRows] = await pool.promise().query('SELECT id FROM products WHERE id = ? AND seller_id = ?', [productId, sellerId]);
        if (productRows.length === 0) {
            return res.status(404).json({ error: 'Product not found or access denied' });
        }

        await pool.promise().query(
            'UPDATE products SET name = ?, description = ?, price = ?, quantity = ?, category_id = ?, image_url = ? WHERE id = ?',
            [name, description, price, quantity, category_id, image_url, productId]
        );
        res.json({ message: 'Product updated' });
    } catch (err) {
        console.error('Error updating product:', err);
        res.status(500).json({ error: 'Database error' });
    }
});



// DELETE /api/seller/products/:id - delete a product
app.delete('/api/seller/products/:id', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    const productId = req.params.id;
    try {
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        const [result] = await pool.promise().query('DELETE FROM products WHERE id = ? AND seller_id = ?', [productId, sellerId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json({ message: 'Product deleted' });
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ error: 'Database error' });
    }
});






//Buyers  tO GET PRODUCTS 
// GET /api/products - list products with optional filters
app.get('/api/products', async (req, res) => {
    const { category, search, minPrice, maxPrice } = req.query;
    let sql = `
        SELECT p.id, p.name, p.description, p.price, p.quantity, p.image_url,
               p.category_id, c.name as category_name,
               s.id as seller_id, s.store_name
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        LEFT JOIN sellers s ON p.seller_id = s.id
        WHERE p.quantity > 0
    `;
    const params = [];

    if (category) {
        sql += ' AND (c.slug = ? OR c.id = ?)';
        params.push(category, category);
    }
    if (search) {
        sql += ' AND p.name LIKE ?';
        params.push(`%${search}%`);
    }
    if (minPrice) {
        sql += ' AND p.price >= ?';
        params.push(parseFloat(minPrice));
    }
    if (maxPrice) {
        sql += ' AND p.price <= ?';
        params.push(parseFloat(maxPrice));
    }

    sql += ' ORDER BY p.created_at DESC';

    try {
        const [rows] = await pool.promise().query(sql, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// GET /api/products/:id - get single product details
app.get('/api/products/:id', async (req, res) => {
    const productId = req.params.id;
    try {
        const [rows] = await pool.promise().query(`
            SELECT p.id, p.name, p.description, p.price, p.quantity, p.image_url,
                   p.category_id, c.name as category_name,
                   s.id as seller_id, s.store_name, s.store_slug
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN sellers s ON p.seller_id = s.id
            WHERE p.id = ?
        `, [productId]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching product:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// GET /api/categories - list all categories
app.get('/api/categories', async (req, res) => {
    try {
        const [rows] = await pool.promise().query('SELECT id, name, slug FROM categories ORDER BY name');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Helper to get or create cart for current user/session
async function getOrCreateCart(req) {
    let cartId = null;
    if (req.session.userId) {
        // Logged in user: find cart by user_id
        const [rows] = await pool.promise().query('SELECT id FROM carts WHERE user_id = ?', [req.session.userId]);
        if (rows.length > 0) {
            cartId = rows[0].id;
        } else {
            // Create new cart for user
            const [result] = await pool.promise().query('INSERT INTO carts (user_id) VALUES (?)', [req.session.userId]);
            cartId = result.insertId;
        }
    } else {
        // Guest: use session_id
        if (!req.session.cartSessionId) {
            req.session.cartSessionId = require('crypto').randomBytes(16).toString('hex');
        }
        const sessionId = req.session.cartSessionId;
        const [rows] = await pool.promise().query('SELECT id FROM carts WHERE session_id = ?', [sessionId]);
        if (rows.length > 0) {
            cartId = rows[0].id;
        } else {
            const [result] = await pool.promise().query('INSERT INTO carts (session_id) VALUES (?)', [sessionId]);
            cartId = result.insertId;
        }
    }
    return cartId;
}

//get cart items
app.get('/api/cart', async (req, res) => {
    try {
        const cartId = await getOrCreateCart(req);
        const [items] = await pool.promise().query(`
            SELECT ci.id, ci.product_id, p.name, p.price as current_price,
                   ci.price as added_price, ci.quantity,
                   p.image_url, s.store_name as seller_name
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            LEFT JOIN sellers s ON p.seller_id = s.id
            WHERE ci.cart_id = ?
        `, [cartId]);
        res.json(items);
    } catch (err) {
        console.error('Error fetching cart:', err);
        res.status(500).json({ error: 'Database error' });
    }
});




//add item to cart
app.post('/api/cart/add', async (req, res) => {
    const { productId, quantity = 1 } = req.body;
    if (!productId) {
        return res.status(400).json({ error: 'Product ID required' });
    }

    try {
        // Get current price from product
        const [productRows] = await pool.promise().query('SELECT price FROM products WHERE id = ? AND quantity > 0', [productId]);
        if (productRows.length === 0) {
            return res.status(404).json({ error: 'Product not available' });
        }
        const price = productRows[0].price;

        const cartId = await getOrCreateCart(req);

        // Check if product already in cart
        const [existing] = await pool.promise().query('SELECT id, quantity FROM cart_items WHERE cart_id = ? AND product_id = ?', [cartId, productId]);
        if (existing.length > 0) {
            // Update quantity
            await pool.promise().query('UPDATE cart_items SET quantity = quantity + ? WHERE id = ?', [quantity, existing[0].id]);
        } else {
            // Insert new item
            await pool.promise().query('INSERT INTO cart_items (cart_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                [cartId, productId, quantity, price]);
        }

        res.json({ message: 'Item added to cart' });
    } catch (err) {
        console.error('Error adding to cart:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

//update quantity
app.put('/api/cart/update/:itemId', async (req, res) => {
    const itemId = req.params.itemId;
    const { quantity } = req.body;
    if (!quantity || quantity < 1) {
        return res.status(400).json({ error: 'Quantity must be at least 1' });
    }

    try {
        const cartId = await getOrCreateCart(req);
        // Ensure item belongs to this cart
        const [result] = await pool.promise().query(
            'UPDATE cart_items SET quantity = ? WHERE id = ? AND cart_id = ?',
            [quantity, itemId, cartId]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json({ message: 'Cart updated' });
    } catch (err) {
        console.error('Error updating cart:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


//remove item FROM cart
app.delete('/api/cart/remove/:itemId', async (req, res) => {
    const itemId = req.params.itemId;
    try {
        const cartId = await getOrCreateCart(req);
        const [result] = await pool.promise().query('DELETE FROM cart_items WHERE id = ? AND cart_id = ?', [itemId, cartId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json({ message: 'Item removed' });
    } catch (err) {
        console.error('Error removing item:', err);
        res.status(500).json({ error: 'Database error' });
    }
});



//clear entire cart
app.delete('/api/cart/clear', async (req, res) => {
    try {
        const cartId = await getOrCreateCart(req);
        await pool.promise().query('DELETE FROM cart_items WHERE cart_id = ?', [cartId]);
        res.json({ message: 'Cart cleared' });
    } catch (err) {
        console.error('Error clearing cart:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


app.get('/api/checkout/summary', async (req, res) => {
    try {
        const cartId = await getOrCreateCart(req);
        const [items] = await pool.promise().query(`
            SELECT ci.id, ci.product_id, p.name, ci.price, ci.quantity,
                   p.seller_id, s.store_name as seller_name
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            LEFT JOIN sellers s ON p.seller_id = s.id
            WHERE ci.cart_id = ?
        `, [cartId]);

        let subtotal = 0;
        items.forEach(item => {
            subtotal += item.price * item.quantity;
        });

        // For now, shipping and tax are zero (can be added later)
        const shipping = 0;
        const tax = 0;
        const grandTotal = subtotal + shipping + tax;

        res.json({
            items,
            subtotal,
            shipping,
            tax,
            grandTotal
        });
    } catch (err) {
    console.error('❌ Error fetching checkout summary:', err);
    console.error('Stack:', err.stack);
    res.status(500).json({ error: err.message }); // Send the actual error to frontend (temporary)
    }
});


app.post('/api/checkout', async (req, res) => {
    const { shippingAddress, billingAddress, paymentMethod = 'cod' } = req.body;

    if (!shippingAddress || !billingAddress) {
        return res.status(400).json({ error: 'Shipping and billing addresses are required' });
    }

    const connection = await pool.promise().getConnection();
    try {
        await connection.beginTransaction();

        // Get cart
        const cartId = await getOrCreateCart(req);
        const [items] = await connection.query(`
            SELECT ci.product_id, ci.quantity, ci.price, p.name as product_name, p.seller_id
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.cart_id = ?
        `, [cartId]);

        if (items.length === 0) {
            await connection.rollback();
            return res.status(400).json({ error: 'Cart is empty' });
        }

        // Calculate totals
        let subtotal = 0;
        items.forEach(item => {
            subtotal += item.price * item.quantity;
        });
        const shipping = 0; // placeholder
        const tax = 0;      // placeholder
        const grandTotal = subtotal + shipping + tax;

        // Generate unique order number
        const orderNumber = 'ORD-' + Date.now() + '-' + Math.floor(1000 + Math.random() * 9000);

        // Insert order
        const [orderResult] = await connection.query(
            `INSERT INTO orders (order_number, user_id, session_id, subtotal, shipping_total, tax_total, grand_total, shipping_address, billing_address, payment_method)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                orderNumber,
                req.session.userId || null,
                req.session.cartSessionId || null,
                subtotal,
                shipping,
                tax,
                grandTotal,
                shippingAddress,
                billingAddress,
                paymentMethod
            ]
        );
        const orderId = orderResult.insertId;

        // Insert order items and update inventory
        for (const item of items) {
            await connection.query(
                `INSERT INTO order_items (order_id, seller_id, product_id, product_name, quantity, price_per_unit, total_price)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    orderId,
                    item.seller_id,
                    item.product_id,
                    item.product_name,
                    item.quantity,
                    item.price,
                    item.price * item.quantity
                ]
            );

            // Deduct inventory
            await connection.query(
                'UPDATE products SET quantity = quantity - ? WHERE id = ? AND quantity >= ?',
                [item.quantity, item.product_id, item.quantity]
            );
        }

        // Clear cart
        await connection.query('DELETE FROM cart_items WHERE cart_id = ?', [cartId]);

        await connection.commit();

        res.status(201).json({
            message: 'Order placed successfully',
            orderNumber,
            orderId
        });

    } catch (err) {
        await connection.rollback();
        console.error('Error placing order:', err);
        res.status(500).json({ error: 'Failed to place order' });
    } finally {
        connection.release();
    }
});






// GET /api/orders - get all orders for the logged-in user
app.get('/api/orders', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const [orders] = await pool.promise().query(`
            SELECT o.id, o.order_number, o.order_date, o.grand_total, o.status,
                   o.payment_status, o.shipping_address
            FROM orders o
            WHERE o.user_id = ?
            ORDER BY o.order_date DESC
        `, [req.session.userId]);

        // For each order, fetch its items
        for (let order of orders) {
			const [items] = await pool.promise().query(`
				SELECT oi.id, oi.product_name, oi.quantity, oi.price_per_unit,
					   oi.total_price, oi.status as item_status,
					   p.image_url
				FROM order_items oi
				LEFT JOIN products p ON oi.product_id = p.id
				WHERE oi.order_id = ?
			`, [order.id]);
			order.items = items;
		}

        res.json(orders);
		} catch (err) {
		console.error('Error fetching orders:', err);
		res.status(500).json({ error: err.message }); // temporary
		}
});


/// GET /api/seller/orders - get orders containing seller's products
app.get('/api/seller/orders', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }

    try {
        // Get seller_id from sellers table
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        // Fetch all order items for this seller, along with order details
        const [orderItems] = await pool.promise().query(`
            SELECT oi.id as item_id, oi.order_id, oi.product_id, oi.product_name,
                   oi.quantity, oi.price_per_unit, oi.total_price, oi.status as item_status,
                   o.order_number, o.order_date, o.user_id, u.full_name as customer_name,
                   o.shipping_address, o.payment_status
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
            JOIN users u ON o.user_id = u.id
            WHERE oi.seller_id = ?
            ORDER BY o.order_date DESC
        `, [sellerId]);

        // Group by order_id
        const ordersMap = new Map();
        orderItems.forEach(item => {
            if (!ordersMap.has(item.order_id)) {
                ordersMap.set(item.order_id, {
                    order_id: item.order_id,
                    order_number: item.order_number,
                    order_date: item.order_date,
                    customer_name: item.customer_name,
                    shipping_address: item.shipping_address,
                    payment_status: item.payment_status,
                    items: []
                });
            }
            ordersMap.get(item.order_id).items.push({
                item_id: item.item_id,
                product_id: item.product_id,
                product_name: item.product_name,
                quantity: item.quantity,
                price_per_unit: item.price_per_unit,
                total_price: item.total_price,
                status: item.item_status
            });
        });

        const orders = Array.from(ordersMap.values());
        res.json(orders);
		} catch (err) {
			console.error('Error fetching seller orders:', err);
			res.status(500).json({ error: err.message }); // temporary
		}
});


// PUT /api/seller/orders/item/:itemId - update status of an order item
app.put('/api/seller/orders/item/:itemId', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }

    const itemId = req.params.itemId;
    const { status } = req.body;

    const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    try {
        // Get seller_id
        const [sellerRows] = await pool.promise().query('SELECT id FROM sellers WHERE user_id = ?', [req.session.userId]);
        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        const sellerId = sellerRows[0].id;

        // Ensure item belongs to this seller
        const [itemRows] = await pool.promise().query(
            'SELECT id FROM order_items WHERE id = ? AND seller_id = ?',
            [itemId, sellerId]
        );
        if (itemRows.length === 0) {
            return res.status(404).json({ error: 'Order item not found' });
        }

        // Update status
        await pool.promise().query(
            'UPDATE order_items SET status = ? WHERE id = ?',
            [status, itemId]
        );

        res.json({ message: 'Item status updated' });
    } catch (err) {
        console.error('Error updating order item:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

//Protected Route for Seller Orders
app.get('/seller/orders', (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, '..', 'frontend', 'seller-orders.html'));
});




// GET /api/wishlist - get all wishlist items for logged-in user
app.get('/api/wishlist', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        const [items] = await pool.promise().query(`
            SELECT w.id as wishlist_id, w.product_id, w.created_at,
                   p.name, p.price, p.image_url, p.quantity as stock,
                   s.store_name as seller_name
            FROM wishlists w
            JOIN products p ON w.product_id = p.id
            LEFT JOIN sellers s ON p.seller_id = s.id
            WHERE w.user_id = ?
            ORDER BY w.created_at DESC
        `, [req.session.userId]);

        res.json(items);
    } catch (err) {
        console.error('Error fetching wishlist:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// POST /api/wishlist/add - add product to wishlist
app.post('/api/wishlist/add', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { productId } = req.body;
    if (!productId) {
        return res.status(400).json({ error: 'Product ID required' });
    }

    try {
        // Check if product exists
        const [product] = await pool.promise().query('SELECT id FROM products WHERE id = ?', [productId]);
        if (product.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Insert (ignore duplicate)
        await pool.promise().query(
            'INSERT IGNORE INTO wishlists (user_id, product_id) VALUES (?, ?)',
            [req.session.userId, productId]
        );

        res.json({ message: 'Added to wishlist' });
    } catch (err) {
        console.error('Error adding to wishlist:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/wishlist/add - add product to wishlist
app.post('/api/wishlist/add', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { productId } = req.body;
    if (!productId) {
        return res.status(400).json({ error: 'Product ID required' });
    }

    try {
        // Check if product exists
        const [product] = await pool.promise().query('SELECT id FROM products WHERE id = ?', [productId]);
        if (product.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Insert (ignore duplicate)
        await pool.promise().query(
            'INSERT IGNORE INTO wishlists (user_id, product_id) VALUES (?, ?)',
            [req.session.userId, productId]
        );

        res.json({ message: 'Added to wishlist' });
    } catch (err) {
        console.error('Error adding to wishlist:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// DELETE /api/wishlist/remove/:productId - remove product from wishlist
app.delete('/api/wishlist/remove/:productId', async (req, res) => {
    console.log('DELETE /api/wishlist/remove called for product:', req.params.productId);
    console.log('User ID from session:', req.session.userId);
    
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const productId = req.params.productId;

    try {
        const [result] = await pool.promise().query(
            'DELETE FROM wishlists WHERE user_id = ? AND product_id = ?',
            [req.session.userId, productId]
        );

        console.log('Delete result:', result);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Item not in wishlist' });
        }

        res.json({ message: 'Removed from wishlist' });
    } catch (err) {
        console.error('🔥 Error removing from wishlist:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/store/:slug - get seller storefront data
app.get('/api/store/:slug', async (req, res) => {
    const slug = req.params.slug;

    try {
        // Get seller details
        const [sellerRows] = await pool.promise().query(`
            SELECT s.id, s.store_name, s.store_slug, s.store_description, s.store_logo_url,
                   s.store_banner_url, s.created_at
            FROM sellers s
            WHERE s.store_slug = ? AND s.status = 'approved'
        `, [slug]);

        if (sellerRows.length === 0) {
            return res.status(404).json({ error: 'Store not found' });
        }

        const seller = sellerRows[0];

        // Get seller's products
        const [products] = await pool.promise().query(`
            SELECT id, name, description, price, quantity, image_url, created_at
            FROM products
            WHERE seller_id = ? AND quantity > 0
            ORDER BY created_at DESC
        `, [seller.id]);

        res.json({
            seller,
            products
        });
    } catch (err) {
        console.error('Error fetching storefront:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// GET /api/seller/store - get logged-in seller's store info
app.get('/api/seller/store', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.status(403).json({ error: 'Seller access required' });
    }
    try {
        const [rows] = await pool.promise().query(
            'SELECT id, store_name, store_slug, store_description, store_logo_url FROM sellers WHERE user_id = ?',
            [req.session.userId]
        );
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Seller record not found' });
        }
        res.json(rows[0]);
    } catch (err) {
        console.error('Error fetching seller store:', err);
        res.status(500).json({ error: 'Database error' });
    }
});




// GET /api/admin/orders - get all orders (admin only)
app.get('/api/admin/orders', async (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }

    try {
        // Fetch all orders with buyer name and total
        const [orders] = await pool.promise().query(`
            SELECT o.id, o.order_number, o.order_date, o.grand_total, o.status,
                   o.payment_status, o.shipping_address, o.billing_address,
                   u.id as user_id, u.full_name as customer_name, u.email as customer_email
            FROM orders o
            JOIN users u ON o.user_id = u.id
            ORDER BY o.order_date DESC
        `);

        // For each order, fetch its items with seller name
        for (let order of orders) {
            const [items] = await pool.promise().query(`
                SELECT oi.id, oi.product_name, oi.quantity, oi.price_per_unit,
                       oi.total_price, oi.status as item_status,
                       s.store_name as seller_name
                FROM order_items oi
                LEFT JOIN sellers s ON oi.seller_id = s.id
                WHERE oi.order_id = ?
            `, [order.id]);
            order.items = items;
        }

        res.json(orders);
    } catch (err) {
        console.error('Error fetching admin orders:', err);
        res.status(500).json({ error: 'Database error' });
    }
});


// GET /api/category/:slug - get category details and its products
app.get('/api/category/:slug', async (req, res) => {
    const slug = req.params.slug;
    try {
        const [catRows] = await pool.promise().query('SELECT id, name FROM categories WHERE slug = ?', [slug]);
        if (catRows.length === 0) {
            return res.status(404).json({ error: 'Category not found' });
        }
        const category = catRows[0];
        const [products] = await pool.promise().query(`
            SELECT p.id, p.name, p.price, p.image_url, p.quantity,
                   s.store_name as seller_name
            FROM products p
            LEFT JOIN sellers s ON p.seller_id = s.id
            WHERE p.category_id = ? AND p.quantity > 0
            ORDER BY p.created_at DESC
        `, [category.id]);
        res.json({ category, products });
    } catch (err) {
        console.error('Error fetching category:', err);
        res.status(500).json({ error: 'Database error' });
    }
});



// Dashboard route (protected)



app.get('/admin/sellers', (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'admin') {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, '..', 'frontend', 'admin-sellers.html'));
});

app.get('/seller/products', (req, res) => {
    if (!req.session.userId || req.session.userRole !== 'seller') {
        return res.redirect('/dashboard');
    }
    res.sendFile(path.join(__dirname, '..', 'frontend', 'seller-products.html'));
});

// Logout route
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out successfully.' });
    });
});



	
console.log('Environment:', process.env.NODE_ENV);
console.log('DB_HOST:', process.env.DB_HOST);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
