const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 5000;
const SECRET = 'swiftride_secret_2024';

// Create uploads folder
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
});

// Serve uploaded images
app.use('/uploads', express.static(uploadsDir));

// CORS
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        callback(null, true);
    },
    credentials: true
}));
app.use(express.json());

// PostgreSQL Database connection
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'car_rental',
    port: process.env.DB_PORT || 5432,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('Database error:', err);
        return;
    }
    console.log('✅ Database connected');
    release();
});

// Helper function
function validatePassword(password) {
    if (password.length < 8) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[!@#$%^&*]/.test(password)) return false;
    return true;
}

// ========== AUTH ROUTES ==========
app.post('/api/register', async (req, res) => {
    const { name, email, password, phone } = req.body;

    if (!validatePassword(password)) {
        return res.status(400).json({
            message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character'
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        pool.query('INSERT INTO users (name, email, password, phone) VALUES ($1, $2, $3, $4)',
            [name, email, hashedPassword, phone],
            (err) => {
                if (err) {
                    if (err.code === '23505') { // PostgreSQL duplicate key error
                        return res.status(400).json({ message: 'Email already exists' });
                    }
                    return res.status(500).json({ message: 'Database error' });
                }
                res.json({ message: 'Registration successful!' });
            });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    pool.query('SELECT * FROM users WHERE email = $1', [email], async (err, result) => {
        if (err || result.rows.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    });
});

app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;

    pool.query('SELECT * FROM users WHERE email = $1', [email], (err, result) => {
        if (err || result.rows.length === 0) {
            return res.status(404).json({ message: 'Email not found' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 3600000);

        pool.query('UPDATE users SET reset_token = $1, reset_expires = $2 WHERE email = $3',
            [token, expires, email],
            (err) => {
                if (err) return res.status(500).json({ message: 'Database error' });
                res.json({ resetToken: token });
            });
    });
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!validatePassword(newPassword)) {
        return res.status(400).json({ message: 'Password requirements not met' });
    }

    pool.query('SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()', [token], async (err, result) => {
        if (err || result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        pool.query('UPDATE users SET password = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2',
            [hashedPassword, result.rows[0].id],
            (err) => {
                if (err) return res.status(500).json({ message: 'Database error' });
                res.json({ message: 'Password reset successful!' });
            });
    });
});

// ========== CAR ROUTES ==========
app.get('/api/cars', (req, res) => {
    pool.query('SELECT * FROM cars', (err, result) => {
        if (err) return res.status(500).json({ message: 'Error' });
        res.json(result.rows);
    });
});

// ========== BOOKING ROUTES ==========
app.post('/api/bookings', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        const { car_id, start_date, end_date } = req.body;

        pool.query('SELECT price_per_day FROM cars WHERE id = $1', [car_id], (err, result) => {
            if (err || result.rows.length === 0) return res.status(404).json({ message: 'Car not found' });

            const days = Math.ceil((new Date(end_date) - new Date(start_date)) / (1000 * 60 * 60 * 24));
            const total = result.rows[0].price_per_day * days;

            pool.query('INSERT INTO bookings (user_id, car_id, start_date, end_date, total_price) VALUES ($1, $2, $3, $4, $5)',
                [decoded.id, car_id, start_date, end_date, total],
                (err) => {
                    if (err) return res.status(500).json({ message: 'Booking failed' });
                    res.json({ message: 'Booking created!' });
                });
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.get('/api/my-bookings', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        pool.query(`SELECT b.*, c.name as car_name, c.image_url 
                  FROM bookings b 
                  JOIN cars c ON b.car_id = c.id 
                  WHERE b.user_id = $1 
                  ORDER BY b.booking_date DESC`,
            [decoded.id],
            (err, result) => {
                if (err) return res.status(500).json({ message: 'Error' });
                res.json(result.rows);
            });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.put('/api/bookings/:id/cancel', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        pool.query('UPDATE bookings SET status = $1 WHERE id = $2 AND user_id = $3 AND status = $4',
            ['cancelled', req.params.id, decoded.id, 'pending'],
            (err) => {
                if (err) return res.status(400).json({ message: 'Cannot cancel' });
                res.json({ message: 'Booking cancelled' });
            });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// ========== ADMIN STATS ==========
app.get('/api/admin/stats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        const stats = {};
        pool.query('SELECT COUNT(*) as count FROM users', (err, result) => {
            stats.totalUsers = parseInt(result.rows[0].count);
            pool.query('SELECT COUNT(*) as count FROM cars', (err, result) => {
                stats.totalCars = parseInt(result.rows[0].count);
                pool.query('SELECT COUNT(*) as count FROM bookings', (err, result) => {
                    stats.totalBookings = parseInt(result.rows[0].count);
                    pool.query('SELECT SUM(total_price) as revenue FROM bookings WHERE status != $1', ['cancelled'], (err, result) => {
                        stats.totalRevenue = result.rows[0].revenue || 0;
                        res.json(stats);
                    });
                });
            });
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// ========== ADMIN BOOKINGS ==========
app.get('/api/admin/bookings', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        pool.query(`SELECT b.*, u.name as user_name, c.name as car_name 
                  FROM bookings b 
                  JOIN users u ON b.user_id = u.id 
                  JOIN cars c ON b.car_id = c.id 
                  ORDER BY b.booking_date DESC`,
            (err, result) => {
                if (err) return res.status(500).json({ message: 'Error' });
                res.json(result.rows);
            });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.put('/api/admin/bookings/:id/status', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        pool.query('UPDATE bookings SET status = $1 WHERE id = $2', [req.body.status, req.params.id], (err) => {
            if (err) return res.status(500).json({ message: 'Error' });
            res.json({ message: 'Status updated' });
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// ========== ADMIN CAR MANAGEMENT ==========
app.post('/api/admin/cars', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        const { name, price_per_day, category, transmission, seats, image_url, status } = req.body;

        let finalImageUrl = image_url || 'https://images.unsplash.com/photo-1492144534655-ae79c964c9d7?w=400';

        pool.query('INSERT INTO cars (name, price_per_day, category, transmission, seats, image_url, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [name, price_per_day, category, transmission, seats, finalImageUrl, status || 'available'],
            (err) => {
                if (err) return res.status(500).json({ message: 'Error adding car' });
                res.json({ message: 'Car added successfully' });
            });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.put('/api/admin/cars/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        const { name, price_per_day, category, transmission, seats, image_url, status } = req.body;

        pool.query('UPDATE cars SET name=$1, price_per_day=$2, category=$3, transmission=$4, seats=$5, image_url=$6, status=$7 WHERE id=$8',
            [name, price_per_day, category, transmission, seats, image_url, status, req.params.id],
            (err) => {
                if (err) return res.status(500).json({ message: 'Error updating car' });
                res.json({ message: 'Car updated successfully' });
            });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.delete('/api/admin/cars/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        pool.query('DELETE FROM cars WHERE id = $1', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: 'Error deleting car' });
            res.json({ message: 'Car deleted successfully' });
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// ========== IMAGE UPLOAD ==========
app.post('/api/upload', upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    res.json({ imageUrl });
});

// ========== NEWSLETTER ROUTES ==========
app.post('/api/newsletter/subscribe', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    pool.query('INSERT INTO newsletter (email) VALUES ($1)', [email], (err) => {
        if (err) {
            if (err.code === '23505') {
                return res.status(400).json({ message: 'Email already subscribed!' });
            }
            return res.status(500).json({ message: 'Database error' });
        }
        res.json({ message: 'Successfully subscribed to newsletter!' });
    });
});

app.get('/api/admin/newsletter', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        pool.query('SELECT * FROM newsletter ORDER BY subscribed_at DESC', (err, result) => {
            if (err) return res.status(500).json({ message: 'Error' });
            res.json(result.rows);
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.listen(PORT, () => {
    console.log(`🚗 SwiftRide Server on http://localhost:${PORT}`);
    console.log(`📸 Uploads at http://localhost:${PORT}/uploads`);
});