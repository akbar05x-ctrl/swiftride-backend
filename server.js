const express = require('express');
const mysql = require('mysql2');
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
        // Allow requests with no origin (like mobile apps, postman, or curl)
        if (!origin) return callback(null, true);
        // Dynamically allow the request origin to satisfy credentials: true requirement
        callback(null, true);
    },
    credentials: true
}));
app.use(express.json());

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
   password: '',
    database: process.env.DB_NAME || 'car_rental',
    port: process.env.DB_PORT || 3306
};

// Automatically enable SSL for non-localhost environments (e.g. Aiven MySQL)
if (process.env.DB_SSL === 'true' || (process.env.DB_HOST && !process.env.DB_HOST.includes('localhost'))) {
    dbConfig.ssl = {
        rejectUnauthorized: false
    };
}

const db = mysql.createConnection(dbConfig);

db.connect((err) => {
    if (err) {
        console.error('Database error:', err);
        return;
    }
    console.log('✅ Database connected');
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
        db.query('INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, phone],
            (err) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
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

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, users) => {
        if (err || users.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = users[0];
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

// ========== FORGOT PASSWORD FIXED ==========
app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    
    console.log('📧 Forgot password request for:', email);

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'Email not found' });
        }

        // Generate a simple 6-digit OTP
        const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 3600000);

        db.query('UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?',
            [resetToken, expires, email],
            (updateErr) => {
                if (updateErr) {
                    console.error('Update Error:', updateErr);
                    return res.status(500).json({ message: 'Failed to generate reset token' });
                }
                
                console.log('✅ Reset token generated:', resetToken);
                
                res.json({ 
                    success: true,
                    resetToken: resetToken,
                    message: 'Reset code generated successfully!'
                });
            });
    });
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    
    console.log('🔐 Reset password attempt with token:', token);

    if (!token || !newPassword) {
        return res.status(400).json({ message: 'Token and new password are required' });
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).json({ 
            message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character'
        });
    }

    db.query('SELECT * FROM users WHERE reset_token = ? AND reset_expires > NOW()', [token], async (err, users) => {
        if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (users.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired reset code' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        db.query('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?',
            [hashedPassword, users[0].id],
            (updateErr) => {
                if (updateErr) {
                    console.error('Update Error:', updateErr);
                    return res.status(500).json({ message: 'Failed to reset password' });
                }
                console.log('✅ Password reset successful');
                res.json({ message: 'Password reset successful! You can now login.' });
            });
    });
});

// ========== CAR ROUTES ==========
app.get('/api/cars', (req, res) => {
    db.query('SELECT * FROM cars', (err, cars) => {
        if (err) return res.status(500).json({ message: 'Error' });
        res.json(cars);
    });
});

// ========== BOOKING ROUTES ==========
app.post('/api/bookings', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        const { car_id, start_date, end_date } = req.body;

        db.query('SELECT price_per_day FROM cars WHERE id = ?', [car_id], (err, cars) => {
            if (err || cars.length === 0) return res.status(404).json({ message: 'Car not found' });

            const days = Math.ceil((new Date(end_date) - new Date(start_date)) / (1000 * 60 * 60 * 24));
            const total = cars[0].price_per_day * days;

            db.query('INSERT INTO bookings (user_id, car_id, start_date, end_date, total_price) VALUES (?, ?, ?, ?, ?)',
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
        db.query(`SELECT b.*, c.name as car_name, c.image_url 
                  FROM bookings b 
                  JOIN cars c ON b.car_id = c.id 
                  WHERE b.user_id = ? 
                  ORDER BY b.booking_date DESC`,
            [decoded.id],
            (err, results) => {
                if (err) return res.status(500).json({ message: 'Error' });
                res.json(results);
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
        db.query('UPDATE bookings SET status = "cancelled" WHERE id = ? AND user_id = ? AND status = "pending"',
            [req.params.id, decoded.id],
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
        db.query('SELECT COUNT(*) as count FROM users', (err, users) => {
            stats.totalUsers = users[0].count;
            db.query('SELECT COUNT(*) as count FROM cars', (err, cars) => {
                stats.totalCars = cars[0].count;
                db.query('SELECT COUNT(*) as count FROM bookings', (err, bookings) => {
                    stats.totalBookings = bookings[0].count;
                    db.query('SELECT SUM(total_price) as revenue FROM bookings WHERE status != "cancelled"', (err, revenue) => {
                        stats.totalRevenue = revenue[0].revenue || 0;
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

        db.query(`SELECT b.*, u.name as user_name, c.name as car_name 
                  FROM bookings b 
                  JOIN users u ON b.user_id = u.id 
                  JOIN cars c ON b.car_id = c.id 
                  ORDER BY b.booking_date DESC`,
            (err, results) => {
                if (err) return res.status(500).json({ message: 'Error' });
                res.json(results);
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

        db.query('UPDATE bookings SET status = ? WHERE id = ?', [req.body.status, req.params.id], (err) => {
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

        db.query('INSERT INTO cars (name, price_per_day, category, transmission, seats, image_url, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
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

        db.query('UPDATE cars SET name=?, price_per_day=?, category=?, transmission=?, seats=?, image_url=?, status=? WHERE id=?',
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

        db.query('DELETE FROM cars WHERE id = ?', [req.params.id], (err) => {
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

app.listen(PORT, () => {
    console.log(`🚗 SwiftRide Server on http://localhost:${PORT}`);
    console.log(`📸 Uploads at http://localhost:5000/uploads`);
});

// ========== NEWSLETTER ROUTES ==========

app.get('/api/admin/newsletter', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        db.query('SELECT * FROM newsletter ORDER BY subscribed_at DESC', (err, results) => {
            if (err) return res.status(500).json({ message: 'Error' });
            res.json(results);
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Unsubscribe from newsletter
app.delete('/api/newsletter/unsubscribe', (req, res) => {
    const { email } = req.body;

    db.query('DELETE FROM newsletter WHERE email = ?', [email], (err) => {
        if (err) return res.status(500).json({ message: 'Error' });
        res.json({ message: 'Unsubscribed successfully!' });
    });
});

// Newsletter Subscribe
app.post('/api/newsletter/subscribe', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    db.query('INSERT INTO newsletter (email) VALUES (?)', [email], (err) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Email already subscribed!' });
            }
            return res.status(500).json({ message: 'Database error' });
        }
        res.json({ message: 'Successfully subscribed to newsletter!' });
    });
});


// ========== NEWSLETTER ROUTES ==========

// Subscribe to newsletter
app.post('/api/newsletter/subscribe', (req, res) => {
    const { email } = req.body;
    console.log('📧 Newsletter subscription:', email);

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    db.query('INSERT INTO newsletter (email) VALUES (?)', [email], (err) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Email already subscribed!' });
            }
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        console.log('✅ Subscribed:', email);
        res.json({ message: '✅ Successfully subscribed to newsletter!' });
    });
});

// Get all newsletter subscribers (Admin only)
app.get('/api/admin/newsletter', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ message: 'Admin only' });

        db.query('SELECT * FROM newsletter ORDER BY subscribed_at DESC', (err, results) => {
            if (err) return res.status(500).json({ message: 'Error' });
            res.json(results);
        });
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
});
