const mysql = require('mysql2');
const bcrypt = require('bcrypt');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root1234',
    database: 'car_rental'
});

async function hashPasswords() {
    try {
        // Hash admin password
        const adminHash = await bcrypt.hash('admin123', 10);
        await db.promise().query('UPDATE users SET password = ? WHERE email = ?', [adminHash, 'admin@swiftride.com']);
        
        // Hash test user password
        const testHash = await bcrypt.hash('test123', 10);
        await db.promise().query('UPDATE users SET password = ? WHERE email = ?', [testHash, 'test@test.com']);
        
        console.log('✅ Passwords hashed successfully!');
        process.exit(0);
    } catch (error) {
        console.error('Error:', error);
        process.exit(1);
    }
}

hashPasswords();
