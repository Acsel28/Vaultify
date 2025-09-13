const mysql = require('mysql2/promise');
require('dotenv').config();

// Database configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'admin',
    password: process.env.DB_PASSWORD || 'advait',
    database: process.env.DB_NAME || 'password_manager',
    port: process.env.DB_PORT || 3306,
    connectionLimit: 10,
    acquireTimeout: 60000,
    timeout: 60000,
    multipleStatements: true
};

// Create connection pool
let pool;

const connectDB = async () => {
    try {
        pool = mysql.createPool(dbConfig);
        
        // Test the connection
        const connection = await pool.getConnection();
        console.log(`✅ MySQL Connected: ${dbConfig.host}:${dbConfig.port}`);
        console.log(`📊 Database: ${dbConfig.database}`);
        console.log(`👤 User: ${dbConfig.user}`);
        
        // Release the test connection
        connection.release();
        
        // Create tables if they don't exist
        await initializeTables();
        
        console.log('✅ Database tables initialized successfully');
        
    } catch (error) {
        console.error('❌ MySQL connection failed:', error.message);
        console.error('💡 Check your MySQL server and credentials');
        process.exit(1);
    }
};

// Initialize database tables
const initializeTables = async () => {
    try {
        const connection = await pool.getConnection();
        
        // Users table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                security_score INT DEFAULT 0,
                theme VARCHAR(20) DEFAULT 'light',
                notifications BOOLEAN DEFAULT TRUE,
                auto_lock INT DEFAULT 300,
                last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_email (email)
            )
        `);
        
        // Password entries table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS password_entries (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(100) NOT NULL,
                website VARCHAR(255) NOT NULL,
                website_name VARCHAR(100),
                username VARCHAR(200) NOT NULL,
                encrypted_password TEXT NOT NULL,
                url VARCHAR(500),
                notes TEXT,
                tags JSON,
                has_two_factor BOOLEAN DEFAULT FALSE,
                strength VARCHAR(20) DEFAULT 'Fair',
                strength_score INT DEFAULT 0,
                is_favorite BOOLEAN DEFAULT FALSE,
                last_used TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_website (website),
                INDEX idx_strength (strength_score)
            )
        `);
        
        // MFA settings table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS mfa_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT UNIQUE NOT NULL,
                is_enabled BOOLEAN DEFAULT FALSE,
                otp_secret VARCHAR(255),
                email_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id)
            )
        `);
        
        // Quiz results table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS quiz_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                quiz_type VARCHAR(50) DEFAULT 'cybersecurity_basics',
                score INT NOT NULL,
                correct_answers INT NOT NULL,
                total_questions INT NOT NULL,
                answers JSON,
                time_spent INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_quiz_type (quiz_type),
                INDEX idx_score (score)
            )
        `);
        
        connection.release();
        console.log('✅ All database tables ready');
        
    } catch (error) {
        console.error('❌ Error creating tables:', error.message);
        throw error;
    }
};

// Execute query helper
const query = async (sql, params = []) => {
    const connection = await pool.getConnection();
    try {
        const [results] = await connection.execute(sql, params);
        return results;
    } catch (error) {
        console.error('❌ SQL Error:', error.message);
        console.error('❌ SQL:', sql.substring(0, 100));
        throw error;
    } finally {
        connection.release();
    }
};

// Transaction helper
const transaction = async (callback) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const result = await callback(connection);
        await connection.commit();
        return result;
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
};

// Close connection pool
const closeDB = async () => {
    if (pool) {
        await pool.end();
        console.log('📤 MySQL connection pool closed');
    }
};

// Handle shutdown
process.on('SIGINT', async () => {
    await closeDB();
    process.exit(0);
});

module.exports = {
    connectDB,
    query,
    transaction,
    closeDB
};