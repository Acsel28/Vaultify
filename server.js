const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const CryptoJS = require('crypto-js');
require('dotenv').config();

// MYSQL ONLY - NO MODEL IMPORTS
const { connectDB, query, transaction } = require('./config/database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-encryption-key-32-chars-long!';

// Connect to MySQL
connectDB();

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
    console.log(`📥 ${req.method} ${req.path} - ${new Date().toISOString()}`);
    next();
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// Encryption utilities
const encrypt = (text, key) => {
    return CryptoJS.AES.encrypt(text, key).toString();
};

const decrypt = (cipherText, key) => {
    try {
        const bytes = CryptoJS.AES.decrypt(cipherText, key);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        console.error('Decryption error:', error);
        return '';
    }
};

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Validation middleware
const validateInput = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed',
                details: errors.array()
            });
        }
        next();
    };
};

// Password strength calculator
const calculatePasswordStrength = (password) => {
    let score = 0;
    const feedback = [];
    
    const length = password.length;
    if (length < 8) {
        score += length * 2;
        feedback.push('Password too short. Use at least 8 characters.');
    } else if (length < 12) {
        score += 16 + (length - 8) * 4;
        feedback.push('Consider using 12+ characters for better security.');
    } else {
        score += 32 + Math.min((length - 12) * 2, 20);
    }
    
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    score += variety * 10;
    
    let charset = 0;
    if (hasLower) charset += 26;
    if (hasUpper) charset += 26;
    if (hasNumber) charset += 10;
    if (hasSymbol) charset += 32;
    
    const entropy = length * Math.log2(charset);
    score += Math.min(entropy / 2, 25);
    
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
    if (commonPasswords.includes(password.toLowerCase())) {
        score -= 50;
        feedback.push('This is a commonly used password. Choose something unique.');
    }
    
    const sequential = ['123', 'abc', 'qwe'];
    if (sequential.some(pattern => password.toLowerCase().includes(pattern))) {
        score -= 20;
        feedback.push('Avoid sequential characters or numbers.');
    }
    
    const finalScore = Math.min(Math.max(score, 0), 100);
    let strength = 'Very Weak';
    
    if (finalScore >= 90) strength = 'Very Strong';
    else if (finalScore >= 75) strength = 'Strong';
    else if (finalScore >= 60) strength = 'Good';
    else if (finalScore >= 40) strength = 'Fair';
    else if (finalScore >= 20) strength = 'Weak';
    
    return {
        score: finalScore,
        strength,
        feedback,
        entropy: Math.round(entropy * 100) / 100
    };
};

// Quiz questions
const quizQuestions = [
    {
        id: 1,
        question: "What is the minimum recommended length for a secure password in 2024?",
        options: ["8 characters", "10 characters", "12 characters", "16 characters"],
        correctAnswer: 2,
        explanation: "Security experts now recommend at least 12 characters for passwords.",
        category: "Password Security",
        difficulty: "easy"
    },
    {
        id: 2,
        question: "Which is the most secure way to store passwords?",
        options: ["Browser's built-in manager", "Written on paper", "Dedicated password manager", "Memorize all passwords"],
        correctAnswer: 2,
        explanation: "Dedicated password managers use strong encryption.",
        category: "Password Management",
        difficulty: "easy"
    },
    {
        id: 3,
        question: "What does two-factor authentication (2FA) provide?",
        options: ["Backup password", "Additional security layer", "Password encryption", "Account recovery"],
        correctAnswer: 1,
        explanation: "2FA adds an extra layer of security beyond passwords.",
        category: "Authentication",
        difficulty: "medium"
    },
    {
        id: 4,
        question: "How often should you change your passwords?",
        options: ["Every month", "Every 3 months", "Only when compromised", "Every year"],
        correctAnswer: 2,
        explanation: "Modern security practices recommend changing only when compromised.",
        category: "Password Management",
        difficulty: "medium"
    },
    {
        id: 5,
        question: "What is a phishing attack?",
        options: ["Malware infection", "Fraudulent credential theft", "Network intrusion", "Data encryption"],
        correctAnswer: 1,
        explanation: "Phishing involves tricking users into revealing credentials.",
        category: "Cyber Threats",
        difficulty: "easy"
    }
];

// Security tips
const securityTips = [
    {
        id: 1,
        title: "Use Unique Passwords Everywhere",
        description: "Each account should have its own unique password.",
        category: "Password Hygiene",
        importance: "critical"
    },
    {
        id: 2,
        title: "Enable Two-Factor Authentication",
        description: "Add an extra layer of security with 2FA.",
        category: "Authentication",
        importance: "high"
    },
    {
        id: 3,
        title: "Regular Security Checkups",
        description: "Review your accounts monthly.",
        category: "Account Management",
        importance: "medium"
    },
    {
        id: 4,
        title: "Beware of Phishing Attempts",
        description: "Always verify sender and URL before clicking.",
        category: "Threat Awareness",
        importance: "critical"
    }
];

// Update security score helper
const updateUserSecurityScore = async (userId, bonusPoints = 0) => {
    try {
        const entries = await query('SELECT strength_score, has_two_factor FROM password_entries WHERE user_id = ?', [userId]);
        const quizResults = await query('SELECT score FROM quiz_results WHERE user_id = ?', [userId]);
        
        let score = 0;
        
        // Password strength (40%)
        if (entries.length > 0) {
            const avgStrength = entries.reduce((sum, entry) => sum + entry.strength_score, 0) / entries.length;
            score += (avgStrength * 0.4);
        }
        
        // Number of passwords (20%)
        if (entries.length > 0) {
            score += Math.min(entries.length * 5, 20);
        }
        
        // 2FA usage (15%)
        const twoFactorCount = entries.filter(entry => entry.has_two_factor).length;
        if (twoFactorCount > 0) {
            score += Math.min(twoFactorCount * 3, 15);
        }
        
        // Quiz completion (15%)
        if (quizResults.length > 0) {
            const avgQuizScore = quizResults.reduce((sum, qr) => sum + qr.score, 0) / quizResults.length;
            score += (avgQuizScore * 0.15);
        }
        
        // Bonus points (10%)
        score += bonusPoints;
        
        const finalScore = Math.min(Math.round(score), 100);
        await query('UPDATE users SET security_score = ? WHERE id = ?', [finalScore, userId]);
        
        console.log('✅ Security score updated to:', finalScore);
        
    } catch (error) {
        console.error('❌ Security score update error:', error);
    }
};

// ROUTES

// Health check
app.get('/api/health', async (req, res) => {
    try {
        await query('SELECT 1 as test');
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            database: 'Connected',
            type: 'MySQL'
        });
    } catch (error) {
        res.json({ 
            status: 'OK', 
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            database: 'Disconnected',
            type: 'MySQL',
            error: error.message
        });
    }
});

// DEBUG ROUTES
app.get('/api/debug/users', async (req, res) => {
    try {
        const users = await query('SELECT id, email, security_score, created_at, last_login FROM users ORDER BY created_at DESC');
        res.json({ 
            count: users.length, 
            users: users,
            databaseType: 'MySQL'
        });
    } catch (error) {
        console.error('❌ Debug users error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/debug/vaults', async (req, res) => {
    try {
        const entries = await query(`
            SELECT pe.*, u.email as user_email 
            FROM password_entries pe 
            LEFT JOIN users u ON pe.user_id = u.id 
            ORDER BY pe.created_at DESC
        `);
        
        const vaultsByUser = {};
        entries.forEach(entry => {
            if (!vaultsByUser[entry.user_id]) {
                vaultsByUser[entry.user_id] = {
                    userId: entry.user_id,
                    userEmail: entry.user_email,
                    entries: []
                };
            }
            vaultsByUser[entry.user_id].entries.push({
                id: entry.id,
                website: entry.website,
                username: entry.username,
                strength: entry.strength,
                strengthScore: entry.strength_score
            });
        });
        
        const vaults = Object.values(vaultsByUser);
        
        res.json({ 
            count: vaults.length, 
            totalEntries: entries.length,
            vaults: vaults.map(v => ({
                ...v,
                entriesCount: v.entries.length
            })),
            databaseType: 'MySQL'
        });
    } catch (error) {
        console.error('❌ Debug vaults error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/debug/clear', async (req, res) => {
    try {
        await query('DELETE FROM quiz_results');
        await query('DELETE FROM password_entries');
        await query('DELETE FROM mfa_settings');
        await query('DELETE FROM users');
        res.json({ message: 'All data cleared successfully' });
    } catch (error) {
        console.error('❌ Clear data error:', error);
        res.status(500).json({ error: error.message });
    }
});

// AUTHENTICATION ROUTES

// Sign up
app.post('/api/auth/signup', 
    validateInput([
        body('email').isEmail().normalizeEmail(),
        body('masterPassword').isLength({ min: 8 }).withMessage('Master password must be at least 8 characters long')
    ]),
    async (req, res) => {
        console.log('🎯 === SIGNUP STARTED ===');
        console.log('📧 Email:', req.body.email);
        console.log('🔐 Password length:', req.body.masterPassword?.length);
        
        try {
            const { email, masterPassword } = req.body;
            
            // Check if user exists
            console.log('🔍 Checking if user exists...');
            const existingUsers = await query('SELECT id FROM users WHERE email = ?', [email]);
            if (existingUsers.length > 0) {
                console.log('❌ User already exists');
                return res.status(409).json({ error: 'User already exists' });
            }
            
            // Hash password
            console.log('🔐 Hashing password...');
            const passwordHash = await bcrypt.hash(masterPassword, 12);
            
            // Calculate security score
            const passwordStrength = calculatePasswordStrength(masterPassword);
            console.log('📊 Password strength:', passwordStrength.strength);
            
            // Create user
            console.log('💾 Creating user in MySQL...');
            const result = await query(
                'INSERT INTO users (email, password_hash, security_score) VALUES (?, ?, ?)',
                [email, passwordHash, Math.round(passwordStrength.score * 0.3)]
            );
            
            const userId = result.insertId;
            console.log('✅ User created with ID:', userId);
            
            // Create MFA settings
            await query('INSERT INTO mfa_settings (user_id, is_enabled) VALUES (?, FALSE)', [userId]);
            
            // Get created user
            const [newUser] = await query('SELECT id, email, security_score, created_at FROM users WHERE id = ?', [userId]);
            
            // Generate token
            const token = jwt.sign(
                { userId: newUser.id, email: newUser.email },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            console.log('🎉 === SIGNUP COMPLETED ===');
            
            res.status(201).json({
                message: 'User created successfully',
                user: {
                    id: newUser.id,
                    email: newUser.email,
                    securityScore: newUser.security_score,
                    createdAt: newUser.created_at
                },
                token
            });
            
        } catch (error) {
            console.error('💥 SIGNUP ERROR:', error.message);
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(409).json({ error: 'Email already exists' });
            }
            res.status(500).json({ error: 'Registration failed: ' + error.message });
        }
    }
);

// Sign in
app.post('/api/auth/signin', 
    validateInput([
        body('email').isEmail().normalizeEmail(),
        body('masterPassword').notEmpty().withMessage('Master password is required')
    ]),
    async (req, res) => {
        console.log('🎯 === SIGNIN STARTED ===');
        console.log('📧 Email:', req.body.email);
        
        try {
            const { email, masterPassword } = req.body;
            
            // Find user
            console.log('🔍 Finding user in MySQL...');
            const users = await query('SELECT * FROM users WHERE email = ?', [email]);
            if (users.length === 0) {
                console.log('❌ User not found');
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            
            const user = users[0];
            console.log('✅ User found:', user.id);
            
            // Check password
            console.log('🔐 Checking password...');
            const isValidPassword = await bcrypt.compare(masterPassword, user.password_hash);
            
            if (!isValidPassword) {
                console.log('❌ Invalid password');
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            
            // Update last login
            await query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
            
            // Generate token
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            console.log('🎉 === SIGNIN COMPLETED ===');
            
            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    email: user.email,
                    securityScore: user.security_score,
                    preferences: {
                        theme: user.theme,
                        notifications: user.notifications,
                        autoLock: user.auto_lock
                    }
                },
                token
            });
            
        } catch (error) {
            console.error('💥 SIGNIN ERROR:', error.message);
            res.status(500).json({ error: 'Login failed: ' + error.message });
        }
    }
);

// VAULT ROUTES

// Get passwords
app.get('/api/vault', authenticateToken, async (req, res) => {
    try {
        const entries = await query('SELECT * FROM password_entries WHERE user_id = ? ORDER BY created_at DESC', [req.user.userId]);
        
        const passwords = entries.map(entry => {
            const decryptedPassword = decrypt(entry.encrypted_password, ENCRYPTION_KEY);
            return {
                id: entry.id,
                userId: entry.user_id,
                website: entry.website,
                websiteName: entry.website_name,
                username: entry.username,
                password: decryptedPassword,
                notes: entry.notes || '',
                tags: entry.tags ? JSON.parse(entry.tags) : [],
                hasTwoFactor: entry.has_two_factor || false,
                strength: entry.strength,
                strengthScore: entry.strength_score,
                isFavorite: entry.is_favorite || false,
                createdAt: entry.created_at,
                lastModified: entry.updated_at,
                lastUsed: entry.last_used
            };
        });
        
        res.json({
            passwords,
            count: passwords.length
        });
        
    } catch (error) {
        console.error('❌ Get vault error:', error);
        res.status(500).json({ error: 'Failed to get passwords: ' + error.message });
    }
});

// Add password
app.post('/api/vault',
    authenticateToken,
    validateInput([
        body('website').notEmpty().withMessage('Website is required'),
        body('username').notEmpty().withMessage('Username is required'),
        body('password').notEmpty().withMessage('Password is required')
    ]),
    async (req, res) => {
        try {
            const { website, websiteName, username, password, notes, tags, hasTwoFactor } = req.body;
            
            console.log('🔍 Adding password for website:', website);
            
            // Calculate strength and encrypt
            const strengthAnalysis = calculatePasswordStrength(password);
            const encryptedPassword = encrypt(password, ENCRYPTION_KEY);
            
            // Insert entry
            const result = await query(`
                INSERT INTO password_entries 
                (user_id, title, website, website_name, username, encrypted_password, notes, tags, has_two_factor, strength, strength_score) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                req.user.userId,
                websiteName || website,
                website.toLowerCase().replace(/^https?:\/\//, ''),
                websiteName || website,
                username,
                encryptedPassword,
                notes || '',
                JSON.stringify(tags || []),
                hasTwoFactor || false,
                strengthAnalysis.strength,
                strengthAnalysis.score
            ]);
            
            console.log('✅ Password added with ID:', result.insertId);
            
            // Update security score
            await updateUserSecurityScore(req.user.userId);
            
            res.status(201).json({
                message: 'Password saved successfully',
                password: {
                    id: result.insertId,
                    userId: req.user.userId,
                    website: website.toLowerCase().replace(/^https?:\/\//, ''),
                    websiteName: websiteName || website,
                    username,
                    password,
                    notes: notes || '',
                    tags: tags || [],
                    hasTwoFactor: hasTwoFactor || false,
                    strength: strengthAnalysis.strength,
                    strengthScore: strengthAnalysis.score,
                    createdAt: new Date(),
                    lastModified: new Date()
                }
            });
            
        } catch (error) {
            console.error('❌ Add password error:', error);
            res.status(500).json({ error: 'Failed to add password: ' + error.message });
        }
    }
);

// Update password
app.put('/api/vault/:id',
    authenticateToken,
    async (req, res) => {
        try {
            const entryId = req.params.id;
            const updates = req.body;
            
            console.log('🔍 Updating password ID:', entryId);
            
            // Check entry exists
            const entries = await query('SELECT * FROM password_entries WHERE id = ? AND user_id = ?', [entryId, req.user.userId]);
            if (entries.length === 0) {
                return res.status(404).json({ error: 'Password entry not found' });
            }
            
            // Build update query
            let updateQuery = 'UPDATE password_entries SET updated_at = CURRENT_TIMESTAMP';
            let updateParams = [];
            
            if (updates.website) {
                updateQuery += ', website = ?, website_name = ?';
                updateParams.push(updates.website.toLowerCase(), updates.websiteName || updates.website);
            }
            
            if (updates.username) {
                updateQuery += ', username = ?';
                updateParams.push(updates.username);
            }
            
            if (updates.password) {
                const strengthAnalysis = calculatePasswordStrength(updates.password);
                const encryptedPassword = encrypt(updates.password, ENCRYPTION_KEY);
                updateQuery += ', encrypted_password = ?, strength = ?, strength_score = ?';
                updateParams.push(encryptedPassword, strengthAnalysis.strength, strengthAnalysis.score);
            }
            
            if (updates.notes !== undefined) {
                updateQuery += ', notes = ?';
                updateParams.push(updates.notes);
            }
            
            if (updates.tags) {
                updateQuery += ', tags = ?';
                updateParams.push(JSON.stringify(updates.tags));
            }
            
            if (updates.hasTwoFactor !== undefined) {
                updateQuery += ', has_two_factor = ?';
                updateParams.push(updates.hasTwoFactor);
            }
            
            updateQuery += ' WHERE id = ? AND user_id = ?';
            updateParams.push(entryId, req.user.userId);
            
            await query(updateQuery, updateParams);
            
            console.log('✅ Password updated successfully');
            
            // Update security score
            await updateUserSecurityScore(req.user.userId);
            
            // Get updated entry
            const [updatedEntry] = await query('SELECT * FROM password_entries WHERE id = ?', [entryId]);
            
            res.json({
                message: 'Password updated successfully',
                password: {
                    id: updatedEntry.id,
                    userId: updatedEntry.user_id,
                    website: updatedEntry.website,
                    websiteName: updatedEntry.website_name,
                    username: updatedEntry.username,
                    password: updates.password || decrypt(updatedEntry.encrypted_password, ENCRYPTION_KEY),
                    notes: updatedEntry.notes,
                    tags: updatedEntry.tags ? JSON.parse(updatedEntry.tags) : [],
                    hasTwoFactor: updatedEntry.has_two_factor,
                    strength: updatedEntry.strength,
                    strengthScore: updatedEntry.strength_score,
                    createdAt: updatedEntry.created_at,
                    lastModified: updatedEntry.updated_at
                }
            });
            
        } catch (error) {
            console.error('❌ Update password error:', error);
            res.status(500).json({ error: 'Failed to update password: ' + error.message });
        }
    }
);

// Delete password
app.delete('/api/vault/:id', authenticateToken, async (req, res) => {
    try {
        const entryId = req.params.id;
        
        const result = await query('DELETE FROM password_entries WHERE id = ? AND user_id = ?', [entryId, req.user.userId]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Password entry not found' });
        }
        
        console.log('✅ Password deleted successfully');
        
        // Update security score
        await updateUserSecurityScore(req.user.userId);
        
        res.json({ message: 'Password deleted successfully' });
        
    } catch (error) {
        console.error('❌ Delete password error:', error);
        res.status(500).json({ error: 'Failed to delete password: ' + error.message });
    }
});

// QUIZ ROUTES

// Get quiz questions
app.get('/api/quiz/questions', authenticateToken, (req, res) => {
    try {
        const shuffledQuestions = [...quizQuestions].sort(() => Math.random() - 0.5);
        const questionsForClient = shuffledQuestions.map(q => ({
            id: q.id,
            question: q.question,
            options: q.options,
            category: q.category,
            difficulty: q.difficulty
        }));
        
        res.json({ questions: questionsForClient });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get quiz questions' });
    }
});

// Submit quiz
app.post('/api/quiz/submit',
    authenticateToken,
    validateInput([
        body('answers').isArray().withMessage('Answers must be an array'),
        body('timeSpent').isInt({ min: 0 }).withMessage('Time spent must be a positive integer')
    ]),
    async (req, res) => {
        try {
            const { answers, timeSpent } = req.body;
            
            // Calculate score
            let correctAnswers = 0;
            const detailedResults = [];
            
            answers.forEach((userAnswer, index) => {
                const question = quizQuestions[index];
                if (question && userAnswer === question.correctAnswer) {
                    correctAnswers++;
                }
                
                detailedResults.push({
                    questionId: question?.id,
                    userAnswer,
                    correctAnswer: question?.correctAnswer,
                    isCorrect: userAnswer === question?.correctAnswer,
                    explanation: question?.explanation
                });
            });
            
            const score = Math.round((correctAnswers / quizQuestions.length) * 100);
            
            console.log('📊 Quiz score:', score, 'Correct:', correctAnswers);
            
            // Save to MySQL
            const result = await query(`
                INSERT INTO quiz_results (user_id, score, correct_answers, total_questions, answers, time_spent) 
                VALUES (?, ?, ?, ?, ?, ?)
            `, [
                req.user.userId,
                score,
                correctAnswers,
                quizQuestions.length,
                JSON.stringify(detailedResults),
                timeSpent
            ]);
            
            // Update security score
            const bonusPoints = score > 80 ? 10 : score > 60 ? 5 : 2;
            await updateUserSecurityScore(req.user.userId, bonusPoints);
            
            res.json({
                message: 'Quiz completed successfully',
                result: {
                    id: result.insertId,
                    userId: req.user.userId,
                    score,
                    correctAnswers,
                    totalQuestions: quizQuestions.length,
                    answers: detailedResults,
                    timeSpent
                }
            });
            
        } catch (error) {
            console.error('❌ Submit quiz error:', error);
            res.status(500).json({ error: 'Failed to submit quiz: ' + error.message });
        }
    }
);

// SECURITY ROUTES

// Get security tips
app.get('/api/security/tips', authenticateToken, async (req, res) => {
    try {
        const entries = await query('SELECT strength_score FROM password_entries WHERE user_id = ?', [req.user.userId]);
        const personalizedTips = [...securityTips];
        
        if (entries.length === 0) {
            personalizedTips.unshift({
                id: 'first_password',
                title: 'Add Your First Password',
                description: 'Start building your secure vault by adding your first password.',
                category: 'Getting Started',
                importance: 'high'
            });
        } else {
            const weakPasswords = entries.filter(entry => entry.strength_score < 60);
            if (weakPasswords.length > 0) {
                personalizedTips.unshift({
                    id: 'improve_weak',
                    title: 'Improve Weak Passwords',
                    description: `You have ${weakPasswords.length} weak password(s).`,
                    category: 'Password Strength',
                    importance: 'critical'
                });
            }
        }
        
        res.json({ tips: personalizedTips });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to get security tips' });
    }
});

// Get security score
app.get('/api/security/score', authenticateToken, async (req, res) => {
    try {
        const users = await query('SELECT security_score FROM users WHERE id = ?', [req.user.userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const user = users[0];
        const entries = await query('SELECT strength_score, has_two_factor FROM password_entries WHERE user_id = ?', [req.user.userId]);
        const quizResults = await query('SELECT score FROM quiz_results WHERE user_id = ?', [req.user.userId]);
        
        const metrics = {
            totalPasswords: entries.length,
            strongPasswords: entries.filter(entry => entry.strength_score >= 80).length,
            weakPasswords: entries.filter(entry => entry.strength_score < 60).length,
            uniquePasswords: entries.length,
            twoFactorEnabled: entries.filter(entry => entry.has_two_factor).length,
            quizzesTaken: quizResults.length,
            averageQuizScore: quizResults.length > 0 
                ? Math.round(quizResults.reduce((sum, qr) => sum + qr.score, 0) / quizResults.length)
                : 0
        };
        
        res.json({
            securityScore: user.security_score,
            metrics,
            lastUpdated: new Date().toISOString()
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to get security score' });
    }
});

// Check password strength
app.post('/api/security/check-password',
    authenticateToken,
    validateInput([
        body('password').notEmpty().withMessage('Password is required')
    ]),
    (req, res) => {
        try {
            const { password } = req.body;
            const analysis = calculatePasswordStrength(password);
            
            res.json({
                strength: analysis.strength,
                score: analysis.score,
                entropy: analysis.entropy,
                feedback: analysis.feedback
            });
            
        } catch (error) {
            res.status(500).json({ error: 'Failed to check password strength' });
        }
    }
);

// Error handling
app.use((err, req, res, next) => {
    console.error('💥 Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🗃️ Database: MySQL (100% clean - no MongoDB)`);
    console.log(`🎯 Password Manager ready!`);
});

module.exports = app;