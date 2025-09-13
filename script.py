# Create MongoDB integration files for the password manager

# Database connection setup
database_js = """const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/password_manager', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
        
        // Enable mongoose debugging in development
        if (process.env.NODE_ENV === 'development') {
            mongoose.set('debug', true);
        }

        // Handle connection events
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err);
        });

        mongoose.connection.on('disconnected', () => {
            console.log('📤 MongoDB disconnected');
        });

        // Graceful shutdown
        process.on('SIGINT', async () => {
            await mongoose.connection.close();
            console.log('📤 MongoDB connection closed through app termination');
            process.exit(0);
        });

    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        process.exit(1);
    }
};

module.exports = connectDB;
"""

# User Model
user_model_js = """const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\\w+([\\.-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$/, 'Please enter a valid email']
    },
    passwordHash: {
        type: String,
        required: [true, 'Password hash is required'],
        minlength: 60 // bcrypt hash length
    },
    securityScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    recoveryKey: {
        type: String,
        default: null
    },
    mfaEnabled: {
        type: Boolean,
        default: false
    },
    mfaSecret: {
        type: String,
        default: null
    },
    preferences: {
        theme: {
            type: String,
            enum: ['light', 'dark'],
            default: 'light'
        },
        notifications: {
            type: Boolean,
            default: true
        },
        autoLock: {
            type: Number,
            default: 300 // seconds
        }
    },
    lastLogin: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true // This adds createdAt and updatedAt automatically
});

// Index for email lookups
userSchema.index({ email: 1 });

// Virtual for password entries count
userSchema.virtual('passwordCount', {
    ref: 'Vault',
    localField: '_id',
    foreignField: 'userId',
    count: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('passwordHash')) return next();
    
    try {
        // Hash password with cost of 12
        const saltRounds = 12;
        this.passwordHash = await bcrypt.hash(this.passwordHash, saltRounds);
        next();
    } catch (error) {
        next(error);
    }
});

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.passwordHash);
    } catch (error) {
        throw new Error('Password comparison failed');
    }
};

// Instance method to update last login
userSchema.methods.updateLastLogin = function() {
    this.lastLogin = new Date();
    return this.save();
};

// Static method to find by email
userSchema.statics.findByEmail = function(email) {
    return this.findOne({ email: email.toLowerCase() });
};

// Remove sensitive data when converting to JSON
userSchema.methods.toJSON = function() {
    const userObject = this.toObject();
    delete userObject.passwordHash;
    delete userObject.mfaSecret;
    delete userObject.recoveryKey;
    return userObject;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
"""

# Vault Model
vault_model_js = """const mongoose = require('mongoose');

const vaultEntrySchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Title is required'],
        trim: true,
        maxlength: [100, 'Title cannot exceed 100 characters']
    },
    website: {
        type: String,
        required: [true, 'Website is required'],
        trim: true,
        lowercase: true
    },
    websiteName: {
        type: String,
        trim: true,
        maxlength: [100, 'Website name cannot exceed 100 characters']
    },
    username: {
        type: String,
        required: [true, 'Username is required'],
        trim: true,
        maxlength: [200, 'Username cannot exceed 200 characters']
    },
    encryptedPassword: {
        type: String,
        required: [true, 'Encrypted password is required']
    },
    url: {
        type: String,
        trim: true,
        validate: {
            validator: function(v) {
                if (!v) return true; // Allow empty URLs
                return /^https?:\\/\\/.+/.test(v);
            },
            message: 'URL must be a valid http or https URL'
        }
    },
    notes: {
        type: String,
        maxlength: [500, 'Notes cannot exceed 500 characters'],
        default: ''
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: [30, 'Tag cannot exceed 30 characters']
    }],
    hasTwoFactor: {
        type: Boolean,
        default: false
    },
    strength: {
        type: String,
        enum: ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'],
        default: 'Fair'
    },
    strengthScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    isFavorite: {
        type: Boolean,
        default: false
    },
    lastUsed: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

const vaultSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required']
    },
    entries: [vaultEntrySchema]
}, {
    timestamps: true
});

// Index for user lookups
vaultSchema.index({ userId: 1 });

// Index for searching entries
vaultSchema.index({ 'entries.title': 'text', 'entries.website': 'text', 'entries.username': 'text' });

// Virtual for entries count
vaultSchema.virtual('entriesCount').get(function() {
    return this.entries.length;
});

// Instance method to add entry
vaultSchema.methods.addEntry = function(entryData) {
    this.entries.push(entryData);
    return this.save();
};

// Instance method to update entry
vaultSchema.methods.updateEntry = function(entryId, updateData) {
    const entry = this.entries.id(entryId);
    if (entry) {
        Object.assign(entry, updateData);
        return this.save();
    }
    throw new Error('Entry not found');
};

// Instance method to remove entry
vaultSchema.methods.removeEntry = function(entryId) {
    const entry = this.entries.id(entryId);
    if (entry) {
        entry.remove();
        return this.save();
    }
    throw new Error('Entry not found');
};

// Instance method to find entry
vaultSchema.methods.findEntry = function(entryId) {
    return this.entries.id(entryId);
};

// Static method to find vault by user ID
vaultSchema.statics.findByUserId = function(userId) {
    return this.findOne({ userId });
};

// Static method to create vault for user
vaultSchema.statics.createForUser = function(userId) {
    return this.create({ userId, entries: [] });
};

const Vault = mongoose.model('Vault', vaultSchema);

module.exports = Vault;
"""

# MFA Model
mfa_model_js = """const mongoose = require('mongoose');

const mfaSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required'],
        unique: true
    },
    isEnabled: {
        type: Boolean,
        default: false
    },
    otpSecret: {
        type: String,
        default: null
    },
    backupCodes: [{
        code: {
            type: String,
            required: true
        },
        used: {
            type: Boolean,
            default: false
        },
        usedAt: {
            type: Date,
            default: null
        }
    }],
    emailVerified: {
        type: Boolean,
        default: false
    },
    phoneNumber: {
        type: String,
        default: null,
        validate: {
            validator: function(v) {
                if (!v) return true; // Allow null/empty phone numbers
                return /^\\+?[1-9]\\d{1,14}$/.test(v); // E.164 format
            },
            message: 'Phone number must be in valid international format'
        }
    },
    phoneVerified: {
        type: Boolean,
        default: false
    },
    preferredMethod: {
        type: String,
        enum: ['app', 'sms', 'email'],
        default: 'app'
    },
    lastVerification: {
        type: Date,
        default: null
    },
    failedAttempts: {
        type: Number,
        default: 0
    },
    lockedUntil: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

// Index for user lookups
mfaSchema.index({ userId: 1 });

// Virtual to check if account is locked
mfaSchema.virtual('isLocked').get(function() {
    return !!(this.lockedUntil && this.lockedUntil > Date.now());
});

// Instance method to enable MFA
mfaSchema.methods.enable = function(secret) {
    this.isEnabled = true;
    this.otpSecret = secret;
    this.failedAttempts = 0;
    this.lockedUntil = null;
    return this.save();
};

// Instance method to disable MFA
mfaSchema.methods.disable = function() {
    this.isEnabled = false;
    this.otpSecret = null;
    this.backupCodes = [];
    this.failedAttempts = 0;
    this.lockedUntil = null;
    return this.save();
};

// Instance method to record failed attempt
mfaSchema.methods.recordFailedAttempt = function() {
    this.failedAttempts += 1;
    
    // Lock account after 5 failed attempts for 30 minutes
    if (this.failedAttempts >= 5) {
        this.lockedUntil = Date.now() + 30 * 60 * 1000; // 30 minutes
    }
    
    return this.save();
};

// Instance method to record successful verification
mfaSchema.methods.recordSuccessfulVerification = function() {
    this.lastVerification = new Date();
    this.failedAttempts = 0;
    this.lockedUntil = null;
    return this.save();
};

// Instance method to generate backup codes
mfaSchema.methods.generateBackupCodes = function(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        codes.push({ code });
    }
    this.backupCodes = codes;
    return this.save();
};

// Instance method to use backup code
mfaSchema.methods.useBackupCode = function(code) {
    const backupCode = this.backupCodes.find(bc => bc.code === code && !bc.used);
    if (backupCode) {
        backupCode.used = true;
        backupCode.usedAt = new Date();
        return this.save();
    }
    return false;
};

// Static method to find by user ID
mfaSchema.statics.findByUserId = function(userId) {
    return this.findOne({ userId });
};

// Static method to create for user
mfaSchema.statics.createForUser = function(userId) {
    return this.create({ userId });
};

const MFA = mongoose.model('MFA', mfaSchema);

module.exports = MFA;
"""

# Quiz Result Model
quiz_model_js = """const mongoose = require('mongoose');

const quizAnswerSchema = new mongoose.Schema({
    questionId: {
        type: Number,
        required: true
    },
    userAnswer: {
        type: Number,
        required: true
    },
    correctAnswer: {
        type: Number,
        required: true
    },
    isCorrect: {
        type: Boolean,
        required: true
    },
    timeSpent: {
        type: Number, // seconds spent on this question
        default: 0
    }
}, { _id: false });

const quizResultSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required']
    },
    quizType: {
        type: String,
        enum: ['cybersecurity_basics', 'password_security', 'advanced_security'],
        default: 'cybersecurity_basics'
    },
    score: {
        type: Number,
        required: true,
        min: 0,
        max: 100
    },
    correctAnswers: {
        type: Number,
        required: true,
        min: 0
    },
    totalQuestions: {
        type: Number,
        required: true,
        min: 1
    },
    answers: [quizAnswerSchema],
    timeSpent: {
        type: Number, // total time in seconds
        required: true,
        min: 0
    },
    passed: {
        type: Boolean,
        default: function() {
            return this.score >= 70; // 70% passing score
        }
    },
    retakeCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Index for user lookups
quizResultSchema.index({ userId: 1 });
quizResultSchema.index({ userId: 1, quizType: 1 });

// Virtual for percentage score
quizResultSchema.virtual('percentage').get(function() {
    return Math.round((this.correctAnswers / this.totalQuestions) * 100);
});

// Instance method to check if quiz was passed
quizResultSchema.methods.isPassed = function() {
    return this.score >= 70;
};

// Static method to get user's best score for a quiz type
quizResultSchema.statics.getBestScore = function(userId, quizType = 'cybersecurity_basics') {
    return this.findOne({ userId, quizType })
        .sort({ score: -1 })
        .limit(1);
};

// Static method to get user's quiz history
quizResultSchema.statics.getUserHistory = function(userId, limit = 10) {
    return this.find({ userId })
        .sort({ createdAt: -1 })
        .limit(limit);
};

// Static method to get average score for a user
quizResultSchema.statics.getUserAverageScore = async function(userId) {
    const results = await this.aggregate([
        { $match: { userId: mongoose.Types.ObjectId(userId) } },
        { $group: { _id: null, averageScore: { $avg: '$score' } } }
    ]);
    
    return results.length > 0 ? Math.round(results[0].averageScore) : 0;
};

const QuizResult = mongoose.model('QuizResult', quizResultSchema);

module.exports = QuizResult;
"""

# Models index file
models_index_js = """const User = require('./User');
const Vault = require('./Vault');
const MFA = require('./MFA');
const QuizResult = require('./QuizResult');

module.exports = {
    User,
    Vault,
    MFA,
    QuizResult
};
"""

# Updated server.js with MongoDB integration
updated_server_js = """const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const CryptoJS = require('crypto-js');
const mongoose = require('mongoose');
require('dotenv').config();

// Import database connection and models
const connectDB = require('./config/database');
const { User, Vault, MFA, QuizResult } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-encryption-key-32-chars-long!';

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 auth requests per windowMs
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// Encryption utilities
const encrypt = (text, key) => {
    return CryptoJS.AES.encrypt(text, key).toString();
};

const decrypt = (cipherText, key) => {
    const bytes = CryptoJS.AES.decrypt(cipherText, key);
    return bytes.toString(CryptoJS.enc.Utf8);
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
    
    // Length scoring
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
    
    // Character variety
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\\d/.test(password);
    const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    score += variety * 10;
    
    // Entropy calculation
    let charset = 0;
    if (hasLower) charset += 26;
    if (hasUpper) charset += 26;
    if (hasNumber) charset += 10;
    if (hasSymbol) charset += 32;
    
    const entropy = length * Math.log2(charset);
    score += Math.min(entropy / 2, 25);
    
    // Common password penalty
    const commonPasswords = ['password', '123456', 'qwerty', 'admin'];
    if (commonPasswords.includes(password.toLowerCase())) {
        score -= 50;
        feedback.push('This is a commonly used password. Choose something unique.');
    }
    
    // Sequential pattern penalty
    const sequential = ['123', 'abc', 'qwe'];
    if (sequential.some(pattern => password.toLowerCase().includes(pattern))) {
        score -= 20;
        feedback.push('Avoid sequential characters or numbers.');
    }
    
    const finalScore = Math.min(Math.max(score, 0), 100);
    let strength = 'Very Weak';
    
    if (finalScore >= 80) strength = 'Very Strong';
    else if (finalScore >= 60) strength = 'Strong';
    else if (finalScore >= 40) strength = 'Good';
    else if (finalScore >= 20) strength = 'Fair';
    else if (finalScore >= 10) strength = 'Weak';
    
    return {
        score: finalScore,
        strength,
        feedback,
        entropy: Math.round(entropy * 100) / 100
    };
};

// Quiz questions data
const quizQuestions = [
    {
        id: 1,
        question: "What is the minimum recommended length for a secure password in 2024?",
        options: ["8 characters", "10 characters", "12 characters", "16 characters"],
        correctAnswer: 2,
        explanation: "Security experts now recommend at least 12 characters for passwords, with longer being even better.",
        category: "Password Security",
        difficulty: "easy"
    },
    {
        id: 2,
        question: "Which is the most secure way to store passwords?",
        options: ["Browser's built-in manager", "Written on paper", "Dedicated password manager", "Memorize all passwords"],
        correctAnswer: 2,
        explanation: "Dedicated password managers use strong encryption and provide the best security for password storage.",
        category: "Password Management",
        difficulty: "easy"
    },
    {
        id: 3,
        question: "What does two-factor authentication (2FA) provide?",
        options: ["Backup password", "Additional security layer", "Password encryption", "Account recovery"],
        correctAnswer: 1,
        explanation: "2FA adds an extra layer of security beyond just your password, making accounts much harder to compromise.",
        category: "Authentication",
        difficulty: "medium"
    },
    {
        id: 4,
        question: "How often should you change your passwords?",
        options: ["Every month", "Every 3 months", "Only when compromised", "Every year"],
        correctAnswer: 2,
        explanation: "Modern security practices recommend changing passwords only when there's evidence of compromise.",
        category: "Password Management",
        difficulty: "medium"
    },
    {
        id: 5,
        question: "What is a phishing attack?",
        options: ["Malware infection", "Fraudulent credential theft", "Network intrusion", "Data encryption"],
        correctAnswer: 1,
        explanation: "Phishing involves tricking users into revealing credentials through fake websites, emails, or messages.",
        category: "Cyber Threats",
        difficulty: "easy"
    }
];

// Security tips data
const securityTips = [
    {
        id: 1,
        title: "Use Unique Passwords Everywhere",
        description: "Each account should have its own unique password. Password reuse is one of the biggest security risks.",
        category: "Password Hygiene",
        importance: "critical"
    },
    {
        id: 2,
        title: "Enable Two-Factor Authentication",
        description: "Add an extra layer of security by enabling 2FA on all important accounts.",
        category: "Authentication",
        importance: "high"
    },
    {
        id: 3,
        title: "Regular Security Checkups",
        description: "Review your accounts monthly and remove access to unused services.",
        category: "Account Management",
        importance: "medium"
    },
    {
        id: 4,
        title: "Beware of Phishing Attempts",
        description: "Always verify the sender and URL before clicking links or entering credentials.",
        category: "Threat Awareness",
        importance: "critical"
    }
];

// Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
    });
});

// Authentication Routes

// Sign up
app.post('/api/auth/signup', 
    validateInput([
        body('email').isEmail().normalizeEmail(),
        body('masterPassword').isLength({ min: 8 }).withMessage('Master password must be at least 8 characters long')
    ]),
    async (req, res) => {
        try {
            const { email, masterPassword } = req.body;
            
            // Check if user already exists
            const existingUser = await User.findByEmail(email);
            if (existingUser) {
                return res.status(409).json({ error: 'User already exists' });
            }
            
            // Calculate initial security score
            const passwordStrength = calculatePasswordStrength(masterPassword);
            
            // Create new user (password will be hashed by the pre-save hook)
            const newUser = new User({
                email,
                passwordHash: masterPassword, // Will be hashed by pre-save hook
                securityScore: Math.round(passwordStrength.score * 0.3) // Initial score based on master password
            });
            
            await newUser.save();
            
            // Create empty vault for user
            await Vault.createForUser(newUser._id);
            
            // Create MFA record for user
            await MFA.createForUser(newUser._id);
            
            // Generate JWT token
            const token = jwt.sign(
                { userId: newUser._id, email: newUser.email },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            res.status(201).json({
                message: 'User created successfully',
                user: newUser.toJSON(),
                token
            });
            
        } catch (error) {
            console.error('Signup error:', error);
            if (error.code === 11000) {
                return res.status(409).json({ error: 'Email already exists' });
            }
            res.status(500).json({ error: 'Internal server error' });
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
        try {
            const { email, masterPassword } = req.body;
            
            // Find user
            const user = await User.findByEmail(email);
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Verify password
            const isValidPassword = await user.comparePassword(masterPassword);
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Update last login
            await user.updateLastLogin();
            
            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id, email: user.email },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            res.json({
                message: 'Login successful',
                user: user.toJSON(),
                token
            });
            
        } catch (error) {
            console.error('Signin error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Password Vault Routes

// Get all passwords for user
app.get('/api/vault', authenticateToken, async (req, res) => {
    try {
        const vault = await Vault.findByUserId(req.user.userId);
        
        if (!vault) {
            return res.json({ passwords: [], count: 0 });
        }
        
        // Decrypt passwords for response
        const passwords = vault.entries.map(entry => {
            const decryptedPassword = decrypt(entry.encryptedPassword, ENCRYPTION_KEY);
            return {
                id: entry._id,
                userId: vault.userId,
                website: entry.website,
                websiteName: entry.websiteName,
                username: entry.username,
                password: decryptedPassword,
                notes: entry.notes,
                tags: entry.tags,
                hasTwoFactor: entry.hasTwoFactor,
                strength: entry.strength,
                strengthScore: entry.strengthScore,
                isFavorite: entry.isFavorite,
                createdAt: entry.createdAt,
                lastModified: entry.updatedAt,
                lastUsed: entry.lastUsed
            };
        });
        
        res.json({
            passwords,
            count: passwords.length
        });
        
    } catch (error) {
        console.error('Get passwords error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add new password
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
            
            // Calculate password strength
            const strengthAnalysis = calculatePasswordStrength(password);
            
            // Encrypt password
            const encryptedPassword = encrypt(password, ENCRYPTION_KEY);
            
            // Find or create vault for user
            let vault = await Vault.findByUserId(req.user.userId);
            if (!vault) {
                vault = await Vault.createForUser(req.user.userId);
            }
            
            // Create new password entry
            const newEntry = {
                title: websiteName || website,
                website: website.toLowerCase().replace(/^https?:\\/\\//, ''),
                websiteName: websiteName || website,
                username,
                encryptedPassword,
                notes: notes || '',
                tags: tags || [],
                hasTwoFactor: hasTwoFactor || false,
                strength: strengthAnalysis.strength,
                strengthScore: strengthAnalysis.score
            };
            
            await vault.addEntry(newEntry);
            
            // Update user's security score
            await updateUserSecurityScore(req.user.userId);
            
            // Get the newly added entry
            const addedEntry = vault.entries[vault.entries.length - 1];
            
            // Return password info (with decrypted password)
            const responsePassword = {
                id: addedEntry._id,
                userId: vault.userId,
                website: addedEntry.website,
                websiteName: addedEntry.websiteName,
                username: addedEntry.username,
                password,
                notes: addedEntry.notes,
                tags: addedEntry.tags,
                hasTwoFactor: addedEntry.hasTwoFactor,
                strength: addedEntry.strength,
                strengthScore: addedEntry.strengthScore,
                createdAt: addedEntry.createdAt,
                lastModified: addedEntry.updatedAt
            };
            
            res.status(201).json({
                message: 'Password saved successfully',
                password: responsePassword
            });
            
        } catch (error) {
            console.error('Add password error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Update password
app.put('/api/vault/:id',
    authenticateToken,
    validateInput([
        body('website').optional().notEmpty(),
        body('username').optional().notEmpty(),
        body('password').optional().notEmpty()
    ]),
    async (req, res) => {
        try {
            const entryId = req.params.id;
            const updates = req.body;
            
            // Find vault
            const vault = await Vault.findByUserId(req.user.userId);
            if (!vault) {
                return res.status(404).json({ error: 'Vault not found' });
            }
            
            // Find entry
            const entry = vault.findEntry(entryId);
            if (!entry) {
                return res.status(404).json({ error: 'Password entry not found' });
            }
            
            // Process updates
            if (updates.password) {
                // Re-encrypt new password
                updates.encryptedPassword = encrypt(updates.password, ENCRYPTION_KEY);
                
                // Recalculate strength
                const strengthAnalysis = calculatePasswordStrength(updates.password);
                updates.strength = strengthAnalysis.strength;
                updates.strengthScore = strengthAnalysis.score;
            }
            
            if (updates.website) {
                updates.website = updates.website.toLowerCase().replace(/^https?:\\/\\//, '');
            }
            
            // Apply updates
            await vault.updateEntry(entryId, updates);
            
            // Update user's security score
            await updateUserSecurityScore(req.user.userId);
            
            // Return updated password (with decrypted password)
            const updatedEntry = vault.findEntry(entryId);
            const responsePassword = {
                id: updatedEntry._id,
                userId: vault.userId,
                website: updatedEntry.website,
                websiteName: updatedEntry.websiteName,
                username: updatedEntry.username,
                password: updates.password ? updates.password : decrypt(updatedEntry.encryptedPassword, ENCRYPTION_KEY),
                notes: updatedEntry.notes,
                tags: updatedEntry.tags,
                hasTwoFactor: updatedEntry.hasTwoFactor,
                strength: updatedEntry.strength,
                strengthScore: updatedEntry.strengthScore,
                createdAt: updatedEntry.createdAt,
                lastModified: updatedEntry.updatedAt
            };
            
            res.json({
                message: 'Password updated successfully',
                password: responsePassword
            });
            
        } catch (error) {
            console.error('Update password error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Delete password
app.delete('/api/vault/:id', authenticateToken, async (req, res) => {
    try {
        const entryId = req.params.id;
        
        // Find vault
        const vault = await Vault.findByUserId(req.user.userId);
        if (!vault) {
            return res.status(404).json({ error: 'Vault not found' });
        }
        
        // Remove entry
        await vault.removeEntry(entryId);
        
        // Update user's security score
        await updateUserSecurityScore(req.user.userId);
        
        res.json({ message: 'Password deleted successfully' });
        
    } catch (error) {
        console.error('Delete password error:', error);
        if (error.message === 'Entry not found') {
            return res.status(404).json({ error: 'Password entry not found' });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Educational Routes

// Get quiz questions
app.get('/api/quiz/questions', authenticateToken, (req, res) => {
    try {
        // Shuffle questions for variety
        const shuffledQuestions = [...quizQuestions].sort(() => Math.random() - 0.5);
        
        // Remove correct answers from response
        const questionsForClient = shuffledQuestions.map(q => ({
            id: q.id,
            question: q.question,
            options: q.options,
            category: q.category,
            difficulty: q.difficulty
        }));
        
        res.json({ questions: questionsForClient });
        
    } catch (error) {
        console.error('Get quiz questions error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Submit quiz answers
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
            
            // Save quiz result to database
            const quizResult = new QuizResult({
                userId: req.user.userId,
                score,
                correctAnswers,
                totalQuestions: quizQuestions.length,
                answers: detailedResults,
                timeSpent
            });
            
            await quizResult.save();
            
            // Update user's security score (bonus for taking quiz)
            const bonusPoints = score > 80 ? 10 : score > 60 ? 5 : 2;
            await updateUserSecurityScore(req.user.userId, bonusPoints);
            
            res.json({
                message: 'Quiz completed successfully',
                result: quizResult
            });
            
        } catch (error) {
            console.error('Submit quiz error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Get security tips
app.get('/api/security/tips', authenticateToken, async (req, res) => {
    try {
        // Get personalized tips based on user's password vault
        const vault = await Vault.findByUserId(req.user.userId);
        const personalizedTips = [...securityTips];
        
        // Add context-specific tips
        if (!vault || vault.entries.length === 0) {
            personalizedTips.unshift({
                id: 'first_password',
                title: 'Add Your First Password',
                description: 'Start building your secure vault by adding your first password.',
                category: 'Getting Started',
                importance: 'high'
            });
        } else {
            const weakPasswords = vault.entries.filter(entry => entry.strengthScore < 60);
            if (weakPasswords.length > 0) {
                personalizedTips.unshift({
                    id: 'improve_weak',
                    title: 'Improve Weak Passwords',
                    description: `You have ${weakPasswords.length} weak password(s). Consider updating them for better security.`,
                    category: 'Password Strength',
                    importance: 'critical'
                });
            }
        }
        
        res.json({ tips: personalizedTips });
        
    } catch (error) {
        console.error('Get security tips error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user security score
app.get('/api/security/score', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const vault = await Vault.findByUserId(req.user.userId);
        const quizResults = await QuizResult.find({ userId: req.user.userId });
        
        // Calculate detailed security metrics
        const entries = vault ? vault.entries : [];
        const metrics = {
            totalPasswords: entries.length,
            strongPasswords: entries.filter(entry => entry.strengthScore >= 80).length,
            weakPasswords: entries.filter(entry => entry.strengthScore < 60).length,
            uniquePasswords: entries.length, // In real app, check for duplicates
            twoFactorEnabled: entries.filter(entry => entry.hasTwoFactor).length,
            quizzesTaken: quizResults.length,
            averageQuizScore: quizResults.length > 0 
                ? Math.round(quizResults.reduce((sum, qr) => sum + qr.score, 0) / quizResults.length)
                : 0
        };
        
        res.json({
            securityScore: user.securityScore,
            metrics,
            lastUpdated: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Get security score error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Password strength check endpoint
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
            console.error('Check password error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Utility Functions

async function updateUserSecurityScore(userId, bonusPoints = 0) {
    try {
        const user = await User.findById(userId);
        if (!user) return;
        
        const vault = await Vault.findByUserId(userId);
        const quizResults = await QuizResult.find({ userId });
        
        let score = 0;
        const entries = vault ? vault.entries : [];
        
        // Base score from password strength (40% of total)
        if (entries.length > 0) {
            const avgStrength = entries.reduce((sum, entry) => sum + entry.strengthScore, 0) / entries.length;
            score += (avgStrength * 0.4);
        }
        
        // Bonus for having passwords (20% of total)
        if (entries.length > 0) {
            score += Math.min(entries.length * 5, 20);
        }
        
        // Bonus for 2FA usage (15% of total)
        const twoFactorCount = entries.filter(entry => entry.hasTwoFactor).length;
        if (twoFactorCount > 0) {
            score += Math.min(twoFactorCount * 3, 15);
        }
        
        // Bonus for quiz completion (15% of total)
        if (quizResults.length > 0) {
            const avgQuizScore = quizResults.reduce((sum, qr) => sum + qr.score, 0) / quizResults.length;
            score += (avgQuizScore * 0.15);
        }
        
        // Educational bonus (10% of total)
        score += bonusPoints;
        
        user.securityScore = Math.min(Math.round(score), 100);
        await user.save();
    
    } catch (error) {
        console.error('Update security score error:', error);
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📚 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔒 CORS enabled for: ${process.env.FRONTEND_URL || 'http://localhost:3001'}`);
});

module.exports = app;
"""

# Updated package.json with MongoDB dependencies
updated_package_json = """{
  "name": "secure-password-manager-backend",
  "version": "1.0.0",
  "description": "Backend API for student password manager with educational features and MongoDB integration",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "seed": "node scripts/seed.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "express-validator": "^7.0.1",
    "crypto-js": "^4.1.1",
    "dotenv": "^16.3.1",
    "uuid": "^9.0.0",
    "mongoose": "^7.5.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  },
  "keywords": [
    "password-manager",
    "cybersecurity",
    "education",
    "student",
    "api",
    "mongodb",
    "mongoose"
  ],
  "author": "Student Developer",
  "license": "MIT"
}"""

# Updated .env file
updated_env_file = """# Environment Variables
NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:3001

# Security Keys (CHANGE THESE IN PRODUCTION!)
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-make-it-very-long-and-random
ENCRYPTION_KEY=your-encryption-key-32-chars-long!

# MongoDB Configuration
# For local MongoDB installation:
MONGODB_URI=mongodb://localhost:27017/password_manager

# For MongoDB Atlas (cloud):
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/password_manager?retryWrites=true&w=majority

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=5
"""

# Save all files
files_created = []

# Create config directory structure
import os
os.makedirs('config', exist_ok=True)
os.makedirs('models', exist_ok=True)

with open('config/database.js', 'w') as f:
    f.write(database_js)
files_created.append('config/database.js')

with open('models/User.js', 'w') as f:
    f.write(user_model_js)
files_created.append('models/User.js')

with open('models/Vault.js', 'w') as f:
    f.write(vault_model_js)
files_created.append('models/Vault.js')

with open('models/MFA.js', 'w') as f:
    f.write(mfa_model_js)
files_created.append('models/MFA.js')

with open('models/QuizResult.js', 'w') as f:
    f.write(quiz_model_js)
files_created.append('models/QuizResult.js')

with open('models/index.js', 'w') as f:
    f.write(models_index_js)
files_created.append('models/index.js')

# Update existing files
with open('server.js', 'w') as f:
    f.write(updated_server_js)
files_created.append('server.js (updated)')

with open('package.json', 'w') as f:
    f.write(updated_package_json)
files_created.append('package.json (updated)')

with open('.env', 'w') as f:
    f.write(updated_env_file)
files_created.append('.env (updated)')

print("MongoDB integration files created successfully!")
print("Files created/updated:")
for file in files_created:
    print(f"- {file}")