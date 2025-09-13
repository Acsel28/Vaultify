// Application State
class PasswordManagerApp {
    constructor() {
        this.currentUser = null;
        this.currentScreen = 'loading';
        this.currentTab = 'vault';
        this.passwordEntries = [];
        this.editingPasswordId = null;
        this.quizData = {
            questions: [],
            currentQuestion: 0,
            userAnswers: [],
            score: 0,
            isComplete: false
        };
        
        // Common passwords for dictionary check
        this.commonPasswords = new Set([
            "password", "123456", "123456789", "12345678", "12345", "1234567", "qwerty", "abc123", "Password", "password1",
            "admin", "123123", "welcome", "login", "guest", "hello", "1234", "letmein", "pass", "monkey",
            "dragon", "master", "shadow", "superman", "michael", "internet", "computer", "123321", "test", "princess",
            "qwerty123", "password123", "1234567890", "12345678910", "000000", "iloveyou", "1q2w3e4r", "qwertyuiop",
            "123qwe", "zxcvbnm", "asdfgh", "qwerty1", "123456a", "password1234", "qwerty12", "football"
        ]);

        // Sequential patterns
        this.sequentialPatterns = [
            "abcdefghijklmnopqrstuvwxyz",
            "qwertyuiopasdfghjklzxcvbnm",
            "1234567890",
            "0987654321"
        ];
        
        // Mock data
        this.mockUsers = [
            {
                id: 1,
                email: "demo@student.edu",
                masterPasswordHash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeL/NYy4TZ7qT85NK",
                createdAt: "2024-01-01",
                securityScore: 85
            }
        ];

        this.mockPasswordEntries = [
            {
                id: 1,
                userId: 1,
                website: "github.com",
                websiteName: "GitHub",
                username: "student123",
                encryptedPassword: "StrongPass123!@#",
                notes: "Work account for coding projects",
                createdAt: "2024-01-01",
                lastModified: "2024-01-01",
                strength: "Strong",
                strengthScore: 85
            },
            {
                id: 2,
                userId: 1,
                website: "gmail.com",
                websiteName: "Gmail",
                username: "student@example.com",
                encryptedPassword: "SecureEmail2024$",
                notes: "Primary email account",
                createdAt: "2024-01-02",
                lastModified: "2024-01-02",
                strength: "Very Strong",
                strengthScore: 92
            },
            {
                id: 3,
                userId: 1,
                website: "netflix.com",
                websiteName: "Netflix",
                username: "student123",
                encryptedPassword: "MovieNight456!",
                notes: "Streaming service",
                createdAt: "2024-01-03",
                lastModified: "2024-01-03",
                strength: "Strong",
                strengthScore: 78
            }
        ];

        this.quizQuestions = [
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
            },
            {
                id: 6,
                question: "Which password is stronger?",
                options: ["P@ssw0rd123", "MyDogNamedMax!", "correct-horse-battery-staple", "Tr0ub4dor&3"],
                correctAnswer: 2,
                explanation: "Long passphrases with random words are typically stronger and easier to remember than complex short passwords.",
                category: "Password Security",
                difficulty: "hard"
            },
            {
                id: 7,
                question: "What should you do if you receive a suspicious email asking for login credentials?",
                options: ["Reply with credentials", "Click the link to verify", "Delete the email", "Forward to IT security"],
                correctAnswer: 2,
                explanation: "Suspicious emails requesting credentials should be deleted. Legitimate companies never ask for passwords via email.",
                category: "Cyber Threats",
                difficulty: "easy"
            },
            {
                id: 8,
                question: "What is the purpose of password entropy?",
                options: ["Password complexity", "Randomness measurement", "Encryption strength", "All of the above"],
                correctAnswer: 3,
                explanation: "Password entropy measures randomness, which directly relates to complexity and effective encryption strength.",
                category: "Password Security",
                difficulty: "hard"
            }
        ];

        this.securityTips = [
            {
                id: 1,
                title: "Use Unique Passwords Everywhere",
                description: "Each account should have its own unique password. Password reuse is one of the biggest security risks.",
                category: "Password Hygiene",
                importance: "critical",
                icon: "fas fa-key"
            },
            {
                id: 2,
                title: "Enable Two-Factor Authentication",
                description: "Add an extra layer of security by enabling 2FA on all important accounts.",
                category: "Authentication",
                importance: "high",
                icon: "fas fa-shield-alt"
            },
            {
                id: 3,
                title: "Regular Security Checkups",
                description: "Review your accounts monthly and remove access to unused services.",
                category: "Account Management",
                importance: "medium",
                icon: "fas fa-search"
            },
            {
                id: 4,
                title: "Beware of Phishing Attempts",
                description: "Always verify the sender and URL before clicking links or entering credentials.",
                category: "Threat Awareness",
                importance: "critical",
                icon: "fas fa-exclamation-triangle"
            }
        ];

        // Initialize when DOM is ready
        this.init();
    }

    init() {
        console.log('Initializing PasswordManagerApp');
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setupEventListeners();
                this.loadUserData();
                setTimeout(() => this.showAuthScreen(), 1500);
            });
        } else {
            this.setupEventListeners();
            this.loadUserData();
            setTimeout(() => this.showAuthScreen(), 1500);
        }
    }

    setupEventListeners() {
        console.log('Setting up event listeners');
        
        // Authentication forms
        const loginForm = document.getElementById('loginForm');
        const signupForm = document.getElementById('signupForm');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                console.log('Login form submitted');
                this.handleLogin(e);
            });
        }
        
        if (signupForm) {
            signupForm.addEventListener('submit', (e) => {
                e.preventDefault();
                console.log('Signup form submitted');
                this.handleSignup(e);
            });
        }

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.logout();
            });
        }

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tabName = e.currentTarget.id.replace('nav-', '');
                this.switchTab(tabName);
            });
        });

        // Password management
        const addPasswordBtn = document.getElementById('add-password-btn');
        const addPasswordForm = document.getElementById('add-password-form');
        const cancelAddBtn = document.getElementById('cancel-add-btn');

        if (addPasswordBtn) {
            addPasswordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.switchTab('add');
            });
        }
        
        if (addPasswordForm) {
            addPasswordForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleSavePassword(e);
            });
        }
        
        if (cancelAddBtn) {
            cancelAddBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.cancelAddPassword();
            });
        }

        // Password generator
        const generatePasswordBtn = document.getElementById('generate-password-btn');
        const regenerateBtn = document.getElementById('regenerate-btn');
        const copyGeneratedBtn = document.getElementById('copy-generated-btn');

        if (generatePasswordBtn) {
            generatePasswordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.generatePasswordForForm();
            });
        }
        
        if (regenerateBtn) {
            regenerateBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.generatePassword();
            });
        }
        
        if (copyGeneratedBtn) {
            copyGeneratedBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.copyGeneratedPassword();
            });
        }
        
        // Generator options
        const passwordLengthSlider = document.getElementById('password-length');
        if (passwordLengthSlider) {
            passwordLengthSlider.addEventListener('input', (e) => this.updatePasswordLength(e));
        }

        document.querySelectorAll('.generator-options input[type="checkbox"]').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.generatePassword());
        });

        // Password strength checking with real-time updates
        const signupPassword = document.getElementById('signupPassword');
        const passwordInput = document.getElementById('password');
        const newPasswordInput = document.getElementById('new-password');

        if (signupPassword) {
            signupPassword.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value, 'password-strength-indicator');
            });
        }
        
        if (passwordInput) {
            passwordInput.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value, 'add-password-strength');
            });
        }
        
        if (newPasswordInput) {
            newPasswordInput.addEventListener('input', (e) => {
                this.checkPasswordStrength(e.target.value, 'new-password-strength');
            });
        }

        // Search with debouncing
        const vaultSearch = document.getElementById('vault-search');
        if (vaultSearch) {
            let searchTimeout;
            vaultSearch.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => this.searchVault(e.target.value), 300);
            });
        }

        // Quiz
        const quizSubmitBtn = document.getElementById('quiz-submit-btn');
        const nextQuestionBtn = document.getElementById('next-question-btn');
        const retakeQuizBtn = document.getElementById('retake-quiz-btn');

        if (quizSubmitBtn) {
            quizSubmitBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.submitQuizAnswer();
            });
        }
        
        if (nextQuestionBtn) {
            nextQuestionBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.nextQuestion();
            });
        }
        
        if (retakeQuizBtn) {
            retakeQuizBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.startQuiz();
            });
        }

        // Settings
        const changeMasterPasswordBtn = document.getElementById('change-master-password-btn');
        const saveNewPasswordBtn = document.getElementById('save-new-password-btn');
        const exportDataBtn = document.getElementById('export-data-btn');
        const deleteAccountBtn = document.getElementById('delete-account-btn');

        if (changeMasterPasswordBtn) {
            changeMasterPasswordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.openModal('change-password-modal');
            });
        }
        
        if (saveNewPasswordBtn) {
            saveNewPasswordBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.changeMasterPassword();
            });
        }
        
        if (exportDataBtn) {
            exportDataBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.exportData();
            });
        }
        
        if (deleteAccountBtn) {
            deleteAccountBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.deleteAccount();
            });
        }

        // Modal management
        const confirmDeleteBtn = document.getElementById('confirm-delete-btn');
        if (confirmDeleteBtn) {
            confirmDeleteBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.confirmDeletePassword();
            });
        }

        // Generate initial password
        setTimeout(() => this.generatePassword(), 500);
        
        console.log('Event listeners setup complete');
    }

    // COMPREHENSIVE PASSWORD STRENGTH CALCULATION
    calculatePasswordStrength(password) {
        if (!password) return { score: 0, strength: 'Very Weak', feedback: ['Please enter a password'], entropy: 0, requirements: {} };

        let score = 0;
        let feedback = [];
        let bonuses = 0;
        let penalties = 0;

        // 1. LENGTH SCORING (Exponential - more important for security)
        const length = password.length;
        if (length < 8) {
            score += length * 3; // 0-21 points
            feedback.push('Password too short. Use at least 8 characters.');
        } else if (length < 12) {
            score += 24 + (length - 8) * 5; // 24-44 points
            feedback.push('Consider using 12+ characters for better security.');
        } else if (length < 16) {
            score += 44 + (length - 12) * 4; // 44-60 points
        } else {
            score += 60 + Math.min((length - 16) * 2, 15); // 60-75 points
        }

        // 2. CHARACTER VARIETY SCORING
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /\d/.test(password);
        const hasSymbol = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);

        let charsetSize = 0;
        if (hasLower) { charsetSize += 26; score += 5; }
        if (hasUpper) { charsetSize += 26; score += 5; }
        if (hasNumber) { charsetSize += 10; score += 5; }
        if (hasSymbol) { charsetSize += 32; score += 10; }

        const variety = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
        if (variety < 3) {
            feedback.push('Use a mix of uppercase, lowercase, numbers, and symbols.');
        }

        // 3. ENTROPY CALCULATION
        let entropy = 0;
        if (charsetSize > 0) {
            entropy = length * Math.log2(charsetSize);
            const entropyBonus = Math.min(entropy / 4, 20); // Max 20 points from entropy
            score += entropyBonus;
        }

        // 4. DICTIONARY CHECK (Major penalty for common passwords)
        const lowerPassword = password.toLowerCase();
        if (this.commonPasswords.has(lowerPassword)) {
            penalties += 50;
            feedback.push('This is a commonly used password. Choose something unique.');
        }

        // Check for common patterns within the password
        for (const commonPwd of this.commonPasswords) {
            if (lowerPassword.includes(commonPwd) && commonPwd.length > 4) {
                penalties += 25;
                feedback.push('Avoid using common words or patterns.');
                break;
            }
        }

        // 5. REPETITION DETECTION
        const repeatedChars = this.detectRepeatedCharacters(password);
        if (repeatedChars.maxRepeat > 2) {
            penalties += repeatedChars.maxRepeat * 5;
            feedback.push('Avoid repeating characters multiple times.');
        }

        const repeatedSubstrings = this.detectRepeatedSubstrings(password);
        if (repeatedSubstrings > 0) {
            penalties += repeatedSubstrings * 10;
            feedback.push('Avoid repeating patterns or substrings.');
        }

        // 6. SEQUENTIAL PATTERN DETECTION
        const sequentialPenalty = this.detectSequentialPatterns(password);
        if (sequentialPenalty > 0) {
            penalties += sequentialPenalty;
            feedback.push('Avoid sequential characters (123, abc, qwerty).');
        }

        // 7. ADDITIONAL BONUSES
        // Unique character bonus
        const uniqueChars = new Set(password.toLowerCase()).size;
        const uniqueRatio = uniqueChars / length;
        if (uniqueRatio > 0.7) {
            bonuses += 10;
        }

        // Mixed case bonus
        if (hasUpper && hasLower && password !== password.toLowerCase() && password !== password.toUpperCase()) {
            bonuses += 5;
        }

        // Symbol placement bonus (not just at the end)
        if (hasSymbol) {
            const symbolAtEnd = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]$/.test(password);
            const symbolAtStart = /^[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);
            if (!symbolAtEnd || !symbolAtStart) {
                bonuses += 5;
            }
        }

        // Apply bonuses and penalties
        score = score + bonuses - penalties;
        score = Math.max(0, Math.min(100, score));

        // Determine strength level and color
        let strength, color;
        if (score >= 96) {
            strength = 'Very Strong';
            color = '#059669';
        } else if (score >= 81) {
            strength = 'Strong';
            color = '#16a34a';
        } else if (score >= 61) {
            strength = 'Good';
            color = '#65a30d';
        } else if (score >= 41) {
            strength = 'Fair';
            color = '#d97706';
        } else if (score >= 21) {
            strength = 'Weak';
            color = '#ea580c';
        } else {
            strength = 'Very Weak';
            color = '#dc2626';
        }

        // Requirements for display
        const requirements = {
            length: length >= 12,
            uppercase: hasUpper,
            lowercase: hasLower,
            numbers: hasNumber,
            symbols: hasSymbol,
            unique: uniqueRatio > 0.7,
            notCommon: !this.commonPasswords.has(lowerPassword)
        };

        return {
            score: Math.round(score),
            strength,
            color,
            feedback: feedback.length > 0 ? feedback : ['Password strength looks good!'],
            entropy: Math.round(entropy),
            requirements,
            details: {
                length,
                variety,
                entropy: Math.round(entropy),
                penalties,
                bonuses
            }
        };
    }

    detectRepeatedCharacters(password) {
        let maxRepeat = 1;
        let currentRepeat = 1;
        
        for (let i = 1; i < password.length; i++) {
            if (password[i] === password[i-1]) {
                currentRepeat++;
                maxRepeat = Math.max(maxRepeat, currentRepeat);
            } else {
                currentRepeat = 1;
            }
        }
        
        return { maxRepeat };
    }

    detectRepeatedSubstrings(password) {
        let repeats = 0;
        const seen = new Set();
        
        // Check for repeated substrings of length 2-4
        for (let len = 2; len <= Math.min(4, password.length / 2); len++) {
            for (let i = 0; i <= password.length - len; i++) {
                const substring = password.substring(i, i + len);
                if (seen.has(substring)) {
                    repeats++;
                } else {
                    seen.add(substring);
                }
            }
        }
        
        return repeats;
    }

    detectSequentialPatterns(password) {
        let penalty = 0;
        const lowerPassword = password.toLowerCase();
        
        // Check each sequential pattern
        for (const pattern of this.sequentialPatterns) {
            for (let i = 0; i <= pattern.length - 3; i++) {
                const sequence = pattern.substring(i, i + 3);
                if (lowerPassword.includes(sequence)) {
                    penalty += 15;
                }
                // Check longer sequences
                if (i <= pattern.length - 4) {
                    const longerSequence = pattern.substring(i, i + 4);
                    if (lowerPassword.includes(longerSequence)) {
                        penalty += 20;
                    }
                }
            }
        }
        
        return penalty;
    }

    // Authentication Methods
    handleLogin(e) {
        e.preventDefault();
        console.log('Processing login...');
        
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;
        
        console.log('Login attempt for:', email);

        // Mock authentication
        const user = this.mockUsers.find(u => u.email === email);
        if (user && password === 'demo123') {
            console.log('Login successful');
            this.currentUser = user;
            this.loadUserPasswords();
            this.showDashboard();
            this.showToast('Welcome back!', 'success');
        } else {
            console.log('Login failed');
            this.showToast('Invalid email or password', 'error');
        }
    }

    handleSignup(e) {
        e.preventDefault();
        console.log('Processing signup...');
        
        const email = document.getElementById('signupEmail').value;
        const password = document.getElementById('signupPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (password !== confirmPassword) {
            this.showToast('Passwords do not match', 'error');
            return;
        }

        const strength = this.calculatePasswordStrength(password);
        if (strength.score < 75) {
            this.showToast('Please create a stronger master password (75+ strength required)', 'warning');
            return;
        }

        // Check if user exists
        if (this.mockUsers.find(u => u.email === email)) {
            this.showToast('User already exists', 'error');
            return;
        }

        // Create new user
        const newUser = {
            id: this.mockUsers.length + 1,
            email: email,
            masterPasswordHash: 'hashed_' + password,
            createdAt: new Date().toISOString().split('T')[0],
            securityScore: Math.min(strength.score, 100)
        };

        this.mockUsers.push(newUser);
        this.currentUser = newUser;
        this.passwordEntries = [];
        this.showDashboard();
        this.showToast('Account created successfully!', 'success');
    }

    logout() {
        this.currentUser = null;
        this.passwordEntries = [];
        this.showAuthScreen();
        this.showToast('Logged out successfully', 'info');
    }

    // Screen Management
    showAuthScreen() {
        console.log('Showing auth screen');
        this.currentScreen = 'auth';
        document.getElementById('loading-screen').classList.add('hidden');
        document.getElementById('auth-screen').classList.remove('hidden');
        document.getElementById('dashboard-screen').classList.add('hidden');
    }

    showDashboard() {
        console.log('Showing dashboard');
        this.currentScreen = 'dashboard';
        document.getElementById('auth-screen').classList.add('hidden');
        document.getElementById('dashboard-screen').classList.remove('hidden');
        document.getElementById('user-email').textContent = this.currentUser.email;
        this.calculateAndUpdateSecurityScore();
        this.renderVault();
        this.renderSecurityTips();
        this.startQuiz();
        document.getElementById('settings-email').value = this.currentUser.email;
    }

    // Tab Management
    switchTab(tabName) {
        console.log('Switching to tab:', tabName);
        
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
        const navButton = document.getElementById(`nav-${tabName}`);
        if (navButton) {
            navButton.classList.add('active');
        }

        // Show/hide tab content
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.add('hidden'));
        const tabContent = document.getElementById(`${tabName}-tab`);
        if (tabContent) {
            tabContent.classList.remove('hidden');
        }

        this.currentTab = tabName;

        if (tabName === 'add') {
            this.resetAddForm();
        } else if (tabName === 'generator') {
            setTimeout(() => this.generatePassword(), 100); // Refresh generator when opened
        }
    }

    // Password Vault Management
    loadUserData() {
        this.passwordEntries = [];
    }

    loadUserPasswords() {
        this.passwordEntries = this.mockPasswordEntries.filter(entry => entry.userId === this.currentUser.id);
        // Recalculate strength for existing entries
        this.passwordEntries.forEach(entry => {
            const strength = this.calculatePasswordStrength(entry.encryptedPassword);
            entry.strengthScore = strength.score;
            entry.strength = strength.strength;
        });
    }

    calculateAndUpdateSecurityScore() {
        if (!this.currentUser || this.passwordEntries.length === 0) {
            this.currentUser.securityScore = 50; // Base score for new users
        } else {
            // Calculate average password strength
            const avgStrength = this.passwordEntries.reduce((sum, entry) => sum + entry.strengthScore, 0) / this.passwordEntries.length;
            
            // Check for password reuse
            const uniquePasswords = new Set(this.passwordEntries.map(e => e.encryptedPassword)).size;
            const reuseRatio = uniquePasswords / this.passwordEntries.length;
            
            // Base score from average strength
            let securityScore = avgStrength * 0.7;
            
            // Bonus for unique passwords
            securityScore += reuseRatio * 20;
            
            // Bonus for having multiple passwords
            if (this.passwordEntries.length >= 5) securityScore += 5;
            if (this.passwordEntries.length >= 10) securityScore += 5;
            
            this.currentUser.securityScore = Math.min(100, Math.round(securityScore));
        }

        // Update display
        document.getElementById('security-score').textContent = this.currentUser.securityScore;
        this.updateSecurityScoreDisplay();
    }

    renderVault() {
        const vaultList = document.getElementById('vault-list');
        
        if (this.passwordEntries.length === 0) {
            vaultList.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: var(--color-text-secondary);">
                    <i class="fas fa-vault" style="font-size: 48px; margin-bottom: 16px; opacity: 0.5;"></i>
                    <h3>No passwords saved yet</h3>
                    <p>Add your first password to get started with SecureVault</p>
                    <button class="btn btn--primary" onclick="app.switchTab('add')">Add Password</button>
                </div>
            `;
            return;
        }

        // Sort by strength score (strongest first) for better UX
        const sortedEntries = [...this.passwordEntries].sort((a, b) => b.strengthScore - a.strengthScore);

        vaultList.innerHTML = sortedEntries.map(entry => `
            <div class="vault-item" data-id="${entry.id}">
                <div class="vault-item-icon">
                    <i class="fas fa-globe"></i>
                </div>
                <div class="vault-item-info">
                    <div class="vault-item-name">${entry.websiteName}</div>
                    <div class="vault-item-details">
                        <div>Username: ${entry.username}</div>
                        <div class="vault-item-password">
                            <span class="password-text password-masked" data-password="${entry.encryptedPassword}">••••••••••••</span>
                            <button class="password-toggle btn btn--sm" onclick="app.togglePasswordInVault(${entry.id})">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                        <div>
                            <span class="strength-badge ${entry.strength.toLowerCase().replace(' ', '-')}">${entry.strength} (${entry.strengthScore})</span>
                        </div>
                    </div>
                </div>
                <div class="vault-item-actions">
                    <button class="btn btn--sm btn--secondary" onclick="app.copyPassword(${entry.id})" title="Copy Password">
                        <i class="fas fa-copy"></i>
                    </button>
                    <button class="btn btn--sm btn--secondary" onclick="app.editPassword(${entry.id})" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn--sm btn--outline" onclick="app.deletePassword(${entry.id})" title="Delete" style="color: var(--color-error); border-color: var(--color-error);">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `).join('');
    }

    searchVault(query) {
        const filteredEntries = this.passwordEntries.filter(entry => 
            entry.websiteName.toLowerCase().includes(query.toLowerCase()) ||
            entry.username.toLowerCase().includes(query.toLowerCase()) ||
            entry.website.toLowerCase().includes(query.toLowerCase())
        );

        const vaultList = document.getElementById('vault-list');
        
        if (filteredEntries.length === 0 && query) {
            vaultList.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; color: var(--color-text-secondary);">
                    <i class="fas fa-search" style="font-size: 32px; margin-bottom: 16px; opacity: 0.5;"></i>
                    <p>No passwords found matching "${query}"</p>
                </div>
            `;
            return;
        }

        // Temporarily store original entries and render filtered
        const originalEntries = this.passwordEntries;
        this.passwordEntries = filteredEntries;
        this.renderVault();
        this.passwordEntries = originalEntries;
    }

    togglePasswordInVault(id) {
        const vaultItem = document.querySelector(`.vault-item[data-id="${id}"]`);
        if (!vaultItem) return;
        
        const passwordText = vaultItem.querySelector('.password-text');
        const toggleBtn = vaultItem.querySelector('.password-toggle i');
        
        if (passwordText.classList.contains('password-masked')) {
            passwordText.textContent = passwordText.dataset.password;
            passwordText.classList.remove('password-masked');
            toggleBtn.classList.remove('fa-eye');
            toggleBtn.classList.add('fa-eye-slash');
        } else {
            passwordText.textContent = '••••••••••••';
            passwordText.classList.add('password-masked');
            toggleBtn.classList.remove('fa-eye-slash');
            toggleBtn.classList.add('fa-eye');
        }
    }

    copyPassword(id) {
        const entry = this.passwordEntries.find(e => e.id === id);
        if (entry) {
            this.copyToClipboard(entry.encryptedPassword);
            this.showToast('Password copied to clipboard', 'success');
        }
    }

    editPassword(id) {
        this.editingPasswordId = id;
        const entry = this.passwordEntries.find(e => e.id === id);
        
        if (entry) {
            document.getElementById('website').value = entry.website;
            document.getElementById('websiteName').value = entry.websiteName;
            document.getElementById('username').value = entry.username;
            document.getElementById('password').value = entry.encryptedPassword;
            document.getElementById('notes').value = entry.notes || '';
            
            document.getElementById('add-form-title').textContent = 'Edit Password';
            document.getElementById('save-btn-text').textContent = 'Update Password';
            
            this.switchTab('add');
            this.checkPasswordStrength(entry.encryptedPassword, 'add-password-strength');
        }
    }

    deletePassword(id) {
        const entry = this.passwordEntries.find(e => e.id === id);
        if (entry) {
            document.getElementById('delete-password-name').textContent = entry.websiteName;
            this.pendingDeleteId = id;
            this.openModal('delete-modal');
        }
    }

    confirmDeletePassword() {
        if (this.pendingDeleteId) {
            this.passwordEntries = this.passwordEntries.filter(e => e.id !== this.pendingDeleteId);
            this.renderVault();
            this.calculateAndUpdateSecurityScore();
            this.closeModal('delete-modal');
            this.showToast('Password deleted successfully', 'info');
            this.pendingDeleteId = null;
        }
    }

    // Password Form Management
    handleSavePassword(e) {
        e.preventDefault();
        console.log('Saving password...');
        
        const website = document.getElementById('website').value;
        const websiteName = document.getElementById('websiteName').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const notes = document.getElementById('notes').value;

        const strength = this.calculatePasswordStrength(password);

        if (this.editingPasswordId) {
            // Update existing entry
            const entryIndex = this.passwordEntries.findIndex(e => e.id === this.editingPasswordId);
            if (entryIndex !== -1) {
                this.passwordEntries[entryIndex] = {
                    ...this.passwordEntries[entryIndex],
                    website,
                    websiteName,
                    username,
                    encryptedPassword: password,
                    notes,
                    strength: strength.strength,
                    strengthScore: strength.score,
                    lastModified: new Date().toISOString().split('T')[0]
                };
                this.showToast('Password updated successfully', 'success');
            }
        } else {
            // Create new entry
            const newEntry = {
                id: Math.max(...this.passwordEntries.map(e => e.id), 0) + 1,
                userId: this.currentUser.id,
                website,
                websiteName,
                username,
                encryptedPassword: password,
                notes,
                strength: strength.strength,
                strengthScore: strength.score,
                createdAt: new Date().toISOString().split('T')[0],
                lastModified: new Date().toISOString().split('T')[0]
            };
            this.passwordEntries.push(newEntry);
            this.showToast('Password saved successfully', 'success');
        }

        this.renderVault();
        this.calculateAndUpdateSecurityScore();
        this.switchTab('vault');
        this.resetAddForm();
    }

    resetAddForm() {
        const form = document.getElementById('add-password-form');
        if (form) {
            form.reset();
        }
        document.getElementById('add-form-title').textContent = 'Add New Password';
        document.getElementById('save-btn-text').textContent = 'Save Password';
        this.editingPasswordId = null;
        
        // Reset password strength indicator
        this.resetStrengthIndicator('add-password-strength');
    }

    resetStrengthIndicator(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const strengthFill = container.querySelector('.strength-fill');
        const strengthLevel = container.querySelector('.strength-level');
        if (strengthFill && strengthLevel) {
            strengthFill.style.width = '0%';
            strengthFill.style.backgroundColor = '#dc2626';
            strengthLevel.textContent = 'Very Weak';
        }
    }

    cancelAddPassword() {
        this.resetAddForm();
        this.switchTab('vault');
    }

    // ADVANCED PASSWORD GENERATOR
    generatePassword() {
        const lengthInput = document.getElementById('password-length');
        const length = lengthInput ? parseInt(lengthInput.value) : 16;
        
        const includeUppercase = document.getElementById('include-uppercase')?.checked ?? true;
        const includeLowercase = document.getElementById('include-lowercase')?.checked ?? true;
        const includeNumbers = document.getElementById('include-numbers')?.checked ?? true;
        const includeSymbols = document.getElementById('include-symbols')?.checked ?? true;
        const excludeSimilar = document.getElementById('exclude-similar')?.checked ?? false;

        // Build character sets
        let uppercaseChars = includeUppercase ? (excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') : '';
        let lowercaseChars = includeLowercase ? (excludeSimilar ? 'abcdefghijkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz') : '';
        let numberChars = includeNumbers ? (excludeSimilar ? '23456789' : '0123456789') : '';
        let symbolChars = includeSymbols ? '!@#$%^&*()_+-=[]{}|;:,.<>?~`' : '';

        if (!uppercaseChars && !lowercaseChars && !numberChars && !symbolChars) {
            this.showToast('Please select at least one character type', 'warning');
            return '';
        }

        // Ensure at least one character from each selected type
        let password = '';
        const requiredChars = [];
        
        if (uppercaseChars) requiredChars.push(this.getRandomChar(uppercaseChars));
        if (lowercaseChars) requiredChars.push(this.getRandomChar(lowercaseChars));
        if (numberChars) requiredChars.push(this.getRandomChar(numberChars));
        if (symbolChars) requiredChars.push(this.getRandomChar(symbolChars));

        // Fill remaining length with random characters from all sets
        const allChars = uppercaseChars + lowercaseChars + numberChars + symbolChars;
        const remainingLength = length - requiredChars.length;
        
        for (let i = 0; i < remainingLength; i++) {
            password += this.getRandomChar(allChars);
        }

        // Add required characters and shuffle
        password += requiredChars.join('');
        password = this.shuffleString(password);

        // Ensure we don't have obvious patterns
        if (this.hasObviousPatterns(password)) {
            return this.generatePassword(); // Recursively generate until no obvious patterns
        }

        const generatedPasswordInput = document.getElementById('generated-password');
        if (generatedPasswordInput) {
            generatedPasswordInput.value = password;
        }
        
        // Update strength indicator
        const strength = this.calculatePasswordStrength(password);
        this.updateGeneratorStrength(strength);
        
        return password;
    }

    getRandomChar(chars) {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return chars[array[0] % chars.length];
    }

    shuffleString(str) {
        const array = str.split('');
        for (let i = array.length - 1; i > 0; i--) {
            const randomArray = new Uint32Array(1);
            crypto.getRandomValues(randomArray);
            const j = randomArray[0] % (i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array.join('');
    }

    hasObviousPatterns(password) {
        // Check for simple patterns that might reduce security
        const lowerPassword = password.toLowerCase();
        
        // Check for too many repeated characters
        for (let char of password) {
            const count = (password.match(new RegExp(char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
            if (count > password.length / 3) return true;
        }
        
        // Check for obvious sequences
        for (const pattern of this.sequentialPatterns) {
            for (let i = 0; i <= pattern.length - 4; i++) {
                const sequence = pattern.substring(i, i + 4);
                if (lowerPassword.includes(sequence)) return true;
            }
        }
        
        return false;
    }

    generatePasswordForForm() {
        const password = this.generatePassword();
        const passwordInput = document.getElementById('password');
        if (password && passwordInput) {
            passwordInput.value = password;
            this.checkPasswordStrength(password, 'add-password-strength');
        }
    }

    updatePasswordLength(e) {
        const lengthValue = document.getElementById('length-value');
        if (lengthValue) {
            lengthValue.textContent = e.target.value;
        }
        this.generatePassword();
    }

    updateGeneratorStrength(strength) {
        const strengthFill = document.getElementById('generator-strength-fill');
        const strengthText = document.getElementById('generator-strength-text');
        
        if (strengthFill && strengthText) {
            strengthFill.style.width = `${strength.score}%`;
            strengthFill.style.backgroundColor = strength.color;
            strengthText.textContent = `${strength.strength} (${strength.score}/100)`;
        }
    }

    copyGeneratedPassword() {
        const password = document.getElementById('generated-password')?.value;
        if (password) {
            this.copyToClipboard(password);
            this.showToast('Password copied to clipboard', 'success');
        }
    }

    // Real-time Password Strength Checking
    checkPasswordStrength(password, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const strengthFill = container.querySelector('.strength-fill');
        const strengthLevel = container.querySelector('.strength-level');
        
        if (!strengthFill || !strengthLevel) return;
        
        const strength = this.calculatePasswordStrength(password);
        
        // Animate the strength bar
        strengthFill.style.width = `${strength.score}%`;
        strengthFill.style.backgroundColor = strength.color;
        strengthLevel.textContent = `${strength.strength} (${strength.score}/100)`;

        // Show requirements for signup
        if (containerId === 'password-strength-indicator') {
            this.updatePasswordRequirements(strength.requirements, strength.feedback);
        }
    }

    updatePasswordRequirements(requirements, feedback) {
        const requirementsContainer = document.getElementById('strength-requirements');
        if (!requirementsContainer) return;
        
        const reqList = [
            { key: 'length', text: 'At least 12 characters' },
            { key: 'uppercase', text: 'Uppercase letters (A-Z)' },
            { key: 'lowercase', text: 'Lowercase letters (a-z)' },
            { key: 'numbers', text: 'Numbers (0-9)' },
            { key: 'symbols', text: 'Special characters (!@#$...)' },
            { key: 'notCommon', text: 'Not a common password' }
        ];

        let requirementsHTML = reqList.map(req => `
            <div class="requirement ${requirements[req.key] ? 'met' : ''}">
                <i class="fas ${requirements[req.key] ? 'fa-check' : 'fa-times'}"></i>
                ${req.text}
            </div>
        `).join('');

        // Add feedback
        if (feedback && feedback.length > 0) {
            requirementsHTML += '<div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--color-border);">';
            feedback.forEach(msg => {
                requirementsHTML += `<div style="color: var(--color-text-secondary); font-size: 12px; margin-bottom: 4px;"><i class="fas fa-info-circle" style="margin-right: 6px;"></i>${msg}</div>`;
            });
            requirementsHTML += '</div>';
        }

        requirementsContainer.innerHTML = requirementsHTML;
    }

    // Quiz Management with Dynamic Scoring
    startQuiz() {
        // Shuffle questions for variety
        const shuffledQuestions = [...this.quizQuestions].sort(() => Math.random() - 0.5);
        
        this.quizData = {
            questions: shuffledQuestions,
            currentQuestion: 0,
            userAnswers: [],
            score: 0,
            isComplete: false,
            startTime: Date.now()
        };
        this.renderQuizQuestion();
    }

    renderQuizQuestion() {
        if (this.quizData.currentQuestion >= this.quizData.questions.length) return;
        
        const question = this.quizData.questions[this.quizData.currentQuestion];
        
        const currentQuestionEl = document.getElementById('current-question');
        const totalQuestionsEl = document.getElementById('total-questions');
        const questionTextEl = document.getElementById('question-text');
        
        if (currentQuestionEl) currentQuestionEl.textContent = this.quizData.currentQuestion + 1;
        if (totalQuestionsEl) totalQuestionsEl.textContent = this.quizData.questions.length;
        if (questionTextEl) questionTextEl.textContent = question.question;
        
        const progressFill = document.getElementById('quiz-progress-fill');
        if (progressFill) {
            progressFill.style.width = `${((this.quizData.currentQuestion + 1) / this.quizData.questions.length) * 100}%`;
        }

        const optionsContainer = document.getElementById('quiz-options');
        if (optionsContainer) {
            optionsContainer.innerHTML = question.options.map((option, index) => `
                <div class="quiz-option" data-index="${index}" onclick="app.selectQuizOption(${index})">
                    ${option}
                </div>
            `).join('');
        }

        const submitBtn = document.getElementById('quiz-submit-btn');
        if (submitBtn) submitBtn.disabled = true;
        
        const questionContainer = document.getElementById('quiz-question-container');
        const feedbackContainer = document.getElementById('quiz-feedback');
        const resultsContainer = document.getElementById('quiz-results');
        
        if (questionContainer) questionContainer.classList.remove('hidden');
        if (feedbackContainer) feedbackContainer.classList.add('hidden');
        if (resultsContainer) resultsContainer.classList.add('hidden');
    }

    selectQuizOption(index) {
        document.querySelectorAll('.quiz-option').forEach((option, i) => {
            option.classList.toggle('selected', i === index);
        });
        const submitBtn = document.getElementById('quiz-submit-btn');
        if (submitBtn) submitBtn.disabled = false;
        this.selectedAnswer = index;
    }

    submitQuizAnswer() {
        if (this.selectedAnswer === undefined) return;
        
        const question = this.quizData.questions[this.quizData.currentQuestion];
        const isCorrect = this.selectedAnswer === question.correctAnswer;
        
        this.quizData.userAnswers.push({
            questionId: question.id,
            userAnswer: this.selectedAnswer,
            correctAnswer: question.correctAnswer,
            isCorrect,
            difficulty: question.difficulty
        });

        if (isCorrect) {
            // Award points based on difficulty
            const points = question.difficulty === 'hard' ? 2 : question.difficulty === 'medium' ? 1.5 : 1;
            this.quizData.score += points;
        }

        // Show feedback
        const questionContainer = document.getElementById('quiz-question-container');
        const feedbackContainer = document.getElementById('quiz-feedback');
        
        if (questionContainer) questionContainer.classList.add('hidden');
        if (feedbackContainer) feedbackContainer.classList.remove('hidden');

        const feedbackContent = document.getElementById('feedback-content');
        if (feedbackContent) {
            feedbackContent.innerHTML = `
                <div class="feedback-icon ${isCorrect ? 'correct' : 'incorrect'}">
                    <i class="fas ${isCorrect ? 'fa-check-circle' : 'fa-times-circle'}"></i>
                </div>
                <h3>${isCorrect ? 'Correct!' : 'Incorrect'}</h3>
                <p><strong>Correct answer:</strong> ${question.options[question.correctAnswer]}</p>
                <p>${question.explanation}</p>
                <div style="margin-top: 16px; padding: 12px; background: var(--color-bg-1); border-radius: 8px; font-size: 14px;">
                    <strong>Category:</strong> ${question.category} | <strong>Difficulty:</strong> ${question.difficulty}
                </div>
            `;
        }

        // Update option styles
        document.querySelectorAll('.quiz-option').forEach((option, i) => {
            if (i === question.correctAnswer) {
                option.classList.add('correct');
            } else if (i === this.selectedAnswer && !isCorrect) {
                option.classList.add('incorrect');
            }
        });
    }

    nextQuestion() {
        this.quizData.currentQuestion++;
        this.selectedAnswer = undefined;
        
        if (this.quizData.currentQuestion >= this.quizData.questions.length) {
            this.showQuizResults();
        } else {
            this.renderQuizQuestion();
        }
    }

    showQuizResults() {
        this.quizData.isComplete = true;
        this.quizData.endTime = Date.now();
        const timeSpent = Math.round((this.quizData.endTime - this.quizData.startTime) / 1000);
        
        const feedbackContainer = document.getElementById('quiz-feedback');
        const resultsContainer = document.getElementById('quiz-results');
        
        if (feedbackContainer) feedbackContainer.classList.add('hidden');
        if (resultsContainer) resultsContainer.classList.remove('hidden');
        
        const finalScore = document.getElementById('quiz-final-score');
        const maxScore = this.quizData.questions.reduce((sum, q) => sum + (q.difficulty === 'hard' ? 2 : q.difficulty === 'medium' ? 1.5 : 1), 0);
        
        if (finalScore) finalScore.textContent = Math.round(this.quizData.score * 10) / 10;
        
        const resultsTitle = document.getElementById('results-title');
        const resultsDescription = document.getElementById('results-description');
        
        const percentage = (this.quizData.score / maxScore) * 100;
        
        if (resultsTitle && resultsDescription) {
            if (percentage >= 90) {
                resultsTitle.textContent = 'Outstanding!';
                resultsDescription.textContent = `Perfect cybersecurity knowledge! Completed in ${timeSpent} seconds.`;
            } else if (percentage >= 75) {
                resultsTitle.textContent = 'Excellent Work!';
                resultsDescription.textContent = `You have strong cybersecurity knowledge. Time: ${timeSpent} seconds.`;
            } else if (percentage >= 60) {
                resultsTitle.textContent = 'Good Job!';
                resultsDescription.textContent = `Good grasp of security basics. Time: ${timeSpent} seconds.`;
            } else {
                resultsTitle.textContent = 'Keep Learning!';
                resultsDescription.textContent = `Review security tips to improve. Time: ${timeSpent} seconds.`;
            }
        }

        // Show detailed summary
        this.renderQuizSummary();
    }

    renderQuizSummary() {
        const summaryContainer = document.getElementById('quiz-summary');
        if (!summaryContainer) return;
        
        summaryContainer.innerHTML = this.quizData.userAnswers.map((answer, index) => {
            const question = this.quizData.questions[index];
            return `
                <div class="summary-item">
                    <div class="summary-icon ${answer.isCorrect ? 'correct' : 'incorrect'}">
                        <i class="fas ${answer.isCorrect ? 'fa-check' : 'fa-times'}"></i>
                    </div>
                    <div class="summary-content">
                        <h4>Question ${index + 1} - ${question.category}</h4>
                        <p><strong>Question:</strong> ${question.question}</p>
                        <p><strong>Your answer:</strong> ${question.options[answer.userAnswer]}</p>
                        ${!answer.isCorrect ? `<p><strong>Correct answer:</strong> ${question.options[answer.correctAnswer]}</p>` : ''}
                        <p style="font-size: 12px; color: var(--color-text-secondary); margin-top: 8px;">
                            <strong>Difficulty:</strong> ${question.difficulty} | 
                            <strong>Points:</strong> ${answer.isCorrect ? (question.difficulty === 'hard' ? '2.0' : question.difficulty === 'medium' ? '1.5' : '1.0') : '0.0'}
                        </p>
                    </div>
                </div>
            `;
        }).join('');
    }

    // Security Tips
    renderSecurityTips() {
        const tipsContainer = document.getElementById('security-tips-container');
        if (tipsContainer) {
            tipsContainer.innerHTML = this.securityTips.map(tip => `
                <div class="tip-card ${tip.importance}">
                    <div class="tip-header">
                        <div class="tip-icon">
                            <i class="${tip.icon}"></i>
                        </div>
                        <h3 class="tip-title">${tip.title}</h3>
                    </div>
                    <p class="tip-description">${tip.description}</p>
                    <div class="tip-category">${tip.category}</div>
                </div>
            `).join('');
        }
    }

    // Settings
    changeMasterPassword() {
        const currentPassword = document.getElementById('current-password')?.value;
        const newPassword = document.getElementById('new-password')?.value;
        const confirmNewPassword = document.getElementById('confirm-new-password')?.value;

        if (newPassword !== confirmNewPassword) {
            this.showToast('New passwords do not match', 'error');
            return;
        }

        const strength = this.calculatePasswordStrength(newPassword);
        if (strength.score < 75) {
            this.showToast('Please choose a stronger password (75+ strength required)', 'warning');
            return;
        }

        // Mock validation
        if (currentPassword !== 'demo123') {
            this.showToast('Current password is incorrect', 'error');
            return;
        }

        this.closeModal('change-password-modal');
        this.showToast('Master password changed successfully', 'success');
        const form = document.getElementById('change-password-form');
        if (form) form.reset();
    }

    exportData() {
        const data = {
            user: this.currentUser,
            passwords: this.passwordEntries.map(entry => ({
                ...entry,
                encryptedPassword: '***ENCRYPTED***' // Don't export actual passwords
            })),
            securityScore: this.currentUser.securityScore,
            exportDate: new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `securevault-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        
        this.showToast('Data exported successfully', 'success');
    }

    deleteAccount() {
        if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
            this.logout();
            this.showToast('Account deleted successfully', 'info');
        }
    }

    // Utility Methods
    updateSecurityScoreDisplay() {
        const scoreElement = document.querySelector('.score-circle');
        if (scoreElement) {
            const score = this.currentUser.securityScore;
            let color = '#dc2626'; // Red for low scores
            if (score >= 80) color = '#16a34a'; // Green
            else if (score >= 60) color = '#65a30d'; // Light green
            else if (score >= 40) color = '#d97706'; // Yellow
            else if (score >= 20) color = '#ea580c'; // Orange
            
            const gradient = `conic-gradient(${color} ${score}%, var(--color-secondary) ${score}%)`;
            scoreElement.style.background = gradient;
        }
    }

    switchToSignup() {
        console.log('Switching to signup');
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        
        if (loginForm && signupForm) {
            loginForm.classList.add('hidden');
            signupForm.classList.remove('hidden');
        }
    }

    switchToLogin() {
        console.log('Switching to login');
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        
        if (loginForm && signupForm) {
            signupForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
        }
    }

    togglePasswordVisibility(inputId) {
        const input = document.getElementById(inputId);
        if (!input) return;
        
        const button = input.nextElementSibling;
        const icon = button?.querySelector('i');
        
        if (!button || !icon) return;
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }

    openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('hidden');
            document.body.style.overflow = '';
        }
    }

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
        }
    }

    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };

        toast.innerHTML = `
            <div class="toast-icon">
                <i class="fas ${icons[type]}"></i>
            </div>
            <div class="toast-message">${message}</div>
        `;

        toastContainer.appendChild(toast);

        // Auto remove after 4 seconds
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 4000);
    }
}

// Global functions for onclick handlers
window.togglePasswordVisibility = function(inputId) {
    if (window.app) {
        window.app.togglePasswordVisibility(inputId);
    }
};

window.switchToSignup = function() {
    console.log('Global switchToSignup called');
    if (window.app) {
        window.app.switchToSignup();
    }
};

window.switchToLogin = function() {
    console.log('Global switchToLogin called');
    if (window.app) {
        window.app.switchToLogin();
    }
};

window.closeModal = function(modalId) {
    if (window.app) {
        window.app.closeModal(modalId);
    }
};

// CSS for slideOut animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize the application
window.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, creating app');
    window.app = new PasswordManagerApp();
});