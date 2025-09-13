# SecureVault - Student Password Manager Backend

A secure, educational password manager API built with Node.js and Express, designed specifically for students to learn cybersecurity while managing their passwords safely.

## Features

### 🔐 Security
- **Bcrypt** password hashing with 12 salt rounds
- **JWT** authentication with 7-day expiration
- **AES-256** encryption for stored passwords
- **Rate limiting** to prevent brute force attacks
- **Input validation** and sanitization
- **CORS** protection
- **Helmet** security headers

### 📚 Educational
- Interactive cybersecurity quiz system
- Dynamic password strength analysis
- Personalized security tips
- Security score calculation
- Progress tracking

### 🛠 API Endpoints

#### Authentication
- `POST /api/auth/signup` - User registration
- `POST /api/auth/signin` - User login

#### Password Vault
- `GET /api/vault` - Get all user passwords
- `POST /api/vault` - Add new password
- `PUT /api/vault/:id` - Update password
- `DELETE /api/vault/:id` - Delete password

#### Educational
- `GET /api/quiz/questions` - Get quiz questions
- `POST /api/quiz/submit` - Submit quiz answers
- `GET /api/security/tips` - Get personalized security tips
- `GET /api/security/score` - Get user security score

#### Utilities
- `POST /api/security/check-password` - Analyze password strength
- `GET /api/health` - Health check

## Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd secure-password-manager-backend
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Start the server**
```bash
# Development
npm run dev

# Production
npm start
```

## Environment Variables

Create a `.env` file with the following variables:

```env
NODE_ENV=development
PORT=3000
FRONTEND_URL=http://localhost:3001
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
ENCRYPTION_KEY=your-encryption-key-32-chars-long!
```

## Password Strength Algorithm

The server implements a comprehensive password strength algorithm that evaluates:

- **Length scoring**: Exponential scoring for password length
- **Character variety**: Points for different character types
- **Entropy calculation**: Mathematical entropy based on character space
- **Pattern detection**: Penalties for common patterns
- **Dictionary checking**: Validation against common passwords
- **Sequential patterns**: Detection of sequential characters/numbers

## Security Score Calculation

User security scores are calculated based on:
- Average password strength (40%)
- Number of stored passwords (20%)
- Two-factor authentication usage (15%)
- Quiz completion and scores (15%)
- Educational engagement (10%)

## Data Structure

### User Object
```javascript
{
  id: 1,
  email: "student@example.com",
  masterPasswordHash: "bcrypt_hash",
  securityScore: 85,
  createdAt: "2024-01-01T00:00:00.000Z",
  lastLogin: "2024-01-01T00:00:00.000Z",
  preferences: {
    theme: "light",
    notifications: true,
    autoLock: 300
  }
}
```

### Password Entry Object
```javascript
{
  id: 1,
  userId: 1,
  website: "github.com",
  websiteName: "GitHub",
  username: "student123",
  encryptedPassword: "encrypted_string",
  notes: "Development account",
  tags: ["work", "development"],
  hasTwoFactor: false,
  strength: "Strong",
  strengthScore: 85,
  createdAt: "2024-01-01T00:00:00.000Z",
  lastModified: "2024-01-01T00:00:00.000Z",
  lastUsed: null
}
```

## Error Handling

The API includes comprehensive error handling:
- **400**: Validation errors
- **401**: Authentication required
- **403**: Invalid/expired token
- **404**: Resource not found
- **409**: Conflict (user already exists)
- **429**: Rate limit exceeded
- **500**: Internal server error

## Rate Limiting

- **General requests**: 100 requests per 15 minutes per IP
- **Authentication**: 5 requests per 15 minutes per IP

## Database Integration

Currently uses in-memory storage for development. For production:

1. Install MongoDB driver:
```bash
npm install mongodb mongoose
```

2. Update environment variables:
```env
MONGODB_URI=mongodb://localhost:27017/password_manager
```

3. Replace mock data with MongoDB models and operations.

## Testing

Run the test suite:
```bash
npm test
```

## Deployment

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Environment Configuration
- Set `NODE_ENV=production`
- Use strong, random values for `JWT_SECRET` and `ENCRYPTION_KEY`
- Configure proper CORS origins
- Set up MongoDB connection
- Enable HTTPS

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security Notice

This is an educational project. For production use:
- Use a proper database with encryption at rest
- Implement proper session management
- Add comprehensive logging and monitoring
- Conduct security audits
- Use HTTPS in production
- Implement proper backup and disaster recovery
