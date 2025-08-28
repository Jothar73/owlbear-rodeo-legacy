# Security Best Practices Guide for Owlbear Rodeo Legacy

This document provides security guidelines and best practices for developers working with or maintaining the Owlbear Rodeo Legacy codebase.

## General Security Principles

### 1. Zero Trust Architecture
- Never trust user input
- Validate all data at boundaries
- Assume all external data is malicious
- Implement defense in depth

### 2. Principle of Least Privilege
- Grant minimum necessary permissions
- Limit access to sensitive resources
- Use role-based access control
- Regular permission audits

### 3. Fail Securely
- Default to secure state on errors
- Don't leak information in error messages
- Implement proper error boundaries
- Log security events appropriately

## Input Validation and Sanitization

### 1. JSON Data Validation

**❌ Don't:**
```typescript
// Unsafe - no validation
const data = JSON.parse(userInput);
```

**✅ Do:**
```typescript
// Safe - with validation
import Ajv from 'ajv';

const ajv = new Ajv();
const schema = {
  type: 'object',
  properties: {
    to: { type: 'string', maxLength: 100 },
    signal: { type: 'object' }
  },
  required: ['to', 'signal'],
  additionalProperties: false
};

const validate = ajv.compile(schema);

function parseSignalData(input: string) {
  try {
    const data = JSON.parse(input);
    if (!validate(data)) {
      throw new Error('Invalid signal data structure');
    }
    return data;
  } catch (error) {
    // Log error without exposing details
    console.error('Signal parsing failed');
    throw new Error('Invalid signal data');
  }
}
```

### 2. WebRTC Signal Validation

**❌ Don't:**
```typescript
// Unsafe - forwards without validation
socket.on("signal", (data: string) => {
  const { to, signal } = JSON.parse(data);
  this.io.to(to).emit("signal", { from: socket.id, signal });
});
```

**✅ Do:**
```typescript
// Safe - with validation and rate limiting
import rateLimit from 'socket.io-rate-limit';

const signalLimiter = rateLimit({
  tokensPerInterval: 10,
  interval: 1000,
  maxHits: 5
});

socket.use(signalLimiter);

socket.on("signal", (data: string) => {
  try {
    const parsed = parseSignalData(data);
    
    // Validate recipient exists and is authorized
    if (!isValidRecipient(parsed.to, socket.id)) {
      throw new Error('Invalid recipient');
    }
    
    // Validate signal structure
    if (!isValidWebRTCSignal(parsed.signal)) {
      throw new Error('Invalid signal structure');
    }
    
    this.io.to(parsed.to).emit("signal", { 
      from: socket.id, 
      signal: parsed.signal 
    });
  } catch (error) {
    console.error('Signal processing failed:', error.message);
    socket.emit('error', 'Signal processing failed');
  }
});
```

### 3. File Upload Validation

**❌ Don't:**
```typescript
// Unsafe - trusts file type from browser
if (file.type.startsWith('image/')) {
  // Process file
}
```

**✅ Do:**
```typescript
// Safe - validates actual file content
import { fileTypeFromBuffer } from 'file-type';

async function validateImageFile(file: File): Promise<boolean> {
  const MAX_SIZE = 5 * 1024 * 1024; // 5MB
  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  
  // Check file size
  if (file.size > MAX_SIZE) {
    throw new Error('File too large');
  }
  
  // Read file header to validate actual type
  const buffer = await file.arrayBuffer();
  const fileType = await fileTypeFromBuffer(buffer);
  
  if (!fileType || !ALLOWED_TYPES.includes(fileType.mime)) {
    throw new Error('Invalid file type');
  }
  
  return true;
}
```

## Environment Configuration Security

### 1. Environment Variable Validation

**❌ Don't:**
```typescript
// Unsafe - no validation
static ORIGIN_WHITELIST: string = process.env.ALLOW_ORIGIN!!;
```

**✅ Do:**
```typescript
// Safe - with validation and defaults
class Config {
  static getOriginWhitelist(): string {
    const allowOrigin = process.env.ALLOW_ORIGIN;
    
    if (!allowOrigin) {
      throw new Error('ALLOW_ORIGIN environment variable is required');
    }
    
    // Validate regex pattern
    try {
      new RegExp(allowOrigin);
    } catch (error) {
      throw new Error('ALLOW_ORIGIN contains invalid regex pattern');
    }
    
    // Warn about insecure patterns
    if (allowOrigin === '.*' || allowOrigin === '*') {
      console.warn('WARNING: ALLOW_ORIGIN is set to allow all origins. This is insecure for production.');
    }
    
    return allowOrigin;
  }
}
```

### 2. Secure CORS Configuration

**❌ Don't:**
```yaml
# Unsafe - allows any origin
ALLOW_ORIGIN: ".*"
```

**✅ Do:**
```yaml
# Safe - specific origins
ALLOW_ORIGIN: "^https://(localhost|app\.example\.com)(:[0-9]+)?$"
```

## Data Storage Security

### 1. Client-Side Storage

**❌ Don't:**
```typescript
// Unsafe - stores sensitive data in plain text
localStorage.setItem('gameSettings', JSON.stringify({
  password: 'secret123',
  token: 'abc123'
}));
```

**✅ Do:**
```typescript
// Safe - encrypt sensitive data
import CryptoJS from 'crypto-js';

class SecureStorage {
  private encryptionKey: string;
  
  constructor() {
    // Generate or retrieve encryption key
    this.encryptionKey = this.getOrCreateKey();
  }
  
  setSecureItem(key: string, value: any): void {
    const jsonData = JSON.stringify(value);
    const encrypted = CryptoJS.AES.encrypt(jsonData, this.encryptionKey).toString();
    localStorage.setItem(key, encrypted);
  }
  
  getSecureItem(key: string): any {
    const encrypted = localStorage.getItem(key);
    if (!encrypted) return null;
    
    try {
      const decrypted = CryptoJS.AES.decrypt(encrypted, this.encryptionKey);
      const jsonData = decrypted.toString(CryptoJS.enc.Utf8);
      return JSON.parse(jsonData);
    } catch (error) {
      console.error('Failed to decrypt stored data');
      return null;
    }
  }
  
  private getOrCreateKey(): string {
    // Implementation depends on your key management strategy
    // For client-side apps, consider using WebCrypto API
    return sessionStorage.getItem('encKey') || this.generateKey();
  }
}
```

### 2. IndexedDB Security

**❌ Don't:**
```typescript
// Unsafe - no validation of stored data
return JSON.parse(this.storage.getItem(this.name));
```

**✅ Do:**
```typescript
// Safe - validate stored data structure
import Ajv from 'ajv';

class SecureSettings {
  private schema = {
    type: 'object',
    properties: {
      version: { type: 'number' },
      settings: { type: 'object' }
    },
    required: ['version'],
    additionalProperties: true
  };
  
  private validate = new Ajv().compile(this.schema);
  
  getAll(): any {
    const stored = this.storage.getItem(this.name);
    if (!stored) return {};
    
    try {
      const parsed = JSON.parse(stored);
      
      if (!this.validate(parsed)) {
        console.warn('Stored settings failed validation, resetting');
        return {};
      }
      
      return parsed;
    } catch (error) {
      console.error('Failed to parse stored settings');
      return {};
    }
  }
}
```

## Network Communication Security

### 1. Socket.IO Security

**❌ Don't:**
```typescript
// Unsafe - no authentication or rate limiting
io.on('connect', (socket) => {
  socket.on('gameAction', (data) => {
    // Process any action from any client
    gameState.update(data);
  });
});
```

**✅ Do:**
```typescript
// Safe - with authentication and rate limiting
import rateLimit from 'socket.io-rate-limit';

const actionLimiter = rateLimit({
  tokensPerInterval: 30,
  interval: 1000
});

io.use((socket, next) => {
  // Authenticate socket connection
  const token = socket.handshake.auth.token;
  if (!validateToken(token)) {
    return next(new Error('Authentication failed'));
  }
  socket.userId = extractUserId(token);
  next();
});

io.on('connect', (socket) => {
  socket.use(actionLimiter);
  
  socket.on('gameAction', (data) => {
    try {
      // Validate action
      if (!validateGameAction(data)) {
        throw new Error('Invalid action');
      }
      
      // Check authorization
      if (!canPerformAction(socket.userId, data)) {
        throw new Error('Unauthorized action');
      }
      
      gameState.update(data);
    } catch (error) {
      socket.emit('error', 'Action failed');
    }
  });
});
```

### 2. WebRTC Security

**❌ Don't:**
```javascript
// Unsafe - accepts any peer connection
const peer = new SimplePeer({
  initiator: true,
  trickle: false
});
```

**✅ Do:**
```javascript
// Safe - with authentication and validation
const peer = new SimplePeer({
  initiator: true,
  trickle: false,
  config: {
    iceServers: secureIceServers,
    iceTransportPolicy: 'relay' // Force TURN for privacy
  }
});

peer.on('signal', (signal) => {
  // Validate and sign signal before sending
  const signedSignal = signSignal(signal, privateKey);
  sendSignal(signedSignal);
});

peer.on('data', (data) => {
  try {
    // Validate incoming data
    const validatedData = validatePeerData(data);
    handlePeerData(validatedData);
  } catch (error) {
    console.error('Invalid peer data received');
    peer.destroy();
  }
});
```

## Error Handling and Logging

### 1. Secure Error Handling

**❌ Don't:**
```typescript
// Unsafe - leaks sensitive information
catch (error) {
  res.status(500).json({ 
    error: error.message,
    stack: error.stack,
    data: sensitiveData
  });
}
```

**✅ Do:**
```typescript
// Safe - sanitized error responses
catch (error) {
  // Log full error internally
  logger.error('Database operation failed', {
    error: error.message,
    stack: error.stack,
    userId: req.user?.id,
    timestamp: new Date().toISOString()
  });
  
  // Return generic error to client
  res.status(500).json({ 
    error: 'Internal server error',
    errorId: generateErrorId() // For support purposes
  });
}
```

### 2. Security Event Logging

**✅ Implement:**
```typescript
// Security event logging
class SecurityLogger {
  static logAuthenticationFailure(ip: string, attemptedUser: string) {
    logger.warn('Authentication failure', {
      event: 'AUTH_FAILURE',
      ip,
      attemptedUser,
      timestamp: new Date().toISOString()
    });
  }
  
  static logSuspiciousActivity(userId: string, activity: string, details: any) {
    logger.warn('Suspicious activity detected', {
      event: 'SUSPICIOUS_ACTIVITY',
      userId,
      activity,
      details,
      timestamp: new Date().toISOString()
    });
  }
  
  static logDataValidationFailure(source: string, data: any) {
    logger.error('Data validation failure', {
      event: 'VALIDATION_FAILURE',
      source,
      dataType: typeof data,
      timestamp: new Date().toISOString()
    });
  }
}
```

## Resource Management and DoS Prevention

### 1. Connection Limits

**✅ Implement:**
```typescript
// Connection and rate limiting
import { RateLimiterMemory } from 'rate-limiter-flexible';

const connectionLimiter = new RateLimiterMemory({
  points: 10, // Number of connections
  duration: 60, // Per 60 seconds
  blockDuration: 300, // Block for 5 minutes
});

io.use(async (socket, next) => {
  const ip = socket.handshake.address;
  
  try {
    await connectionLimiter.consume(ip);
    next();
  } catch (rejRes) {
    next(new Error('Too many connections'));
  }
});
```

### 2. Memory Usage Monitoring

**✅ Implement:**
```typescript
// Memory monitoring and cleanup
class ResourceMonitor {
  private memoryThreshold = 500 * 1024 * 1024; // 500MB
  
  startMonitoring() {
    setInterval(() => {
      const memUsage = process.memoryUsage();
      
      if (memUsage.heapUsed > this.memoryThreshold) {
        console.warn('High memory usage detected', memUsage);
        this.triggerGarbageCollection();
      }
    }, 30000); // Check every 30 seconds
  }
  
  private triggerGarbageCollection() {
    if (global.gc) {
      global.gc();
    }
    
    // Clean up application-specific resources
    this.cleanupStaleConnections();
    this.cleanupOldChunks();
  }
}
```

## Cryptography Best Practices

### 1. Password Hashing

**❌ Don't:**
```typescript
// Unsafe - weak hashing
const hash = bcrypt.hashSync(password, 10);
```

**✅ Do:**
```typescript
// Safe - strong hashing with proper configuration
import bcrypt from 'bcrypt';
import argon2 from 'argon2';

class PasswordSecurity {
  // Use Argon2 for new implementations
  static async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }
  
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }
  
  // For bcrypt compatibility
  static async bcryptHash(password: string): Promise<string> {
    const saltRounds = 12; // Increase from default 10
    return bcrypt.hash(password, saltRounds);
  }
}
```

### 2. Random Number Generation

**❌ Don't:**
```typescript
// Unsafe - predictable random numbers
const sessionId = Math.random().toString(36);
```

**✅ Do:**
```typescript
// Safe - cryptographically secure random numbers
import crypto from 'crypto';

class SecureRandom {
  static generateSessionId(): string {
    return crypto.randomBytes(32).toString('hex');
  }
  
  static generateApiKey(): string {
    return crypto.randomBytes(48).toString('base64url');
  }
  
  static generateNonce(): string {
    return crypto.randomBytes(16).toString('hex');
  }
}
```

## Security Testing Guidelines

### 1. Input Fuzzing

```typescript
// Example fuzzing test
describe('JSON parsing security', () => {
  const maliciousInputs = [
    '{"__proto__": {"admin": true}}', // Prototype pollution
    '{"a": "' + 'x'.repeat(1000000) + '"}', // Large string DoS
    '{"a": ' + '['.repeat(10000) + '1' + ']'.repeat(10000) + '}', // Deep nesting
    '{"constructor": {"prototype": {"admin": true}}}', // Constructor pollution
  ];
  
  maliciousInputs.forEach((input, index) => {
    it(`should safely handle malicious input ${index}`, () => {
      expect(() => {
        parseUserInput(input);
      }).not.toThrow();
    });
  });
});
```

### 2. Authorization Testing

```typescript
// Example authorization test
describe('Authorization checks', () => {
  it('should prevent unauthorized game actions', async () => {
    const unauthorizedUser = createUser({ role: 'viewer' });
    const gameAction = { type: 'DELETE_MAP', mapId: 'test-map' };
    
    await expect(
      processGameAction(unauthorizedUser, gameAction)
    ).rejects.toThrow('Unauthorized');
  });
});
```

## Deployment Security Checklist

### Development Environment
- [ ] Remove all debug logs before production
- [ ] Disable development-only features
- [ ] Remove test credentials and API keys
- [ ] Validate all environment variables

### Production Environment
- [ ] Enable HTTPS with proper certificates
- [ ] Configure secure headers (HSTS, CSP, etc.)
- [ ] Set up proper logging and monitoring
- [ ] Implement backup and recovery procedures
- [ ] Regular security updates and patches

### Monitoring and Incident Response
- [ ] Set up security event monitoring
- [ ] Create incident response procedures
- [ ] Regular security assessments
- [ ] Vulnerability scanning
- [ ] Penetration testing

## Conclusion

Security is an ongoing process, not a one-time implementation. Regular security reviews, updates, and testing are essential for maintaining a secure application. Always assume that attackers will find the weakest point in your system and plan accordingly.

Key principles to remember:
1. Validate everything at system boundaries
2. Never trust client-side data
3. Implement defense in depth
4. Log security events appropriately
5. Keep dependencies updated
6. Regular security assessments