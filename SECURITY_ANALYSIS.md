# Security Analysis Report - Owlbear Rodeo Legacy

This document provides a comprehensive security analysis of the Owlbear Rodeo Legacy codebase, identifying vulnerabilities, security risks, and potential attack vectors.

## Executive Summary

**Overall Risk Level: HIGH**

The Owlbear Rodeo Legacy application contains numerous security vulnerabilities ranging from dependency issues to architectural security concerns. While this is legacy code intended for personal use only, several critical issues should be addressed before deployment.

## Critical Security Issues

### 1. Dependency Vulnerabilities

#### Frontend Dependencies (531 total vulnerabilities)
- **70 Critical vulnerabilities**
- **252 High-severity vulnerabilities** 
- **165 Moderate vulnerabilities**

**Key Critical Issues:**
- **EJS Template Injection (CVE-2022-29078)**: Critical template injection vulnerability in ejs package
- **Form-data Unsafe Random Function**: Critical cryptographic weakness in boundary generation
- **Lodash Command Injection**: High-severity command injection vulnerability
- **Lodash Prototype Pollution**: High-severity prototype pollution vulnerability

#### Backend Dependencies (31 total vulnerabilities)
- **13 High-severity vulnerabilities**
- **8 Moderate vulnerabilities**

**Key Issues:**
- **WebSocket DoS (ws package)**: High-severity denial of service vulnerability
- **Express body-parser DoS**: High-severity denial of service vulnerability  
- **Path-to-regexp ReDoS**: High-severity regular expression denial of service

### 2. Input Validation and Data Sanitization

#### JSON Parsing Without Validation
**File:** `backend/src/entities/GameServer.ts:34`
```typescript
const { to, signal } = JSON.parse(data);
```
**Risk:** Potential for JSON injection attacks, DoS via malformed JSON

#### Client-side JSON Parsing
**File:** `src/helpers/Settings.ts:33`
```typescript
return JSON.parse(this.storage.getItem(this.name));
```
**Risk:** Deserialization of potentially malicious data from localStorage

### 3. WebRTC Security Concerns

#### Insecure ICE Server Configuration
**File:** `backend/ice.json`
```json
{
  "iceServers": [{ "urls": "stun:stun.l.google.com:19302" }]
}
```
**Risk:** 
- Reliance on external STUN server (Google)
- No authentication for ICE servers
- Potential for STUN/TURN server abuse

#### Peer-to-Peer Data Transfer Risks
**File:** `src/network/Connection.ts`
- Unlimited buffer size for incoming data chunks
- No authentication/authorization for peer connections
- Potential for malicious peers to send oversized data

### 4. Environment Variable Security

#### Missing Environment Variable Validation
**File:** `backend/src/entities/Global.ts:9`
```typescript
static ORIGIN_WHITELIST: string = process.env.ALLOW_ORIGIN!!;
```
**Risk:** 
- Double assertion operator bypasses type checking
- No validation of CORS origin patterns
- Could allow unauthorized origins if misconfigured

### 5. Client-Side Storage Security Issues

#### Unreliable Data Persistence
**File:** `src/contexts/DatabaseContext.tsx`
- IndexedDB data can be arbitrarily deleted by browsers
- No encryption of sensitive data in client storage
- Safari automatically deletes data after one week of inactivity

#### LocalStorage Security
**File:** `src/helpers/Settings.ts`
- Settings stored in plain text in localStorage
- No validation of stored data integrity
- Vulnerable to XSS attacks that could modify settings

### 6. Docker Configuration Issues

#### Insecure Docker Compose Configuration
**File:** `docker-compose.yml`
```yaml
environment:
  ALLOW_ORIGIN: ".*"
```
**Risk:** 
- Wildcard CORS policy allows any origin
- No network isolation between services
- Development configuration used in production context

## Moderate Security Issues

### 1. Network Communication

#### Unencrypted WebSocket Communication
- Socket.IO connections may not enforce TLS/SSL
- Game state transmitted without end-to-end encryption
- Vulnerable to man-in-the-middle attacks

#### Missing Rate Limiting
- No rate limiting on Socket.IO events
- Potential for DoS attacks via message flooding
- No connection throttling implemented

### 2. File Upload Security

#### Image Upload Without Validation
**File:** `src/hooks/useImageDrop.ts:44-50`
```typescript
const urlMatch = html.match(/src="?([^"\s]+)"?\s*/);
```
**Risk:**
- Regex-based URL extraction could be bypassed
- No validation of image file contents
- Potential for serving malicious files

### 3. Client-Side Vulnerabilities

#### DOM Manipulation
**File:** `src/hooks/usePortal.ts:46`
```typescript
const existingParent: HTMLElement | null = document.querySelector(`#${id}`);
```
**Risk:** 
- Potential for CSS injection if `id` is user-controlled
- Direct DOM manipulation without sanitization

## Low Priority Issues

### 1. Code Quality Issues

#### Missing Error Handling
- Inconsistent error handling across async operations
- Unhandled promise rejections in WebRTC operations
- Missing timeout handling for network operations

#### Cryptographic Weaknesses
- No secure random number generation for session IDs
- Bcrypt salt rounds hardcoded to 10 (could be higher)
- No key derivation for client-side encryption

### 2. Information Disclosure

#### Verbose Error Messages
- Stack traces exposed in development mode
- Console logging of sensitive connection data
- Version information exposed in client code

## Architectural Security Concerns

### 1. Trust Model Issues

#### Client-Side Trust
- Game state validation primarily on client-side
- No server-side authorization for actions
- Malicious clients can manipulate game state

#### Peer-to-Peer Trust
- No authentication between peers
- Direct data transfer between untrusted parties
- Potential for data integrity attacks

### 2. Session Management

#### Weak Session Identifiers
- Socket.IO session IDs may be predictable
- No session invalidation mechanism
- Party passwords stored in plain text (client-side)

## Recommendations

### Immediate Actions Required

1. **Update Dependencies**
   - Upgrade all packages with known vulnerabilities
   - Implement dependency scanning in CI/CD pipeline
   - Use tools like `npm audit` or `yarn audit` regularly

2. **Input Validation**
   - Implement proper JSON schema validation for all inputs
   - Add try-catch blocks around all JSON.parse operations
   - Validate all user inputs on both client and server side

3. **CORS Configuration**
   - Replace wildcard CORS policy with specific allowed origins
   - Implement proper environment-based CORS configuration
   - Add CORS preflight handling

### Medium-term Improvements

1. **WebRTC Security**
   - Implement authentication for peer connections
   - Add data size limits for peer-to-peer transfers
   - Use TURN servers with authentication

2. **Data Encryption**
   - Encrypt sensitive data in client-side storage
   - Implement end-to-end encryption for game data
   - Use secure key derivation functions

3. **Rate Limiting**
   - Implement rate limiting on all Socket.IO events
   - Add connection throttling per IP address
   - Implement exponential backoff for failed connections

### Long-term Security Enhancements

1. **Authentication & Authorization**
   - Implement proper user authentication system
   - Add role-based access control for game actions
   - Server-side validation of all game state changes

2. **Security Monitoring**
   - Add security event logging
   - Implement intrusion detection
   - Monitor for unusual network patterns

3. **Secure Architecture**
   - Move to server-authoritative game state model
   - Implement proper session management
   - Add security headers and CSP policies

## Testing Recommendations

### Security Testing
1. **Penetration Testing**
   - Test WebRTC peer connections for vulnerabilities
   - Validate input sanitization across all endpoints
   - Test for common web application vulnerabilities

2. **Dependency Testing**
   - Regular vulnerability scanning
   - Automated dependency updates with testing
   - Security regression testing

3. **Network Security Testing**
   - Test CORS policy implementation
   - Validate WebSocket security
   - Test for DoS vulnerabilities

## Conclusion

While Owlbear Rodeo Legacy is intended for personal use, the security vulnerabilities identified present significant risks. The most critical issues involve dependency vulnerabilities and unsafe input handling that could lead to remote code execution or denial of service attacks.

Given the legacy nature of this codebase and the authors' own acknowledgment of architectural issues, users should consider:

1. Using this application only in trusted, isolated environments
2. Implementing additional security measures at the network level
3. Regular monitoring for security updates and patches
4. Considering migration to the newer, more secure Owlbear Rodeo 2.0

For production or public-facing deployments, a comprehensive security overhaul would be required to address the identified vulnerabilities.