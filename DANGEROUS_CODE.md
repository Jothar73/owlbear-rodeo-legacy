# Suspicious and Dangerous Code Analysis - Owlbear Rodeo Legacy

This document identifies potentially dangerous code patterns, suspicious implementations, and security-sensitive areas that require careful scrutiny.

## High-Risk Code Patterns

### 1. Unsafe Data Deserialization

#### Unvalidated JSON Parsing
**Location:** `backend/src/entities/GameServer.ts:32-39`
```typescript
socket.on("signal", (data: string) => {
  try {
    const { to, signal } = JSON.parse(data);
    this.io.to(to).emit("signal", { from: socket.id, signal });
  } catch (error) {
    console.error("SIGNAL_ERROR", error);
  }
});
```

**Danger Level:** 🔴 **CRITICAL**

**Why This Is Dangerous:**
- Direct JSON parsing of user-controlled data
- No validation of parsed data structure
- Could lead to prototype pollution attacks
- Potential for DoS via malformed JSON
- Signal data forwarded without validation

**Attack Scenarios:**
1. Malicious JSON payload causing server crash
2. Prototype pollution affecting global objects
3. Invalid signal data corrupting WebRTC connections

---

#### Client-Side Settings Deserialization
**Location:** `src/helpers/Settings.ts:32-34`
```typescript
getAll(): any {
  return JSON.parse(this.storage.getItem(this.name));
}
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- Trusts localStorage data implicitly
- No validation of stored data structure
- Could be exploited via XSS attacks
- Type erasure with `any` return type

---

### 2. Direct Code Execution Patterns

#### Dynamic Function Construction (Potential)
**Location:** `src/helpers/Settings.ts:25-29`
```typescript
version(versionNumber: number, upgradeFunction: Function) {
  if (versionNumber > this.currentVersion) {
    this.currentVersion = versionNumber;
    this.setAll(upgradeFunction(this.getAll()));
  }
}
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- Accepts arbitrary function for execution
- No validation of function safety
- Could be exploited if function source is compromised
- Function executes with full context access

---

### 3. Unsafe Network Communication

#### Unrestricted CORS Configuration
**Location:** `docker-compose.yml:12`
```yaml
ALLOW_ORIGIN: ".*"
```

**Danger Level:** 🔴 **CRITICAL**

**Why This Is Dangerous:**
- Allows requests from any origin
- Bypasses same-origin policy protection
- Enables CSRF attacks
- Allows malicious sites to access game data

---

#### Unvalidated WebRTC Signal Forwarding
**Location:** `backend/src/entities/GameServer.ts:34-35`
```typescript
const { to, signal } = JSON.parse(data);
this.io.to(to).emit("signal", { from: socket.id, signal });
```

**Danger Level:** 🔴 **CRITICAL**

**Why This Is Dangerous:**
- No validation of `to` parameter
- Could route signals to unintended recipients
- Signal content not validated
- Potential for signal injection attacks

---

### 4. Resource Exhaustion Vulnerabilities

#### Unbounded Buffer Accumulation
**Location:** `src/network/Connection.ts:46-62`
```typescript
if (unpacked.__chunked) {
  let chunk = this.currentChunks[unpacked.id] || {
    data: [],
    count: 0,
    total: unpacked.total,
  };
  chunk.data[unpacked.index] = unpacked.data;
  chunk.count++;
  this.currentChunks[unpacked.id] = chunk;
  // No size limits or cleanup
}
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- No limit on chunk count or total size
- Could exhaust memory with large files
- No cleanup of abandoned transfers
- Potential for DoS attacks

---

#### Large HTTP Buffer Size
**Location:** `backend/src/index.ts:29`
```typescript
maxHttpBufferSize: 1e7, // 10MB
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- Very large buffer size (10MB)
- No per-client rate limiting
- Could exhaust server memory
- Enables DoS via large payloads

---

### 5. Authentication and Authorization Issues

#### Missing Environment Variable Validation
**Location:** `backend/src/entities/Global.ts:9`
```typescript
static ORIGIN_WHITELIST: string = process.env.ALLOW_ORIGIN!!;
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- Double assertion operator bypasses type checking
- No runtime validation of regex pattern
- Could crash server if environment variable is invalid
- Silent failure if environment variable is undefined

---

### 6. Client-Side Storage Vulnerabilities

#### Unencrypted Sensitive Data Storage
**Location:** `src/network/Session.ts:49-52`
```typescript
// Store party id and password for reconnect
_partyId?: string;
_password?: string;
```

**Danger Level:** 🟡 **HIGH**

**Why This Is Dangerous:**
- Passwords stored in plain text in memory
- No encryption for sensitive data
- Could be extracted via memory dumps
- Vulnerable to XSS attacks

---

### 7. DOM Manipulation Vulnerabilities

#### Unsafe DOM Query Construction
**Location:** `src/hooks/usePortal.ts:45-47`
```typescript
const existingParent: HTMLElement | null = document.querySelector(
  `#${id}`
);
```

**Danger Level:** 🟠 **MEDIUM**

**Why This Is Dangerous:**
- If `id` contains special characters, could break selector
- Potential for CSS injection if id is user-controlled
- No sanitization of id parameter

---

### 8. File Upload and Processing Risks

#### Unsafe URL Extraction from HTML
**Location:** `src/hooks/useImageDrop.ts:44-50`
```typescript
const html = event.dataTransfer?.getData("text/html");
if (html) {
  try {
    const urlMatch = html.match(/src="?([^"\s]+)"?\s*/);
    if (!urlMatch) {
      throw new Error("Unable to find image source");
    }
```

**Danger Level:** 🟠 **MEDIUM**

**Why This Is Dangerous:**
- Regex-based HTML parsing is unreliable
- Could extract unintended URLs
- No validation of URL safety
- Potential for serving malicious content

---

### 9. Cryptographic Weaknesses

#### Fixed Bcrypt Salt Rounds
**Location:** `backend/src/entities/Auth.ts:6`
```typescript
async createPasswordHash(
  password: string,
  saltRounds: number = 10
): Promise<string> {
```

**Danger Level:** 🟠 **MEDIUM**

**Why This Is Dangerous:**
- Salt rounds of 10 may be insufficient for current hardware
- No configuration option for different security levels
- Fixed value doesn't account for hardware improvements

---

### 10. Logic Bombs and Maintenance Issues

#### Logic Error in Cleanup
**Location:** `src/hooks/usePortal.ts:61-63`
```typescript
if (parentElem.childNodes.length === -1) {
  parentElem.remove();
}
```

**Danger Level:** 🟠 **MEDIUM**

**Why This Is Dangerous:**
- Condition can never be true (`length` is never -1)
- Indicates potential logic error
- Could lead to memory leaks
- Suggests insufficient testing

---

## Code Injection Vectors

### 1. WebRTC Signal Injection
**Location:** WebRTC signal handling

**Vulnerability:** Unvalidated signal data forwarded between peers
**Impact:** Could corrupt peer connections or inject malicious signaling data

### 2. Storage Injection
**Location:** localStorage/IndexedDB usage

**Vulnerability:** No validation of stored data integrity
**Impact:** Malicious data could be injected via XSS and persist across sessions

### 3. Message Pack Injection
**Location:** `src/network/Connection.ts:41`

**Vulnerability:** Direct deserialization of MessagePack data
**Impact:** Could lead to object injection if MessagePack decoder has vulnerabilities

## Denial of Service Vectors

### 1. Memory Exhaustion
- Large file transfers via WebRTC
- Unbounded chunk accumulation
- Large Socket.IO payloads

### 2. CPU Exhaustion
- Complex regex patterns in URL extraction
- JSON parsing of deeply nested objects
- Synchronous file operations

### 3. Connection Exhaustion
- No connection limits per IP
- No cleanup of stale connections
- WebRTC connection flooding

## Privacy and Information Disclosure

### 1. Console Logging
**Location:** Multiple files
```typescript
console.error("SIGNAL_ERROR", error);
console.log("Unhandled Rejection at: Promise", p, "reason:", reason);
```

**Risk:** Sensitive data leaked to console logs

### 2. Version Information Disclosure
**Location:** Multiple client-side files
```typescript
process.env.REACT_APP_VERSION
```

**Risk:** Version information aids attackers in identifying vulnerabilities

### 3. Error Message Disclosure
**Risk:** Detailed error messages could reveal system information

## Suspicious Code Patterns

### 1. Worker Thread Communication
**Location:** `src/contexts/DatabaseContext.tsx:25-27`
```typescript
const worker: Comlink.Remote<DatabaseWorkerService> = Comlink.wrap(
  new DatabaseWorker()
);
```

**Suspicion:** Worker threads have different security context
**Review:** Ensure worker doesn't have excessive privileges

### 2. Service Worker Registration
**Location:** `src/serviceWorker.ts`

**Suspicion:** Service workers can intercept network requests
**Review:** Verify service worker doesn't cache sensitive data

### 3. IndexedDB Direct Access
**Location:** `src/contexts/DatabaseContext.tsx:37`
```typescript
let testDBRequest = window.indexedDB.open("__test");
```

**Suspicion:** Direct IndexedDB usage bypasses framework protections
**Review:** Ensure proper error handling and data validation

## Recommendations for Dangerous Code

### Immediate Actions

1. **Input Validation**
   - Add JSON schema validation for all parsed data
   - Implement size limits for all inputs
   - Validate all WebRTC signals before forwarding

2. **CORS Configuration**
   - Replace wildcard CORS with specific allowed origins
   - Implement environment-based CORS configuration

3. **Resource Limits**
   - Add connection limits per IP
   - Implement transfer size limits
   - Add cleanup for abandoned operations

### Code Review Priorities

1. **Network Communication** - Review all data parsing and forwarding
2. **Storage Operations** - Validate all data before storage/retrieval
3. **Error Handling** - Ensure errors don't leak sensitive information
4. **Resource Management** - Check for resource exhaustion vulnerabilities

### Testing Recommendations

1. **Fuzzing** - Test JSON parsers with malformed data
2. **Load Testing** - Verify resource limits work correctly
3. **Security Testing** - Test for injection vulnerabilities
4. **Memory Testing** - Check for memory leaks under stress

## Conclusion

The Owlbear Rodeo Legacy codebase contains several patterns that could be exploited by malicious actors. While some issues are mitigated by the application's intended use case (personal/private use), they represent significant security risks if deployed in a public-facing environment.

**Priority for addressing:**
1. 🔴 Critical issues (CORS, JSON parsing) - Address immediately
2. 🟡 High issues (resource limits, validation) - Address before deployment
3. 🟠 Medium issues (crypto, logic errors) - Address during maintenance cycles

**Key principle:** Treat all external input as potentially malicious and validate accordingly.