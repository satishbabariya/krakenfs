# KrakenFS Security Features

KrakenFS now includes comprehensive authentication and authorization mechanisms to secure your distributed file system.

## Overview

The security system consists of three main components:

1. **Authentication** - Verifies user identity using JWT tokens
2. **Authorization** - Controls access using Role-Based Access Control (RBAC)
3. **Audit Logging** - Tracks all security events for compliance

## Features

### 🔐 Authentication

- **JWT-based authentication** with configurable token expiry
- **BCrypt password hashing** with configurable cost
- **Session management** with IP tracking and user agent logging
- **Default users** created automatically (admin/admin123, user/user123)

### 🛡️ Authorization

- **Role-Based Access Control (RBAC)** with predefined roles
- **Resource-level permissions** for files and directories
- **Action-based access control** (read, write, delete, admin)
- **Wildcard permissions** for administrative access

### 📋 Audit Logging

- **Comprehensive event logging** for all security events
- **JSON and text format** support
- **Configurable log levels** and output files
- **IP address tracking** and user agent logging

## Default Roles

### Admin Role
- **Full administrative access** to all resources
- **User management** capabilities
- **System configuration** access
- **All file operations** (read, write, delete)

### User Role
- **Read and write access** to files
- **No administrative privileges**
- **No user management** capabilities

### Viewer Role
- **Read-only access** to files
- **No write or delete permissions**
- **No administrative access**

## Configuration

### Security Configuration

```yaml
security:
  authentication:
    enable: true
    type: "jwt"
    jwt_secret: "your-secret-key-change-in-production"
    token_expiry: "24h"
    bcrypt_cost: 12
  
  authorization:
    enable: true
    rbac:
      enable: true
  
  audit:
    enable: true
    log_file: "/var/log/krakenfs/audit.log"
    log_level: "info"
    format: "json"
```

### API Configuration

```yaml
api:
  port: 8080
  host: "0.0.0.0"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
```

## API Endpoints

### Authentication Endpoints

#### POST /api/v1/auth/login
Authenticate a user and receive a JWT token.

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "admin",
    "username": "admin",
    "email": "admin@krakenfs.local",
    "role": "admin",
    "active": true
  },
  "expires_at": "2024-01-15T10:30:00Z",
  "session_id": "sess_1234567890"
}
```

#### POST /api/v1/auth/logout
Logout a user and invalidate the session.

**Request:**
```json
{
  "session_id": "sess_1234567890"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

#### POST /api/v1/auth/validate
Validate a JWT token.

**Request:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "valid": true,
  "user": {
    "id": "admin",
    "username": "admin",
    "role": "admin"
  }
}
```

#### GET /api/v1/auth/user
Get current user information and permissions.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "user": {
    "id": "admin",
    "username": "admin",
    "role": "admin"
  },
  "permissions": [
    {
      "id": "admin",
      "name": "Admin",
      "resource": "*",
      "action": "*"
    }
  ]
}
```

### Health Check

#### GET /health
Check API server health.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "krakenfs-api",
  "version": "1.0.0"
}
```

## Usage Examples

### Using cURL

#### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

#### Access Protected Resource
```bash
curl -X GET http://localhost:8080/api/v1/auth/user \
  -H "Authorization: Bearer <your-token>"
```

#### Validate Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"token": "<your-token>"}'
```

### Using JavaScript

```javascript
// Login
const loginResponse = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'admin',
    password: 'admin123'
  })
});

const { token } = await loginResponse.json();

// Use token for authenticated requests
const userResponse = await fetch('/api/v1/auth/user', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

## Security Best Practices

### 1. Change Default Credentials
Always change the default passwords in production:

```bash
# Default credentials (CHANGE THESE!)
admin: admin123
user: user123
```

### 2. Use Strong JWT Secret
Generate a strong JWT secret for production:

```bash
# Generate a strong secret
openssl rand -base64 32
```

### 3. Configure TLS
Enable TLS for secure communication:

```yaml
sync:
  tls:
    enable: true
    cert_file: "/etc/krakenfs/certs/server.crt"
    key_file: "/etc/krakenfs/certs/server.key"
```

### 4. Monitor Audit Logs
Regularly review audit logs for suspicious activity:

```bash
# Monitor audit logs
tail -f /var/log/krakenfs/audit.log
```

### 5. Network Security
- Use firewalls to restrict access to API endpoints
- Consider VPN access for remote administration
- Implement rate limiting for authentication endpoints

## Audit Events

The system logs the following security events:

### Authentication Events
- `login` - Successful user login
- `login_failed` - Failed login attempt
- `logout` - User logout
- `token_refresh` - Token refresh
- `token_expired` - Expired token usage

### Authorization Events
- `access_granted` - Access granted to resource
- `access_denied` - Access denied to resource
- `permission_check` - Permission verification

### File System Events
- `file_read` - File read operation
- `file_write` - File write operation
- `file_delete` - File deletion
- `file_create` - File creation
- `file_modify` - File modification

### User Management Events
- `user_create` - User creation
- `user_update` - User modification
- `user_delete` - User deletion
- `user_disable` - User deactivation
- `user_enable` - User activation

### System Events
- `config_change` - Configuration changes
- `system_start` - System startup
- `system_stop` - System shutdown

## Troubleshooting

### Common Issues

#### 1. Authentication Disabled
If authentication is not working, check:
- Security is enabled in configuration
- JWT secret is properly configured
- Default users are created

#### 2. Access Denied
If users can't access resources:
- Verify user role has appropriate permissions
- Check resource path permissions
- Review audit logs for denied access

#### 3. Token Issues
If JWT tokens are not working:
- Check token expiration time
- Verify JWT secret is consistent
- Ensure proper token format in requests

### Debug Commands

```bash
# Check security status
curl http://localhost:8080/health

# Test authentication
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# View audit logs
tail -f /var/log/krakenfs/audit.log | jq
```

## Migration from Previous Versions

If upgrading from a version without security:

1. **Backup your data** before upgrading
2. **Update configuration** to include security settings
3. **Change default passwords** immediately after upgrade
4. **Test authentication** with default users
5. **Configure proper permissions** for your use case

## Compliance

The security features support various compliance requirements:

- **Audit logging** for SOX compliance
- **Role-based access** for PCI DSS
- **User authentication** for HIPAA
- **Session management** for GDPR

## Support

For security-related issues:

1. Check the audit logs for detailed error information
2. Verify configuration settings
3. Test with default credentials
4. Review network connectivity and firewall rules

## Security Updates

Keep KrakenFS updated to receive security patches and improvements. Monitor the project repository for security advisories and updates. 