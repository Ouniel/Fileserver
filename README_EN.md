# <img width="40" height="40" alt="Secure File Transfer Service" src="https://github.com/user-attachments/assets/36bd8274-1a7a-45d8-97f3-d99eeaf3c907" /> Fileserver

[中文版本](README.md)

A production-grade HTTP file server developed in Go. It abandons traditional fixed-password authentication and integrates three secure authentication mechanisms: Basic Auth, TOTP 2FA, and RSA-PSS Signature, providing multiple security options for your file transfers.

## Key Features

- **🔐 Multiple Authentication Methods**: Supports Basic Auth, TOTP 2FA, and RSA-PSS Signature to meet different security requirements
- **📂 File Management**: Supports file upload, download, and directory browsing
- **Smart Download**: Automatically sets `Content-Disposition`, supports `curl -OJ` to save with original filename
- **🛡️ Security Protection**: Built-in Path Traversal detection to prevent unauthorized directory access; bcrypt password hashing; constant-time comparison to prevent timing attacks
- **📝 Dual Logging**: Access logs output to both terminal stdout and `logs/access.log` file for audit purposes
- **🌐 Cross-Platform**: Fully compatible with Windows, Linux, and macOS

## Usage Examples

### Download File:

```bash
# Basic Auth mode
# -u specifies username:password
# -OJ saves with server-returned filename
curl -OJ -u admin:123456 http://IP:8080/file.txt

# TOTP 2FA mode (password is 6-digit dynamic code)
curl -OJ -u admin:123456 http://IP:8080/file.txt

# RSA Signature mode (using quick script)
./fcurl.sh http://IP:8080/file.txt
```

### Upload File:

```bash
# Basic Auth / TOTP mode
curl -u admin:123456 -F "file=@local_file.txt" http://IP:8080/upload

# RSA Signature mode does not support upload
```

### List Directory:

```bash
# Basic Auth / TOTP mode
curl -u admin:123456 'http://IP:8080/list?path=/'

# RSA Signature mode (using quick script)
./fcurl.sh http://IP:8080/
```

## Quick Start

### 1. Install Dependencies

```bash
go mod tidy
```

### 2. Build

```bash
go build -o fileserver fileserver.go
```

### 3. Run

```bash
./fileserver -port 8080 -dir /data/files
```

### 4. Select Authentication Method

An interactive menu will be displayed on startup:

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    🔐 Fileserver 🔐                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Please select authentication method:

  [1] Basic Auth    - Username/Password (Simple)
  [2] TOTP 2FA      - Dynamic Code (Secure)
  [3] RSA Signature - RSA Signature (Most Secure, supports curl/wget)

Enter option (1-3):
```

## Authentication Methods

### 1. Basic Auth (Simple Authentication)

**Use Case**: Internal networks, quick deployment, low security requirements

**Features**:
- Username and password authentication
- Password stored with bcrypt hashing
- Supports upload, download, and directory listing

**Configuration**:
1. Enter username (default: admin)
2. Enter password (default: 123456, please change in production)

### 2. TOTP 2FA (Two-Factor Authentication)

**Use Case**: Requires additional security layer, prevents password leakage

**Features**:
- Uses Google Authenticator to generate 6-digit dynamic codes
- Supports auto-generation or manual input of secret key
- Supports upload, download, and directory listing

**Configuration**:
1. Enter username (default: admin)
2. Select secret key configuration:
   - [1] Auto-generate new secret key
   - [2] Manually input existing secret key
3. Scan the secret key with Google Authenticator

### 3. RSA Signature (Signature Authentication)

**Use Case**: Highest security requirements, automated scripts, API calls

**Features**:
- RSA-PSS signature verification
- Supports auto-generation of key pairs or manual input of public key
- Replay attack prevention (timestamp verification)
- Compatible with standard curl/wget commands
- Only supports download and directory listing

**Configuration**:
1. Select key configuration method:
   - [1] Auto-generate key pair (Recommended)
   - [2] Manually input existing public key
2. Enter client ID
3. In auto-generate mode: copy private key to sign.go file
4. In manual input mode: paste PEM format public key

**Client Usage**:
```bash
# Using quick script (recommended)
./fcurl.sh http://IP:8080/file.txt

# Or use signature tool to generate URL then download
./sign http://IP:8080/file.txt
# Then use the generated complete URL to download
curl -OJ 'http://IP:8080/download?path=/file.txt&id=client1&ts=...&sig=...'
```

## Command Line Parameters

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `-port` | Service port | 8080 | `-port 9090` |
| `-dir` | Service directory | Current directory | `-dir /data/files` |

## Project Structure

```
fileserver/
├── fileserver.go    # Unified server (supports three auth methods)
├── sign.go          # RSA signature tool (private key hardcoded)
├── genkey.go        # Key pair generation tool
├── fcurl.bat        # Windows quick script
├── fcurl.sh         # Linux/macOS quick script
├── go.mod           # Go module definition
├── README.md        # Chinese documentation
├── README_EN.md     # English documentation
└── logs/            # Log directory (auto-created)
```

## Security Features

- **bcrypt Password Hashing**: Basic Auth passwords encrypted with bcrypt algorithm
- **Constant-Time Comparison**: Prevents timing attacks
- **Input Length Validation**: Limits username, password, and client ID length
- **RSA Key Length Validation**: Enforces ≥2048 bits
- **HTTP Timeout Settings**: Prevents slow attacks
- **Panic Recovery Mechanism**: Prevents service crashes
- **Log Sanitization**: Filters sensitive parameters
- **Path Security Check**: Prevents directory traversal attacks

## Production Deployment Recommendations

1. **Change Default Credentials**: Must modify default configurations for Basic Auth and TOTP
2. **Use HTTPS**: Production environments should use TLS encryption
3. **Restrict Access IP**: Use firewall to limit accessible IP addresses
4. **Rotate Keys Regularly**: RSA mode recommends periodic key pair rotation
5. **Monitor Logs**: Regularly check access logs for anomalies

## License

This project is open-sourced under **Apache License 2.0**. You are free to use, modify, and distribute this software, but must retain the original copyright and license notices when distributing modified versions.

## ⚠️ Disclaimer

Please read and agree to the following terms before using this tool:

- **Legal Use**: This tool is only for hosting and transferring files you have legal rights to access and own.
- **Privacy Respect**: Strictly prohibited from using this tool to infringe on others' privacy or obtain sensitive data without authorization.
- **System Security**: Do not deploy this tool in critical production environment paths involving confidential information, or expose sensitive system root directories to the public internet.
- **Performance Impact**: Large file uploads and downloads may consume significant server bandwidth and I/O resources; please assess the impact on production environments.
- **Risk Acceptance**: This tool is provided "as is" without any express or implied warranties. Users bear full responsibility for any data loss, leakage, legal disputes, or system issues caused by using this tool.
