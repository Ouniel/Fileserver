# <img width="40" height="40" alt="安全文件传输服务" src="https://github.com/user-attachments/assets/36bd8274-1a7a-45d8-97f3-d99eeaf3c907" /> Fileserver

[English Version](README_EN.md)

这是一个基于 Go 语言开发的生产级 HTTP 文件服务器。它摒弃了传统的固定密码认证，集成了 Basic Auth、TOTP 2FA 和 RSA-PSS 签名三种安全认证机制，为您的文件传输提供从简单到高安全的多种选择。

## 主要功能

- **🔐 多种认证方式**：支持 Basic Auth、TOTP 2FA、RSA-PSS 签名认证，满足不同安全需求
- **📂 文件管理**：支持文件上传、下载及目录浏览
- **智能下载**：自动设置 `Content-Disposition`，支持 `curl -OJ` 自动保存原始文件名
- **🛡️ 安全防护**：内置路径穿越（Path Traversal）检测，防止访问非授权目录；bcrypt 密码哈希；常量时间比较防时序攻击
- **📝 双写日志**：访问记录同时输出到终端标准输出和 `logs/access.log` 文件，便于审计
- **🌐 跨平台支持**：完美兼容 Windows、Linux 和 macOS

## 使用示例

### 下载文件：

```bash
# Basic Auth 模式
# -u 指定用户名:密码
# -OJ 使用服务器返回的文件名保存
curl -OJ -u admin:123456 http://IP:8080/file.txt

# TOTP 2FA 模式（密码为6位动态验证码）
curl -OJ -u admin:123456 http://IP:8080/file.txt

# RSA 签名模式（使用快捷脚本）
./fcurl.sh http://IP:8080/file.txt
```

### 上传文件：

```bash
# Basic Auth / TOTP 模式
curl -u admin:123456 -F "file=@local_file.txt" http://IP:8080/upload

# RSA 签名模式暂不支持上传
```

### 列目录：

```bash
# Basic Auth / TOTP 模式
curl -u admin:123456 'http://IP:8080/list?path=/'

# RSA 签名模式（使用快捷脚本）
./fcurl.sh http://IP:8080/
```

## 快速开始

### 1. 安装依赖

```bash
go mod tidy
```

### 2. 编译

```bash
go build -o fileserver fileserver.go
```

### 3. 运行

```bash
./fileserver -port 8080 -dir /data/files
```

### 4. 选择认证方式

启动后会显示交互式菜单：

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    🔐 Fileserver 🔐                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

请选择认证方式：

  [1] Basic Auth    - 用户名密码认证 (简单)
  [2] TOTP 2FA      - 动态验证码认证 (安全)
  [3] RSA Signature - RSA签名认证 (最安全，支持curl/wget)

请输入选项 (1-3):
```

## 认证方式详解

### 1. Basic Auth（简单认证）

适用场景：内部网络、快速部署、低安全要求

特点：
- 用户名密码认证
- 密码使用 bcrypt 哈希存储
- 支持上传、下载、列目录

配置流程：
1. 输入用户名（默认：admin）
2. 输入密码（默认：123456，生产环境请修改）

### 2. TOTP 2FA（双因素认证）

适用场景：需要额外安全层、防止密码泄露

特点：
- 使用 Google Authenticator 生成6位动态验证码
- 支持自动生成或手动输入密钥
- 支持上传、下载、列目录

配置流程：
1. 输入用户名（默认：admin）
2. 选择密钥配置方式：
   - [1] 自动生成新的密钥
   - [2] 手动输入已有密钥
3. 使用 Google Authenticator 扫描密钥

### 3. RSA Signature（签名认证）

适用场景：最高安全要求、自动化脚本、API调用

特点：
- RSA-PSS 签名验证
- 支持自动生成密钥对或手动输入公钥
- 防重放攻击（时间戳验证）
- 兼容标准 curl/wget 命令
- 仅支持下载和列目录

配置流程：
1. 选择密钥配置方式：
   - [1] 自动生成密钥对（推荐）
   - [2] 手动输入已有公钥
2. 输入客户端ID
3. 自动生成模式下：复制私钥到 sign.go 文件
4. 手动输入模式下：粘贴 PEM 格式公钥

客户端使用：
```bash
# 使用快捷脚本（推荐）
./fcurl.sh http://IP:8080/file.txt

# 或使用签名工具生成URL后下载
./sign http://IP:8080/file.txt
# 然后使用生成的完整URL下载
curl -OJ 'http://IP:8080/download?path=/file.txt&id=client1&ts=...&sig=...'
```

## 命令行参数

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-port` | 服务端口 | 8080 | `-port 9090` |
| `-dir` | 服务目录 | 当前目录 | `-dir /data/files` |

## 项目结构

```
fileserver/
├── fileserver.go    # 统一服务端（支持三种认证方式）
├── sign.go          # RSA签名工具（私钥硬编码）
├── genkey.go        # 密钥对生成工具
├── fcurl.bat        # Windows快捷脚本
├── fcurl.sh         # Linux/macOS快捷脚本
├── go.mod           # Go模块定义
├── README.md        # 中文使用说明
├── README_EN.md     # 英文使用说明
└── logs/            # 日志目录（自动创建）
```

## 安全特性

- **bcrypt 密码哈希**：Basic Auth 密码使用 bcrypt 算法加密存储
- **常量时间比较**：防止时序攻击
- **输入长度验证**：限制用户名、密码、客户端ID长度
- **RSA 密钥长度验证**：强制≥2048位
- **HTTP 超时设置**：防止慢攻击
- **Panic 恢复机制**：防止服务崩溃
- **日志脱敏**：过滤敏感参数
- **路径安全检查**：防止目录遍历攻击

## 生产部署建议

1. **修改默认凭证**：Basic Auth 和 TOTP 的默认配置必须修改
2. **使用 HTTPS**：生产环境应使用 TLS 加密传输
3. **限制访问IP**：使用防火墙限制可访问的IP地址
4. **定期更换密钥**：RSA 模式建议定期更换密钥对
5. **监控日志**：定期检查访问日志，发现异常访问

## 许可证 (License)

本项目基于 **Apache License 2.0** 开源。您可以自由地使用、修改和分发本软件，但在分发修改后的版本时需要保留原始版权声明和许可声明。

## ⚠️ 免责声明 (Disclaimer)

使用本工具前请务必阅读并同意以下条款：

- **合法用途**：本工具仅限用于托管、传输您拥有合法访问权限和所有权的文件。
- **隐私尊重**：严禁利用本工具在未经授权的情况下侵犯他人隐私或获取敏感数据。
- **系统安全**：请勿将本工具部署在涉及机密的生产环境关键路径中，或将敏感系统根目录暴露于公网。
- **性能影响**：大文件的上传与下载可能会占用大量服务器带宽与 I/O 资源，请评估对生产环境的影响。
- **风险自担**：本工具按"原样"提供，不包含任何明示或暗示的担保。因使用本工具导致的任何数据丢失、泄露、法律纠纷或系统问题，由用户自行承担。
