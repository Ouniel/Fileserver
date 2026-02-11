// fileserver.go - Fileserver
// 支持多种认证方式：Basic Auth / TOTP 2FA / RSA签名
// 兼容Windows和Linux环境

package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// ==================== 配置区 ====================
const (
	defaultPort = "8080"          // 默认服务端口
	logsDir     = "./logs"        // 日志目录
	maxAge      = 5 * time.Minute // RSA签名有效期
)

// 认证方式
const (
	AuthBasic = iota
	AuthTOTP
	AuthRSA
)

// 动态配置变量（运行时设置）
var (
	basicUsername     string
	basicPasswordHash []byte // 使用 bcrypt 哈希存储
	totpUsername      string
	totpSecret        string
	rsaPublicKeys     = make(map[string]string)
	clientIDRegex     = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// ================================================

// 全局变量
var (
	logFile      *os.File
	logMutex     sync.Mutex
	serverPort   string
	rootDir      string
	authMode     int
	rsaKeys      map[string]*rsa.PublicKey
	rsaKeysMutex sync.RWMutex
)

// dualLog 双写日志：同时输出到终端和文件
func dualLog(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	fmt.Println(msg)
	if logFile != nil {
		logFile.WriteString(msg + "\n")
	}
}

// initLogger 初始化日志系统
func initLogger() error {
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}
	logPath := filepath.Join(logsDir, "access.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("初始化日志文件失败: %w", err)
	}
	logFile = file
	return nil
}

// getClientIP 获取客户端真实IP
func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		if idx := strings.Index(ip, ","); idx != -1 {
			return strings.TrimSpace(ip[:idx])
		}
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// sanitizeLogPath 清理日志路径中的敏感信息
func sanitizeLogPath(reqPath string) string {
	// 隐藏所有敏感参数
	sensitiveParams := []string{"sig", "password", "token", "secret", "key"}
	for _, param := range sensitiveParams {
		if strings.Contains(reqPath, param+"=") {
			// 使用正则替换参数值
			re := regexp.MustCompile(param + `=[^&]*`)
			reqPath = re.ReplaceAllString(reqPath, param+"=***")
		}
	}
	return reqPath
}

// logAccess 记录访问日志
// 自动过滤敏感信息，防止日志泄露
func logAccess(r *http.Request, operation, result string, statusCode int) {
	client := getClientIP(r)
	reqPath := r.URL.Path
	if r.URL.RawQuery != "" {
		reqPath += "?" + r.URL.RawQuery
	}

	// 清理敏感信息
	reqPath = sanitizeLogPath(reqPath)

	msg := fmt.Sprintf("【%s】 %s  %s  %s  %s %d",
		time.Now().Format("2006-01-02 15:04:05"),
		client,
		reqPath,
		operation,
		result,
		statusCode,
	)
	dualLog(msg)
}

// ==================== 认证中间件 ====================

// safeHandler 包装处理器，添加 panic 恢复机制
func safeHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// 记录 panic 信息
				log.Printf("[PANIC] %s %s: %v", r.Method, r.URL.Path, err)
				// 返回 500 错误，不暴露内部细节
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next(w, r)
	}
}

// authMiddleware 根据选择的认证方式返回对应的中间件
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	switch authMode {
	case AuthBasic:
		return basicAuthMiddleware(next)
	case AuthTOTP:
		return totpAuthMiddleware(next)
	case AuthRSA:
		return rsaAuthMiddleware(next)
	default:
		return basicAuthMiddleware(next)
	}
}

// basicAuthMiddleware Basic Auth 认证
// 使用 bcrypt 验证密码，常量时间比较防止时序攻击
func basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			logAccess(r, "认证失败", "Unauthorized", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="文件服务器"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 常量时间比较用户名
		if subtle.ConstantTimeCompare([]byte(user), []byte(basicUsername)) != 1 {
			logAccess(r, "认证失败", "Unauthorized", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="文件服务器"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// bcrypt 验证密码（内置常量时间比较）
		if err := bcrypt.CompareHashAndPassword(basicPasswordHash, []byte(pass)); err != nil {
			logAccess(r, "认证失败", "Unauthorized", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="文件服务器"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// totpAuthMiddleware TOTP 2FA 认证
// 使用常量时间比较用户名，防止时序攻击
func totpAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			logAccess(r, "认证失败", "Unauthorized (Invalid Code)", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="Google 2FA Required"`)
			http.Error(w, "Unauthorized: Please use your 6-digit 2FA code as the password.", http.StatusUnauthorized)
			return
		}

		// 常量时间比较用户名
		if subtle.ConstantTimeCompare([]byte(user), []byte(totpUsername)) != 1 {
			logAccess(r, "认证失败", "Unauthorized (Invalid Code)", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="Google 2FA Required"`)
			http.Error(w, "Unauthorized: Please use your 6-digit 2FA code as the password.", http.StatusUnauthorized)
			return
		}

		// TOTP 验证
		if !totp.Validate(pass, totpSecret) {
			logAccess(r, "认证失败", "Unauthorized (Invalid Code)", http.StatusUnauthorized)
			w.Header().Set("WWW-Authenticate", `Basic realm="Google 2FA Required"`)
			http.Error(w, "Unauthorized: Please use your 6-digit 2FA code as the password.", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// rsaAuthMiddleware RSA 签名认证
func rsaAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("id")
		timestampStr := r.URL.Query().Get("ts")
		signature := r.URL.Query().Get("sig")
		path := r.URL.Query().Get("path")

		if clientID == "" || timestampStr == "" || signature == "" {
			logAccess(r, "认证失败", "缺少必要参数", http.StatusForbidden)
			http.Error(w, "Missing parameters", http.StatusForbidden)
			return
		}

		if !isRSAClientRegistered(clientID) {
			logAccess(r, "认证失败", "Client not registered: "+clientID, http.StatusForbidden)
			http.Error(w, "Client not registered", http.StatusForbidden)
			return
		}

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			logAccess(r, "认证失败", "Invalid timestamp format", http.StatusForbidden)
			http.Error(w, "Invalid timestamp", http.StatusForbidden)
			return
		}

		if !validateTimestamp(timestamp) {
			logAccess(r, "认证失败", "Timestamp expired", http.StatusForbidden)
			http.Error(w, "Invalid timestamp", http.StatusForbidden)
			return
		}

		signString := fmt.Sprintf("path=%s&ts=%s&id=%s", path, timestampStr, clientID)
		pubKey, err := getRSAPublicKey(clientID)
		if err != nil {
			logAccess(r, "认证失败", "Failed to get public key", http.StatusForbidden)
			http.Error(w, "Client not registered", http.StatusForbidden)
			return
		}

		valid, err := verifyRSASignature(pubKey, signString, signature)
		if err != nil || !valid {
			logAccess(r, "认证失败", "Invalid signature", http.StatusForbidden)
			http.Error(w, "Invalid signature", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// ==================== RSA 相关函数 ====================

func parseRSAPublicKeys() error {
	rsaKeysMutex.Lock()
	defer rsaKeysMutex.Unlock()

	rsaKeys = make(map[string]*rsa.PublicKey)
	for clientID, pemStr := range rsaPublicKeys {
		// 验证 clientID 格式
		if len(clientID) < 1 || len(clientID) > 64 {
			return fmt.Errorf("客户端ID %s 长度必须在 1-64 字符之间", clientID)
		}
		if !clientIDRegex.MatchString(clientID) {
			return fmt.Errorf("客户端ID %s 只能包含字母、数字、下划线和连字符", clientID)
		}

		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return fmt.Errorf("解析客户端 %s 的公钥失败: PEM解码失败", clientID)
		}
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("解析客户端 %s 的公钥失败: %w", clientID, err)
		}
		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("客户端 %s 的公钥不是RSA公钥", clientID)
		}

		// 验证 RSA 密钥长度 >= 2048 位
		if rsaPubKey.N.BitLen() < 2048 {
			return fmt.Errorf("客户端 %s 的 RSA 密钥长度 %d 位，必须至少 2048 位", clientID, rsaPubKey.N.BitLen())
		}

		rsaKeys[clientID] = rsaPubKey
	}
	return nil
}

func getRSAPublicKey(clientID string) (*rsa.PublicKey, error) {
	rsaKeysMutex.RLock()
	defer rsaKeysMutex.RUnlock()
	pubKey, exists := rsaKeys[clientID]
	if !exists {
		return nil, fmt.Errorf("client %s not registered", clientID)
	}
	return pubKey, nil
}

// parseRSAPublicKey 解析单个RSA公钥（PEM格式）
func parseRSAPublicKey(pubKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解析PEM块")
	}

	var pubKey interface{}
	var err error

	switch block.Type {
	case "PUBLIC KEY":
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的公钥类型: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("公钥不是RSA类型")
	}

	// 验证密钥长度
	if rsaPubKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA密钥长度不足2048位")
	}

	return rsaPubKey, nil
}

func isRSAClientRegistered(clientID string) bool {
	_, err := getRSAPublicKey(clientID)
	return err == nil
}

func verifyRSASignature(pubKey *rsa.PublicKey, signString, signature string) (bool, error) {
	sigBytes, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return false, fmt.Errorf("签名解码失败: %w", err)
		}
	}
	hash := sha256.Sum256([]byte(signString))
	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], sigBytes, nil)
	if err != nil {
		return false, fmt.Errorf("签名验证失败: %w", err)
	}
	return true, nil
}

func validateTimestamp(timestamp int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= int64(maxAge.Seconds())
}

// ==================== 路径安全 ====================

func securePath(requestPath string) (string, error) {
	cleanPath := filepath.Clean(requestPath)
	cleanPath = strings.TrimPrefix(cleanPath, "/")
	cleanPath = strings.TrimPrefix(cleanPath, "\\")

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("获取根目录失败: %w", err)
	}

	fullPath := filepath.Join(absRoot, cleanPath)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("获取绝对路径失败: %w", err)
	}

	if runtime.GOOS == "windows" {
		absPath = strings.ToLower(absPath)
		absRoot = strings.ToLower(absRoot)
	}

	if !strings.HasPrefix(absPath+string(filepath.Separator), absRoot+string(filepath.Separator)) {
		return "", errors.New("路径超出允许范围")
	}

	execDir, _ := os.Executable()
	logsPath := filepath.Join(filepath.Dir(execDir), logsDir)
	absLogs, _ := filepath.Abs(logsPath)
	if runtime.GOOS == "windows" {
		absLogs = strings.ToLower(absLogs)
	}
	if strings.HasPrefix(absPath, absLogs) {
		return "", errors.New("禁止访问日志目录")
	}

	return fullPath, nil
}

// ==================== HTTP 处理器 ====================

func handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logAccess(r, r.Method, "Method Not Allowed", http.StatusMethodNotAllowed)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var filePath string
	var err error

	if authMode == AuthRSA {
		path := r.URL.Query().Get("path")
		if path == "" {
			logAccess(r, "下载", "Missing path parameter", http.StatusBadRequest)
			http.Error(w, "Missing path parameter", http.StatusBadRequest)
			return
		}
		filePath, err = securePath(path)
	} else {
		clean := path.Clean(r.URL.Path)
		if clean == "/" {
			clean = "/index.html"
		}
		filePath = filepath.Join(rootDir, clean)
		var secureErr error
		filePath, secureErr = securePath(clean)
		if secureErr != nil {
			err = secureErr
		}
	}

	if err != nil {
		logAccess(r, "下载", "Forbidden: "+err.Error(), http.StatusForbidden)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			logAccess(r, "下载", "Not Found", http.StatusNotFound)
			http.NotFound(w, r)
			return
		}
		logAccess(r, "下载", "Internal Server Error", http.StatusInternalServerError)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		logAccess(r, "下载", "Path is a directory", http.StatusBadRequest)
		http.Error(w, "Path is a directory", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filePath)))
	logAccess(r, "下载", filepath.Base(filePath), http.StatusOK)
	http.ServeFile(w, r, filePath)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		logAccess(r, r.Method, "Method Not Allowed", http.StatusMethodNotAllowed)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var dirPath string
	var err error

	if authMode == AuthRSA {
		path := r.URL.Query().Get("path")
		if path == "" {
			path = "."
		}
		dirPath, err = securePath(path)
	} else {
		sub := r.URL.Query().Get("path")
		dirPath = filepath.Join(rootDir, path.Clean(sub))
		dirPath, err = securePath(sub)
	}

	if err != nil {
		logAccess(r, "列目录", "Forbidden: "+err.Error(), http.StatusForbidden)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			logAccess(r, "列目录", "Not Found", http.StatusNotFound)
			http.NotFound(w, r)
			return
		}
		logAccess(r, "列目录", "Internal Server Error", http.StatusInternalServerError)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !info.IsDir() {
		logAccess(r, "列目录", "Path is not a directory", http.StatusBadRequest)
		http.Error(w, "Path is not a directory", http.StatusBadRequest)
		return
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		logAccess(r, "列目录", "Failed to read directory", http.StatusInternalServerError)
		http.Error(w, "Failed to read directory", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		fmt.Fprintln(w, name)
	}
	logAccess(r, "列目录", dirPath, http.StatusOK)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logAccess(r, "上传", "Method Not Allowed", http.StatusMethodNotAllowed)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(50 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		logAccess(r, "上传", "无文件或太大", http.StatusBadRequest)
		http.Error(w, "上传失败", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := header.Filename
	if strings.ContainsAny(filename, "/\\") {
		logAccess(r, "上传", "非法文件名", http.StatusBadRequest)
		http.Error(w, "非法文件名", http.StatusBadRequest)
		return
	}

	dstPath := filepath.Join(rootDir, filename)
	if _, err := securePath(filename); err != nil {
		logAccess(r, "上传", "禁止路径", http.StatusForbidden)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		logAccess(r, "上传", "创建文件失败", http.StatusInternalServerError)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	io.Copy(dst, file)
	logAccess(r, "上传", filename+" 成功", http.StatusOK)
	fmt.Fprintf(w, "上传成功: %s (%d bytes)\n", filename, header.Size)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// ==================== 交互式选择 ====================

// ANSI颜色代码
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// ASCII艺术字
var asciiBanner = `
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗██╗██╗     ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗     ║
║   ██╔════╝██║██║     ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗    ║
║   █████╗  ██║██║     █████╗  █████╗  ██████╔╝██║   ██║█████╗  ██████╔╝    ║
║   ██╔══╝  ██║██║     ██╔══╝  ██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗    ║
║   ██║     ██║███████╗███████╗███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║    ║
║   ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝    ║
║                                                                           ║
║                         🔐 Fileserver 🔐                                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
`

// 打印带颜色的文本
func printColor(color string, format string, args ...interface{}) {
	fmt.Printf(color+format+ColorReset, args...)
}

// 打印步骤
func printStep(step int, total int, icon string, title string, detail string) {
	progress := fmt.Sprintf("[%d/%d]", step, total)
	printColor(ColorCyan, "  %-8s ", progress)
	printColor(ColorGreen, "%s ", icon)
	printColor(ColorBold+ColorWhite, "%s", title)
	if detail != "" {
		printColor(ColorYellow, " %s", detail)
	}
	fmt.Println()
}

// 打印信息项
func printInfo(label string, value string) {
	printColor(ColorBlue, "  ◆ %-15s ", label)
	printColor(ColorWhite, "%s\n", value)
}

// 打印分隔线
func printDivider() {
	printColor(ColorCyan, "  ─────────────────────────────────────────────────────────\n")
}

func printBanner() {
	fmt.Println()
	printColor(ColorCyan, "%s\n", asciiBanner)
}

func readInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func selectAuthMode() int {
	printBanner()

	printStep(1, 5, "⚙️", "初始化系统", "")
	time.Sleep(200 * time.Millisecond)

	printStep(2, 5, "🔐", "选择认证方式", "")
	fmt.Println()
	printColor(ColorYellow, "    ┌─────────────────────────────────────────────────────┐\n")
	printColor(ColorYellow, "    │  [1] Basic Auth    - 用户名密码认证 (简单)          │\n")
	printColor(ColorYellow, "    │  [2] TOTP 2FA      - 动态验证码认证 (安全)          │\n")
	printColor(ColorYellow, "    │  [3] RSA Signature - RSA签名认证 (最安全)           │\n")
	printColor(ColorYellow, "    └─────────────────────────────────────────────────────┘\n")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	printColor(ColorCyan, "  ➤ 请输入选项 (1-3): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		printStep(3, 5, "✓", "已选择", "Basic Auth")
		return AuthBasic
	case "2":
		printStep(3, 5, "✓", "已选择", "TOTP 2FA")
		return AuthTOTP
	case "3":
		printStep(3, 5, "✓", "已选择", "RSA Signature")
		return AuthRSA
	default:
		printStep(3, 5, "⚠", "无效选项", "使用默认 Basic Auth")
		return AuthBasic
	}
}

func configureBasicAuth() {
	printDivider()
	printStep(4, 5, "🔑", "Basic Auth 配置", "")
	fmt.Println()

	// 输入并验证用户名
	for {
		printColor(ColorCyan, "  ➤ 请输入用户名 (默认: admin): ")
		basicUsername = readInput("")
		if basicUsername == "" {
			basicUsername = "admin"
		}

		// 验证用户名长度
		if len(basicUsername) < 1 || len(basicUsername) > 128 {
			printColor(ColorRed, "  ✗ 用户名长度必须在 1-128 字符之间\n")
			continue
		}
		break
	}

	// 输入并验证密码
	var password string
	for {
		printColor(ColorCyan, "  ➤ 请输入密码 (默认: 123456): ")
		password = readInput("")
		if password == "" {
			password = "123456"
		}

		// 验证密码长度
		if len(password) < 1 || len(password) > 128 {
			printColor(ColorRed, "  ✗ 密码长度必须在 1-128 字符之间\n")
			continue
		}
		break
	}

	// 使用 bcrypt 生成密码哈希
	var err error
	basicPasswordHash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("生成密码哈希失败: %v", err)
	}

	fmt.Println()
	printStep(5, 5, "✅", "配置完成", "")
	printInfo("用户名", basicUsername)
	printInfo("密码", strings.Repeat("*", len(password)))
	printColor(ColorGreen, "  🔐 密码已使用 bcrypt 哈希存储\n")
}

func configureTOTP() {
	printDivider()
	printStep(4, 5, "🔑", "TOTP 2FA 配置", "")
	fmt.Println()

	// 输入并验证用户名
	for {
		printColor(ColorCyan, "  ➤ 请输入用户名 (默认: admin): ")
		totpUsername = readInput("")
		if totpUsername == "" {
			totpUsername = "admin"
		}

		// 验证用户名长度
		if len(totpUsername) < 1 || len(totpUsername) > 128 {
			printColor(ColorRed, "  ✗ 用户名长度必须在 1-128 字符之间\n")
			continue
		}
		break
	}

	fmt.Println()
	printColor(ColorYellow, "    ┌─────────────────────────────────────────────────┐\n")
	printColor(ColorYellow, "    │  TOTP密钥配置选项：                              │\n")
	printColor(ColorYellow, "    │  [1] 自动生成新的密钥                            │\n")
	printColor(ColorYellow, "    │  [2] 手动输入已有密钥                            │\n")
	printColor(ColorYellow, "    └─────────────────────────────────────────────────┘\n")
	fmt.Println()

	printColor(ColorCyan, "  ➤ 请选择 (1-2, 默认: 1): ")
	choice := readInput("")

	if choice == "2" {
		printColor(ColorCyan, "  ➤ 请输入TOTP密钥: ")
		totpSecret = readInput("")
		if totpSecret == "" {
			printColor(ColorYellow, "  ⚠ 警告: 密钥为空，将自动生成\n")
			totpSecret = generateTOTPSecret()
		}
	} else {
		totpSecret = generateTOTPSecret()
	}

	fmt.Println()
	printStep(5, 5, "✅", "配置完成", "")
	printInfo("用户名", totpUsername)
	printInfo("TOTP密钥", totpSecret)
	fmt.Println()
	printColor(ColorGreen, "  📱 请使用 Google Authenticator 或类似APP扫描以下密钥\n")
	printColor(ColorCyan, "     密钥: %s\n", totpSecret)
}

func generateTOTPSecret() string {
	// 生成20字节随机密钥（TOTP标准），Base32编码
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		// 如果随机数生成失败，使用备用方案
		for i := range secret {
			secret[i] = byte(65 + (i*7)%26)
		}
	}
	// 使用无填充的Base32编码，并确保只包含有效字符
	encoded := base32.StdEncoding.EncodeToString(secret)
	// 移除填充符 '='
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

func configureRSA() {
	printDivider()
	printStep(4, 5, "🔑", "RSA 公钥配置", "")
	fmt.Println()

	printColor(ColorYellow, "    ┌─────────────────────────────────────────────────┐\n")
	printColor(ColorYellow, "    │  RSA密钥配置选项：                               │\n")
	printColor(ColorYellow, "    │  [1] 自动生成密钥对（推荐）                       │\n")
	printColor(ColorYellow, "    │  [2] 手动输入已有公钥                            │\n")
	printColor(ColorYellow, "    └─────────────────────────────────────────────────┘\n")
	fmt.Println()

	printColor(ColorCyan, "  ➤ 请选择 (1-2, 默认: 1): ")
	choice := readInput("")

	if choice == "2" {
		// 手动输入公钥模式
		configureRSAManual()
	} else {
		// 自动生成密钥对模式
		configureRSAAuto()
	}

	fmt.Println()
	printStep(5, 5, "✅", "配置完成", fmt.Sprintf("已注册 %d 个客户端", len(rsaPublicKeys)))
	for id := range rsaPublicKeys {
		printInfo("客户端", id)
	}
}

func showAuthInfo() {
	fmt.Println()
	printDivider()
	printStep(0, 0, "📋", "服务配置摘要", "")
	fmt.Println()

	switch authMode {
	case AuthBasic:
		printInfo("认证方式", "Basic Auth")
		printInfo("用户名", basicUsername)
		printInfo("密码", "[已加密存储]")
		fmt.Println()
		printColor(ColorGreen, "  📖 使用示例:\n")
		printColor(ColorWhite, "     下载:   curl -OJ -u %s:<密码> http://IP:%s/file.txt\n", basicUsername, serverPort)
		printColor(ColorWhite, "     列目录: curl -u %s:<密码> 'http://IP:%s/list?path=/'\n", basicUsername, serverPort)
		printColor(ColorWhite, "     上传:   curl -u %s:<密码> -F 'file=@a.txt' http://IP:%s/upload\n", basicUsername, serverPort)

	case AuthTOTP:
		printInfo("认证方式", "TOTP 2FA (Google Authenticator)")
		printInfo("用户名", totpUsername)
		printInfo("TOTP密钥", totpSecret)
		fmt.Println()
		printColor(ColorGreen, "  📖 使用示例:\n")
		printColor(ColorWhite, "     下载:   curl -OJ -u %s:6位验证码 http://IP:%s/file.txt\n", totpUsername, serverPort)
		printColor(ColorWhite, "     列目录: curl -u %s:6位验证码 'http://IP:%s/list?path=/'\n", totpUsername, serverPort)
		printColor(ColorWhite, "     上传:   curl -u %s:6位验证码 -F 'file=@a.txt' http://IP:%s/upload\n", totpUsername, serverPort)

	case AuthRSA:
		printInfo("认证方式", "RSA-PSS 签名认证")
		printInfo("已注册客户端", fmt.Sprintf("%d 个", len(rsaPublicKeys)))
		for id := range rsaPublicKeys {
			printInfo("  ├─ 客户端", id)
		}
		fmt.Println()
		printColor(ColorGreen, "  📖 使用示例:\n")
		printColor(ColorWhite, "     1. 生成签名URL:\n")
		printColor(ColorCyan, "        ./sign http://IP:%s/download/file.txt\n", serverPort)
		printColor(ColorWhite, "     2. 下载:\n")
		printColor(ColorCyan, "        curl -OJ 'http://IP:%s/download?path=/file.txt&id=client1&ts=...&sig=...'\n", serverPort)
		printColor(ColorWhite, "     3. 列目录:\n")
		printColor(ColorCyan, "        curl 'http://IP:%s/list?path=/&id=client1&ts=...&sig=...'\n", serverPort)
		fmt.Println()
		printColor(ColorYellow, "     💡 或使用快捷脚本:\n")
		printColor(ColorCyan, "        ./fcurl.sh http://IP:%s/file.txt\n", serverPort)
	}
	fmt.Println()
}

// configureRSAAuto 自动生成RSA密钥对
func configureRSAAuto() {
	fmt.Println()
	printColor(ColorGreen, "  🔄 自动生成RSA密钥对模式\n")
	fmt.Println()

	for {
		printColor(ColorCyan, "  ➤ 请输入客户端ID (空行结束): ")
		clientID := readInput("")
		if clientID == "" {
			break
		}

		// 验证 clientID 长度
		if len(clientID) < 1 || len(clientID) > 64 {
			printColor(ColorRed, "  ✗ 客户端ID长度必须在 1-64 字符之间\n")
			continue
		}

		// 验证 clientID 格式
		if !clientIDRegex.MatchString(clientID) {
			printColor(ColorRed, "  ✗ 客户端ID只能包含字母、数字、下划线和连字符\n")
			continue
		}

		// 生成RSA密钥对
		privKey, pubKey, err := generateRSAKeyPair()
		if err != nil {
			printColor(ColorRed, "  ✗ 生成密钥对失败: %v\n", err)
			continue
		}

		// 存储公钥
		rsaPublicKeys[clientID] = pubKey

		// 显示生成的密钥
		fmt.Println()
		printStep(0, 0, "✓", "已生成密钥对", clientID)
		fmt.Println()
		printColor(ColorYellow, "  ┌─────────────────────────────────────────────────────────┐\n")
		printColor(ColorYellow, "  │  客户端公钥 (已注册到服务器):                            │\n")
		printColor(ColorYellow, "  └─────────────────────────────────────────────────────────┘\n")
		printColor(ColorCyan, "%s\n", pubKey)
		fmt.Println()
		printColor(ColorYellow, "  ┌─────────────────────────────────────────────────────────┐\n")
		printColor(ColorYellow, "  │  客户端私钥 (请复制保存到客户端 sign.go 中):              │\n")
		printColor(ColorYellow, "  └─────────────────────────────────────────────────────────┘\n")
		printColor(ColorCyan, "%s\n", privKey)
		fmt.Println()
		printColor(ColorGreen, "  ✅ 公钥已注册到服务器，私钥请妥善保管并配置到客户端\n")
		fmt.Println()
	}

	if len(rsaPublicKeys) == 0 {
		printColor(ColorYellow, "  ⚠ 警告: 未配置任何客户端，将生成默认测试客户端\n")
		fmt.Println()

		clientID := "testclient"
		privKey, pubKey, err := generateRSAKeyPair()
		if err != nil {
			log.Fatalf("生成默认密钥对失败: %v", err)
		}

		rsaPublicKeys[clientID] = pubKey

		printStep(0, 0, "✓", "已生成默认密钥对", clientID)
		fmt.Println()
		printColor(ColorYellow, "  ┌─────────────────────────────────────────────────────────┐\n")
		printColor(ColorYellow, "  │  客户端公钥 (已注册到服务器):                            │\n")
		printColor(ColorYellow, "  └─────────────────────────────────────────────────────────┘\n")
		printColor(ColorCyan, "%s\n", pubKey)
		fmt.Println()
		printColor(ColorYellow, "  ┌─────────────────────────────────────────────────────────┐\n")
		printColor(ColorYellow, "  │  客户端私钥 (请复制保存到客户端 sign.go 中):              │\n")
		printColor(ColorYellow, "  └─────────────────────────────────────────────────────────┘\n")
		printColor(ColorCyan, "%s\n", privKey)
		fmt.Println()
	}

	fmt.Println()
	printStep(5, 5, "✅", "配置完成", fmt.Sprintf("已注册 %d 个客户端", len(rsaPublicKeys)))
	printColor(ColorGreen, "  📋 请将上述私钥复制到 sign.go 文件的 privateKeyPEM 变量中\n")
	printColor(ColorYellow, "  ⚠️  注意: 如需再次使用相同客户端ID，请保存对应的公钥\n")
}

// configureRSAManual 手动输入公钥
func configureRSAManual() {
	fmt.Println()
	printColor(ColorGreen, "  📝 手动输入公钥模式\n")
	printColor(ColorYellow, "  请逐个添加客户端公钥，输入空行结束\n")
	printColor(ColorYellow, "  客户端ID要求：1-64字符，只允许字母、数字、下划线和连字符\n")
	fmt.Println()

	for {
		printColor(ColorCyan, "  ➤ 请输入客户端ID (空行结束): ")
		clientID := readInput("")
		if clientID == "" {
			break
		}

		// 验证 clientID 长度
		if len(clientID) < 1 || len(clientID) > 64 {
			printColor(ColorRed, "  ✗ 客户端ID长度必须在 1-64 字符之间\n")
			continue
		}

		// 验证 clientID 格式
		if !clientIDRegex.MatchString(clientID) {
			printColor(ColorRed, "  ✗ 客户端ID只能包含字母、数字、下划线和连字符\n")
			continue
		}

		printColor(ColorYellow, "  请输入公钥内容 (PEM格式，输入空行结束)：\n")
		var pubKeyLines []string
		for {
			line := readInput("")
			if line == "" {
				break
			}
			pubKeyLines = append(pubKeyLines, line)
		}

		if len(pubKeyLines) > 0 {
			pubKey := strings.Join(pubKeyLines, "\n")
			// 验证公钥格式
			if _, err := parseRSAPublicKey(pubKey); err != nil {
				printColor(ColorRed, "  ✗ 公钥格式无效: %v\n", err)
				continue
			}
			rsaPublicKeys[clientID] = pubKey
			printStep(0, 0, "✓", "已添加客户端", clientID)
		} else {
			printColor(ColorRed, "  ✗ 公钥内容为空，跳过\n")
		}
		fmt.Println()
	}

	if len(rsaPublicKeys) == 0 {
		printColor(ColorYellow, "  ⚠ 警告: 未配置任何公钥，将添加默认测试客户端\n")
		fmt.Println()
		printColor(ColorCyan, "  ➤ 请输入测试客户端ID (默认: testclient): ")
		clientID := readInput("")
		if clientID == "" {
			clientID = "testclient"
		}
		printColor(ColorYellow, "  请输入公钥内容 (PEM格式)：\n")
		var pubKeyLines []string
		for {
			line := readInput("")
			if line == "" {
				break
			}
			pubKeyLines = append(pubKeyLines, line)
		}
		if len(pubKeyLines) > 0 {
			pubKey := strings.Join(pubKeyLines, "\n")
			if _, err := parseRSAPublicKey(pubKey); err != nil {
				printColor(ColorRed, "  ✗ 公钥格式无效，跳过\n")
			} else {
				rsaPublicKeys[clientID] = pubKey
				printStep(0, 0, "✓", "已添加客户端", clientID)
			}
		}
	}

	fmt.Println()
	printStep(5, 5, "✅", "配置完成", fmt.Sprintf("已注册 %d 个客户端", len(rsaPublicKeys)))
}

// generateRSAKeyPair 生成RSA密钥对
func generateRSAKeyPair() (privateKey string, publicKey string, err error) {
	// 生成2048位RSA密钥
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("生成RSA密钥失败: %w", err)
	}

	// 序列化私钥为PKCS#1格式
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// 序列化公钥为PKIX格式
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("序列化公钥失败: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(privKeyPEM), string(pubKeyPEM), nil
}

// ==================== 主函数 ====================

func init() {
	flag.StringVar(&serverPort, "port", defaultPort, "服务端口")
	flag.StringVar(&rootDir, "dir", ".", "服务目录路径")
}

func main() {
	flag.Parse()

	// 获取绝对路径
	absRootDir, err := filepath.Abs(rootDir)
	if err != nil {
		log.Fatalf("获取目录绝对路径失败: %v", err)
	}
	rootDir = absRootDir

	// 初始化日志
	if err := initLogger(); err != nil {
		log.Fatalf("初始化日志失败: %v", err)
	}
	defer logFile.Close()

	// 检查目录
	info, err := os.Stat(rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf("目录不存在: %s", rootDir)
		}
		log.Fatalf("访问目录失败: %v", err)
	}
	if !info.IsDir() {
		log.Fatalf("指定的路径不是目录: %s", rootDir)
	}

	// 选择认证方式并配置
	authMode = selectAuthMode()

	switch authMode {
	case AuthBasic:
		configureBasicAuth()
	case AuthTOTP:
		configureTOTP()
	case AuthRSA:
		configureRSA()
		if err := parseRSAPublicKeys(); err != nil {
			log.Fatalf("解析RSA公钥失败: %v", err)
		}
	}

	// 设置路由（带 panic 恢复）
	http.HandleFunc("/health", safeHandler(handleHealth))

	if authMode == AuthRSA {
		http.HandleFunc("/download", safeHandler(authMiddleware(handleDownload)))
		http.HandleFunc("/list", safeHandler(authMiddleware(handleList)))
	} else {
		http.HandleFunc("/", safeHandler(authMiddleware(handleDownload)))
		http.HandleFunc("/list", safeHandler(authMiddleware(handleList)))
		http.HandleFunc("/upload", safeHandler(authMiddleware(handleUpload)))
	}

	// 启动服务
	fmt.Println()
	printDivider()
	printColor(ColorGreen+ColorBold, `
  ╔═══════════════════════════════════════════════════════════════════════════╗
  ║                                                                           ║
  ║                      🚀 Fileserver Started 🚀                            ║
  ║                                                                           ║
  ╚═══════════════════════════════════════════════════════════════════════════╝
`)
	printDivider()
	fmt.Println()

	printStep(0, 0, "🌐", "服务状态", "运行中")
	printInfo("监听端口", serverPort)
	printInfo("服务目录", rootDir)
	printInfo("日志目录", logsDir)

	// 同时记录到日志文件
	dualLog(fmt.Sprintf("服务器启动 - 端口: %s, 目录: %s, 认证: %d", serverPort, rootDir, authMode))

	showAuthInfo()

	printDivider()
	printColor(ColorGreen, "  ✨ 服务已就绪，等待连接...\n")
	printColor(ColorCyan, "  📊 按 Ctrl+C 停止服务\n")
	fmt.Println()

	// 创建带超时的 HTTP 服务器
	server := &http.Server{
		Addr:         ":" + serverPort,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
