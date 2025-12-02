package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

var (
	logFile  *os.File
	logMutex sync.Mutex
)

// ==================== 配置区 ====================
const (
	USERNAME    = ""
	TOTP_SECRET = ""
)

// ================================================

// 双写日志：同时输出到终端和文件
func dualLog(msg string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	// 输出到终端
	fmt.Println(msg)

	// 输出到文件
	if logFile != nil {
		logFile.WriteString(msg + "\n")
	}
}

func initLogger() {
	if err := os.MkdirAll("logs", 0755); err != nil {
		log.Fatalf("创建日志目录失败: %v", err)
	}
	logPath := filepath.Join("logs", "access.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("初始化日志文件失败: %v", err)
	}
	logFile = file
}

// 获取客户端真实 IP（支持反向代理）
func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// 格式化日志并双写
func logAccess(r *http.Request, operation, result string, statusCode int) {
	client := getClientIP(r) + ":" + strings.Split(r.RemoteAddr, ":")[1]
	reqPath := r.URL.Path
	if r.URL.RawQuery != "" {
		reqPath += "?" + r.URL.RawQuery
	}

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

// Basic Auth 认证中间件 (修改为 TOTP 验证)
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// user 是用户名，pass 是用户输入的密码（这里需要输入 6 位动态验证码）
		user, pass, ok := r.BasicAuth()

		// 1. 验证用户名
		// 2. 验证 TOTP Code (将用户输入的 pass 作为验证码进行校验)
		// totp.Validate 会自动处理时间漂移，验证 pass 是否匹配 SECRET
		if !ok || user != USERNAME || !totp.Validate(pass, TOTP_SECRET) {

			// 只有认证失败才记录日志，避免日志过于冗长
			logAccess(r, "认证失败", "Unauthorized (Invalid Code)", http.StatusUnauthorized)

			w.Header().Set("WWW-Authenticate", `Basic realm="Google 2FA Required"`)
			http.Error(w, "Unauthorized: Please use your 6-digit 2FA code as the password.", http.StatusUnauthorized)
			return
		}

		// 认证通过
		next(w, r)
	}
}

func main() {
	initLogger()
	defer logFile.Close()

	rootDir, _ := os.Getwd()
	absLogs, _ := filepath.Abs(filepath.Join(rootDir, "logs"))

	securePath := func(p string) bool {
		absP, _ := filepath.Abs(p)
		absR, _ := filepath.Abs(rootDir)
		if !strings.HasPrefix(absP, absR) {
			return false
		}
		if strings.HasPrefix(absP, absLogs) {
			return false
		}
		return true
	}

	// 文件下载 & 目录索引
	http.HandleFunc("/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			logAccess(r, r.Method, "Method Not Allowed", 405)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		clean := path.Clean(r.URL.Path)
		if clean == "/" {
			clean = "/index.html"
		}
		filePath := filepath.Join(rootDir, clean)

		if !securePath(filePath) {
			logAccess(r, "下载", "Forbidden 路径穿越", http.StatusForbidden)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logAccess(r, "下载", clean+" Not Found", http.StatusNotFound)
			http.NotFound(w, r)
			return
		}

		// 核心修改：设置 Content-Disposition，让客户端默认使用文件名保存
		// 这样 curl -OJ 或浏览器下载时会自动使用文件的原始名称
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(filePath)))

		logAccess(r, "下载", clean, http.StatusOK)
		http.ServeFile(w, r, filePath)
	}))

	// 目录列表
	http.HandleFunc("/list", auth(func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("path")
		dir := filepath.Join(rootDir, path.Clean(sub))

		if !securePath(dir) {
			logAccess(r, "列目录", "Forbidden", http.StatusForbidden)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			logAccess(r, "列目录", sub+" 不存在或不是目录", http.StatusNotFound)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		entries, _ := os.ReadDir(dir)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() {
				name += "/"
			}
			fmt.Fprintln(w, name)
		}
		logAccess(r, "列目录", sub, http.StatusOK)
	}))

	// 文件上传
	http.HandleFunc("/upload", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			logAccess(r, "上传", "Method Not Allowed", 405)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		r.ParseMultipartForm(50 << 20) // 50MB
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
		if !securePath(dstPath) {
			logAccess(r, "上传", "禁止路径", http.StatusForbidden)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		dst, _ := os.Create(dstPath)
		defer dst.Close()
		io.Copy(dst, file)

		logAccess(r, "上传", filename+" 成功", http.StatusOK)
		fmt.Fprintf(w, "上传成功: %s (%d bytes)\n", filename, header.Size)
	}))

	dualLog("【服务器启动】 文件服务已就绪，监听 :80")
	// dualLog(fmt.Sprintf("【认证信息】 用户名: %s   密码: %s", USERNAME, TOTP_SECRET))
	dualLog("【操作示例】")
	dualLog("   下载: curl -OJ -u 账户:6位验证码 http://IP/file.txt")
	dualLog("   列目录: curl -u 账户:6位验证码 'http://IP/list?path=docs'")
	dualLog("   上传: curl -u 账户:6位验证码 -F 'file=@a.txt' http://IP/upload")

	log.Fatal(http.ListenAndServe(":80", nil))
}
