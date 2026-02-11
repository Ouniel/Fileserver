// sign.go - 客户端签名生成工具
// 用于生成带签名的URL，供curl/wget等工具使用
// 使用RSA-PSS算法进行签名
// 用法: sign.exe <URL>

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 配置区 - 请修改以下配置
const (
	defaultClientID   = "testclient"
	defaultPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2IwS8ZR5n4mTF8ZBOCwbXNXAFP6RFZUfc1pOocJ+0IQx/UJO
r7Ncl8ion+E1Ixq4l0SUEpn/6fglfhkYzxbblFqwnBTwwgBZ8cQaVy75dCOj40wi
csPC/4hnThCjgGFBCZUvvRJL7fvITADqCEvGSkpRH2YKDvlGReHtMnRbXrQQ+fjs
ZfDkwRdwtftJzgGo3LJ0CZNKRKHTvclHx7nXdT/U2SMQhfamRozdsBHh9nJS6pKe
lUlLQ+PkJoxiQyhhOoA4cMNJOuPq6pfE8WVEoWepYraOr21NiJ0gXgpKbqc16/CZ
3gQCWgyFF8t9BPAYuLmJrQadjI7BOslljYBJ0QIDAQABAoIBAAHIJuKvvRPtuQHL
8NQ+obvO0v4hw/t0v4oaUanaax63uNHZAaElr4v2UiCfMbasTQPgCECvMsjA8Pgr
qEvemyWsfvciWxxFBauli6VoaCTvxVb+durms71UiwFWLD8LdDjQkHK7GXpQTbw5
TObkLHZCkI5SL34RyH8dPrxYrjow6vdGvJdnzuro0aFISoVVmyCxqP615IA76u38
Gw27MfEAfmEPahmnK4l5q8XzrDbhB3hE0B0dPDkcl1/NBCs8d8Bwc2YZGUbbORZu
FFngFRKKpD+OwByPloLayK8UuQg7fdZrq088EwKXJ/QevpoJFb0penMVwP+93Qse
VGU86y0CgYEA2OB2EqDAX7njK8KL9usM8EwDQGpRQBo/96UbgaFTA9InIC2Q/hPB
viXhBrWpRTBYpFFTGT+4C6bUCKzHHqbd8we7tNPqQv86u3QtB+/ch+ahOG0ZbgtB
oAdvlAYrdH4grWZkizgh8vXlje8iwlZ3oYSIpkhr8HBiNM9A15+HlMsCgYEA/5xj
zbVNa0YumfjyiNWKUqSg2sTIUP8sjN1alcZDiVRGy0nofVo3QODlmxbmzwWg8BhO
j9gjpl4rsse5UMhj+d+AMygFR7PH2OFe8U9PEWBdwTgLGlJ4xP+xW/xvur5ePnGn
NnGDcXgTJhaSvUlARWY/8nmNsT4B9R60fa2LpFMCgYAgVnfEl0uX+nOxFrUgADRR
sEPb2v56fG+FUY0kaxWhwDgtSB4ShIei/qrrATNYKblN5wJpBWM/+YQsNvcJzv/R
ORn4AJExpDTxtoTwZgeQDAeGDl54Vh1W60Tr4W+hUx00PcxIJfqJ67hqzXl1WMdF
wilOAgZ2N4utLCoS/KqOuQKBgAXIuS1ve9gAl49eZcaY5m9mUEmDCHFkxNJPM/yN
pvuVj6CMBJnJj9SFAk0XIJPwsaqdMjHpFy1tlhmOkW/1iOWfnBwMPMpZlB0hRG+7
drOS9awoo3+t/BOhIZdOSAz2v9Uz5y/BM9M+f1huTFXCMZUgcjP/cihfmdW9IyJw
6ecHAoGAb9kkTHME0skl9YtLKTIQdzj9CLgQXJmz/SORuSLoF+ErmeNPH6q7lCp6
HYd6UAIKLzSxVIS6UtPtsPc5+3DBdzPzahD3gcfB/PcvSymkforQdPepCb92rTwm
p0rOnreltwN2Owdv/uQiax4LD8/7hI7wSM4D49bsOOm1x9iV5HM=
-----END RSA PRIVATE KEY-----`
)

// loadPrivateKey 从PEM字符串加载RSA私钥
func loadPrivateKey(pemContent string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		return nil, fmt.Errorf("PEM解码失败")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// 尝试PKCS1格式
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("不是RSA私钥")
	}

	return privateKey, nil
}

// generateSignature 生成RSA-PSS签名
func generateSignature(privateKey *rsa.PrivateKey, signString string) (string, error) {
	hash := sha256.Sum256([]byte(signString))

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return "", fmt.Errorf("签名失败: %w", err)
	}

	return base64.URLEncoding.EncodeToString(signature), nil
}

// detectAction 根据URL路径自动检测操作类型
func detectAction(path string) string {
	// 移除开头的斜杠
	path = strings.TrimPrefix(path, "/")

	// 检查路径是否以 /download 开头
	if strings.HasPrefix(path, "download") {
		return "download"
	}

	// 检查路径是否以 /list 开头
	if strings.HasPrefix(path, "list") {
		return "list"
	}

	// 默认认为是下载操作
	return "download"
}

// extractPathFromURL 从URL中提取文件/目录路径
func extractPathFromURL(parsedURL *url.URL) string {
	query := parsedURL.Query()
	path := query.Get("path")

	// 如果URL中没有path参数，尝试从URL路径解析
	if path == "" {
		urlPath := strings.TrimPrefix(parsedURL.Path, "/")

		// 移除 download/ 或 list/ 前缀
		if strings.HasPrefix(urlPath, "download/") {
			path = "/" + strings.TrimPrefix(urlPath, "download/")
		} else if strings.HasPrefix(urlPath, "list/") {
			path = "/" + strings.TrimPrefix(urlPath, "list/")
		}
	}

	// 确保路径以/开头
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return path
}

// buildSignedURL 构建带签名的完整URL
func buildSignedURL(serverURL, endpoint, path, clientID string, timestamp int64, signature string) string {
	return fmt.Sprintf("%s%s?path=%s&id=%s&ts=%d&sig=%s",
		serverURL,
		endpoint,
		url.QueryEscape(path),
		clientID,
		timestamp,
		signature,
	)
}

func main() {
	// 使用硬编码的配置
	clientID := defaultClientID

	// 获取URL参数
	args := os.Args[1:]
	if len(args) < 1 {
		fmt.Println("用法: sign.exe <URL>")
		fmt.Println("")
		fmt.Println("示例:")
		fmt.Println("  下载文件:")
		fmt.Println("    sign.exe http://127.0.0.1:8080/download/shared/test.txt")
		fmt.Println("")
		fmt.Println("  列目录:")
		fmt.Println("    sign.exe http://127.0.0.1:8080/list/shared/")
		fmt.Println("")
		fmt.Println("支持的URL格式:")
		fmt.Println("  - http://host:port/download/path/to/file    (自动识别为下载)")
		fmt.Println("  - http://host:port/list/path/to/dir/        (自动识别为列目录)")
		fmt.Println("")
		fmt.Println("配置信息:")
		fmt.Printf("  客户端ID: %s\n", defaultClientID)
		fmt.Println("  私钥: 已内置于代码中")
		os.Exit(1)
	}

	inputURL := args[0]

	// 解析输入的URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: URL解析失败: %v\n", err)
		os.Exit(1)
	}

	// 加载私钥（从硬编码的字符串）
	privateKey, err := loadPrivateKey(defaultPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	// 自动检测操作类型
	action := detectAction(parsedURL.Path)

	// 提取文件/目录路径
	path := extractPathFromURL(parsedURL)
	if path == "" {
		// 尝试从URL路径的最后部分提取
		urlPath := strings.TrimPrefix(parsedURL.Path, "/")
		parts := strings.SplitN(urlPath, "/", 2)
		if len(parts) >= 2 {
			path = "/" + parts[1]
		} else {
			path = "/"
		}
	}

	// 使用时间戳
	ts := time.Now().Unix()

	// 构造待签名字符串
	signString := fmt.Sprintf("path=%s&ts=%d&id=%s", path, ts, clientID)

	// 生成签名
	signature, err := generateSignature(privateKey, signString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	// 确定endpoint
	endpoint := "/" + action

	// 构建基础URL
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// 生成完整签名URL
	fullURL := buildSignedURL(baseURL, endpoint, path, clientID, ts, signature)

	// 输出结果
	fmt.Println("================== 原始信息 ==================")
	fmt.Printf("操作类型: %s\n", action)
	fmt.Printf("文件路径: %s\n", path)
	fmt.Printf("客户端ID: %s\n", clientID)
	fmt.Println("")
	fmt.Println("================== 签名URL ==================")
	fmt.Println(fullURL)
	fmt.Println("")
	fmt.Println("================== curl 命令 ==================")
	if action == "download" {
		fmt.Printf("curl -OJ '%s'\n", fullURL)
	} else {
		fmt.Printf("curl '%s'\n", fullURL)
	}
	fmt.Println("")
	fmt.Println("================== wget 命令 ==================")
	if action == "download" {
		fmt.Printf("wget --content-disposition '%s'\n", fullURL)
	} else {
		fmt.Printf("wget -qO- '%s'\n", fullURL)
	}
	fmt.Println("")
	fmt.Println("================== PowerShell 命令 ==================")
	if action == "download" {
		fmt.Printf("Invoke-WebRequest -Uri '%s' -OutFile '%s'\n", fullURL, filepath.Base(path))
	} else {
		fmt.Printf("Invoke-WebRequest -Uri '%s' -UseBasicParsing\n", fullURL)
	}
}
