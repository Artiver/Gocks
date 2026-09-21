# 2026.9.21

1. Keep-Alive 连接复用 (http/proxy.go)
参考 gost 的 handleProxy 循环，在同一条 TCP 连接上依次处理多个 HTTP 请求。使用 http.ReadRequest/http.ReadResponse 正确解析请求/响应边界，通过 shouldCloseConnection 判断 HTTP/1.0 和 HTTP/1.1 的 Connection 头语义。

2. 请求头规范化处理 (http/proxy.go)
删除 Proxy-Authorization 和 Proxy-Connection 等 hop-by-hop 头，避免泄露给目标服务器
添加 Via: 1.1 gocks 头，遵循 RFC 7230 代理头规范
CONNECT 响应添加 Proxy-Agent: gocks 头

3. TransportData 修复 (utils/proxy.go)
goroutine 泄漏：等待两个方向都完成，通过 CloseWrite 半关闭通知对端
idle timeout：新增 copyWithIdleTimeout，每次读取前设置 300s 超时，防止空闲连接永久挂起
新增 ReaderConn/PrefixConn 类型，支持 bufio.Reader 缓冲数据和 mix 模式预读数据的透传

4. 错误响应规范化 (http/proxy.go, global/vars.go)
目标连接失败时返回 502 Bad Gateway（含 Connection: close），而非静默关闭。新增 GatewayTimeoutResponse 备用。

5. 首包读取改进 (http/proxy.go)
用 http.ReadRequest 替代固定 512 字节单次 Read，自动循环读取直到请求头完整（\r\n\r\n），支持任意大小的请求头。

6. 安全性改进
常量时间密码比较 (http/auth.go)：使用 crypto/subtle.ConstantTimeCompare 防止时序侧信道
上游拨号超时 (forward/http.go)：net.DialTimeout + SetDeadline 防止挂起
测试验证（11 个测试全部通过）
基本HTTP代理、Keep-Alive 连接复用、CONNECT 隧道
认证（407/200）、Proxy-Authorization 删除、Via 头添加
502 错误响应、常量时间比较、TransportData 无泄漏
