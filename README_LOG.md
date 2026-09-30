# 2026.10.1

代码精简重构，目标是消除「同一个决定写在多处」，每步后 `go build ./... && go vet ./... && go test ./...` 全绿。

## 删除死代码
- `proxy/http/auth.go`：`parseHeaders` / `checkProxyAuthorization`（旧的手写头部解析，无调用方），
  连带删除 `config.CRLF`
- `protocol/socks5`：`UserPassRequest.String`、`UserPassResponse.String`、`Request.String`、
  `Reply.String`、`UDPHeader.String` 五个无人调用的 `String()`
- `tunnel`：`FormatAddress`（无调用方）、`TransportDataContext`（生产走 `TransportDataStats`）
- `constant`：`CR`、`Socks5HandleBytes`、`MaxHeaderBytes`、`ProxyAgentHeader/Value`、`UdpReadBytes`
- `config`：`GatewayTimeoutResponse`（原名「备用」，实际从未接线）
- `protocol/socks5`：整条 `io.Reader/io.Writer` 流式编解码链（`Addr.ReadFrom/WriteTo`、
  `UDPHeader.ReadFrom/WriteTo`、`UDPDatagram.ReadFrom/WriteTo`）。生产路径只用
  字节切片版本（`Encode/Decode/Marshal/Unmarshal`），流式版本只有自己的单测在用，
  其中 `UDPDatagram.ReadFrom` 还带着未使用的 gost UDP-over-TCP 扩展。
  保留 `Addr.readBody`——`ReadRequest/ReadReply` 的精确分帧依赖它

## 消除重复
- 新增 `internal/server`：`Serve` / `ServeListener` 统一了 4 份逐字节相同的
  listen/accept/退避/优雅退出循环（socks5、http、mix、transport/tcp），
  并新增单测覆盖取消退出与 listen 失败
- `tunnel.ReaderConn` 与 `PrefixConn` 合并：`NewPrefixConn` 现在只是
  `NewReaderConn(io.MultiReader(bytes.NewReader(prefix), conn), conn)`，
  少一份 15 个 net.Conn 方法的转发样板
- `udpRelay`：`runDirect` / `runUpstream` 共用的客户端收包前奏（deadline、源 IP 过滤、
  解包、FRAG 校验）抽成 `readClient`
- `handleUDPAssociate`：5 处「回失败响应 + 关控制连接」模板收敛为 `failReply` + `defer`
- `proxy/socks5`：`writeReply` / `writeBndReply` / `writeBindReply` 三个回包工具合并为一个
- `proxy/http`：CONNECT 与普通代理的「补默认端口 → 拨号 → 502 → 日志」前奏抽成 `dialTarget`；
  EOF 过滤从两处收敛到 `isClientGone`
- 新增 `internal/testsupport`：测试用 SOCKS5 上游原本有 4 份独立实现，TCP echo 有 3 份；
  现在统一为 `Socks5Upstream(opts)` / `TCPEcho` / `SilentListener` / `ClosedAddr` /
  `TargetLog.Assert` / `AssertEcho` / `TCPServer`

## 消除冗余状态
- `config.Url` 的 `AuthInfo` 内嵌 + `AuthEnabled bool` + `HttpAuthHeader http.Header`
  三套认证表示合并为 `Auth *Auth`（nil 即不认证），`Auth.ProxyAuthorization()` 按需生成
  头部，不再需要手工同步 `AuthEnabled`
- 默认端口不再用 `strings.Contains(host, ".")` 猜：改用 `net.SplitHostPort`，
  顺带修掉 `localhost` 这类无点主机名被解析成无端口地址的问题
- 连接句柄从 `*net.Conn` 改回 `net.Conn`：`(*conn)` / `&conn` 是没有用途的间接层

## 顺带修复
- TCP 端口转发改为经 `dialer.DialTcpConnection` 拨号，因此 `-F` 上游链生效
  （此前只有 socks5/http 代理遵守 `-F`）
- UDP 端口转发：读缓冲移出循环并放大到 65535，报文不再被截断；每包复制后再交给
  goroutine，避免复用缓冲导致的数据竞争
- TCP 端口转发：`defer src.Close()` 与错误判断顺序修正，成功日志在传输前打印
- mix 分发：预读失败时关闭连接（此前泄漏），并用 `socks5proto.Version` 取代魔数 `0x05`
- `constant.IdleTimeout` 注释写明它同时作用于数据中继（空闲 5 分钟断开）

## 结果
- 应用代码 3022 → 2830 行（−192，−6.4%，未含新增的 `internal/server` 50 行与
  `internal/testsupport` 244 行）
- 测试代码（含新抽取的 `testsupport`）3679 → 3459 行（−220，−6.0%）
- 合计 6701 → 6289 行（−412，−6.1%）；`go test -race ./...` 全部通过

# 2026.9.30

参考 gost 重写 SOCKS5 实现，按阶段提交，每个阶段附带单元测试。

## 新增：internal/protocol/socks5 编解码层
- 方法协商、RFC1929 认证、地址（IPv4/IPv6/域名）、请求/响应、UDP 报文
    
  全部基于 `io.ReadFull` 精确分帧，不再假设「一次 Read 拿到整包」
- 服务端握手 `ServerHandshake` + `Selector` 抽象（NoAuth/UserPass，强制认证，常量时间比较），
  无法协商时按 RFC1928 回 `0x05 0xFF`

## 修复的原实现缺陷
- 握手：忽略 NMETHODS/METHODS、从不回 NoAcceptable；认证单次 Read 解析分片失败；
  账号密码用 `==` 明文比较；mix 预读首包被丢弃
- 请求：单次 `Read(256)` 解析，分片/IPv6/域名请求失败，且会吞掉紧跟请求的载荷；
  非法 CMD/ATYP 不回响应
- CONNECT：BND 地址硬编码 `0.0.0.0:0`；失败一律回通用错误码
- BIND：两次响应都回监听地址；同步 `Accept` 无超时、不感知控制连接关闭；IPv6 下 `To4()` 为空
- UDP ASSOCIATE：只处理一个包、把 SOCKS5 头一起发给目标、从不回响应、域名当裸 IP、
  无客户端 IP 过滤、不感知 TCP 关闭
- 上游 client：固定读 10 字节解析响应，IPv6/域名响应会污染隧道流
- 传输层：目标不支持 CloseWrite 时另一方向阻塞到空闲超时；无法取消
- 配置：借用 `Socks5Auth []byte` 充当认证开关
- 生命周期：listen 失败 `Fatal`/`Panic`、accept 永久错误忙循环、无信号处理

## 阶段划分
1. Phase 0：codec 包 + 单测
2. Phase 1：握手协商/认证 + `PrefixConn` 预读透传
3. Phase 2：请求帧精确解析 + 不支持命令/地址类型的响应码
4. Phase 3：CONNECT 真实 BND 地址 + REP 错误映射
5. Phase 4：BIND 两阶段响应/对端地址/控制连接监控/等待超时
6. Phase 5：UDP ASSOCIATE 完整中继（过滤/头剥离重建/域名解析/生命周期）
7. Phase 6：上游 SOCKS5 client 用 codec 重写 + `DialSocks5UDPAssociate`
8. Phase 6b：UDP 关联经上游转发
9. Phase 3.5：传输层半关闭/完整关闭回退/context/字节统计
10. Phase 8：独立 `AuthEnabled`、优雅退出 + accept 退避、CONNECT/BIND 字节与耗时日志

## 测试
- `internal/protocol/socks5`：codec 往返/分片/截断/精确分帧、握手协商与认证
- `internal/proxy/socks5`：握手、CONNECT（BND/REP/域名/预读载荷）、BIND（两阶段/中止）、
  UDP（往返/域名/FRAG/终止/走上游）、优雅退出
- `internal/forward`：上游 client（认证/IPv6·域名响应/拒绝/UDP associate）
- `internal/tunnel`：半关闭、完整关闭回退、context 取消、双向字节统计
- `internal/netutil`：`Sleep`
- `go build ./... && go vet ./... && go test ./...` 全部通过

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
