# 2026.9.30

SOCKS5 协议全面修复，共修改 5 个源文件、新增 7 个测试文件（50 个用例），保持零外部依赖，6 平台编译通过。

1. 并发安全修复 (constant/socks5.go, forward/socks5.go)
切片常量 ClientRequestIPv4/IPv6/Domain 改为工厂函数 NewClientRequestIPv4/IPv6/Domain，消除 append 全局切片的并发污染风险。buffer 常量调整：UdpReadBytes 1024→65535、Socks5HandleBytes 256→262。

2. 握手与认证修复 (proxy/socks5/proxy.go)
RFC 1928 方法协商：解析客户端 NMETHODS/METHODS 列表，按服务端配置选择方法，客户端不支持时回复 0xFF。
mix 数据丢失修复：用 PrefixConn 包装预读数据，握手始终从 conn 统一读取，不再覆盖 firstBuff。
常量时间比较：认证改用 crypto/subtle.ConstantTimeCompare，消除时序侧信道。
精确读取：认证字段改用 io.ReadFull 逐步读取，防止超长字段切片越界 panic。

3. 请求解析修复 (proxy/socks5/proxy.go)
单次 Read 改为按字段逐步 io.ReadFull 读取（4 字节头 + 按 ATYP 变长地址 + 2 字节端口），修复长域名（255 字节）截断问题，按 ATYP 精确校验最小长度。

4. CONNECT 失败原因码 (proxy/socks5/command.go)
新增 buildFailureResponse 和 mapDialErrorToRep，根据拨号错误类型映射 SOCKS5 REP 码：refused→0x05、unreachable→0x03、no route→0x04、timeout→0x06、其他→0x01。

5. BIND 语义与安全修复 (proxy/socks5/command.go)
监听任意端口（:0）而非客户端期望的源地址；Accept 后校验连入者 IP 与原 SOCKS5 客户端一致，拒绝任意第三方连入；新增 BindWaitTimeout（120s）防止永久阻塞；响应按实际地址类型选择 IPv4/IPv6。

6. UDP ASSOCIATE 完整实现 (proxy/socks5/command.go)
循环转发（非单包）、SOCKS5 UDP 头剥离/重封装、Domain 类型经 net.ResolveIPAddr 解析、会话表（sync.Map）关联客户端与目标、回包 goroutine 重新封装头发回客户端、IPv6 响应支持、分片（Frag!=0）跳过、TCP 控制连接看门狗清理会话。

7. 上游 SOCKS5 客户端修复 (forward/socks5.go)
初始请求方法列表改为声明支持 0x00+0x02 两种方法（RFC 1928 合规）；响应解析改为变长读取（按 ATYP 解析 BND.ADDR），修复 Domain 类型响应阻塞；新增版本号校验；错误消息措辞修正；SetReadDeadline 错误检查；新增 DialSocks5UDPAssociate 接口；buildCommandRequest 支持任意命令类型。

8. 测试覆盖 (新增 7 个文件，50 个用例)
constant/socks5_test.go：工厂函数并发安全（-race）
proxy/socks5/handshake_test.go：方法协商各组合、认证成功/失败、mix 预读流水线、超长字段不 panic
proxy/socks5/request_test.go：三种地址类型、最长域名、错误场景
proxy/socks5/command_connect_test.go：失败码映射
proxy/socks5/command_bind_test.go：IPv4/IPv6 响应格式
proxy/socks5/command_udp_test.go：UDP 解析/封装/Domain 解析
forward/socks5_test.go：命令构造、变长响应、握手认证

验证：go test -race ./... 全部通过，go vet ./... 无问题，6 平台交叉编译全部成功。

# 2026.9.20

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
