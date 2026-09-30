

# 简介

http/socks5代理工具，支持上游代理，支持端口转发，请在授权的安全测试活动下使用。

# 特性

- TCP端口转发
- UDP端口转发
- HTTP代理（Basic认证，支持 Keep-Alive 连接复用）
- Socks5代理
  - CONNECT / BIND / UDP ASSOCIATE
  - 用户密码认证（RFC1929，常量时间比较）
  - 按 RFC1928 进行方法协商与错误码返回
- 混合代理（同一端口同时接受 HTTP 与 Socks5）
- 上游 HTTP/Socks5 代理，支持多级代理链（多个 `-F`），每跳独立协议与认证
- `-F` 对代理模式与 TCP 端口转发同样生效
- UDP 关联经单级上游转发（多级链不支持 UDP）
- 空闲超时（5 分钟无数据即断开）、半关闭透传，SIGINT/SIGTERM 优雅退出

# 目录

```plaintext
Gocks/
├── cmd/gocks/main.go              # CLI 入口（SIGINT/SIGTERM 优雅退出）
├── internal/
│   ├── constant/                  # 协议/超时常量（protocol.go）
│   ├── config/                    # 配置定义与解析（config.go, parse.go, flag.go）
│   ├── protocol/socks5/           # SOCKS5 编解码与服务端握手
│   │                              #   codec/method/auth/addr/request/reply/udp/server
│   ├── tunnel/                    # 数据透传核心（半关闭/超时/字节统计）+ ReaderConn
│   ├── netutil/                   # 网络小工具（可取消的 Sleep）
│   ├── server/                    # 共用的 TCP accept 循环（优雅退出 + 退避重试）
│   ├── testsupport/               # 测试桩（TCP echo / SOCKS5 上游 / TargetLog）
│   ├── dialer/                    # 统一拨号入口（TCP/UDP 上游）
│   ├── forward/                   # 上游代理拨号（forward.go 链式调度, http.go, socks5.go）
│   ├── proxy/                     # 代理协议
│   │   ├── http/                  #   HTTP 代理
│   │   ├── socks5/                #   SOCKS5 代理（CONNECT/BIND/UDP）
│   │   └── mix/                   #   混合代理
│   └── transport/                 # 端口转发
│       ├── tcp/                   #   经 dialer 拨号，因此同样遵守 -F
│       └── udp/
├── go.mod                         # module gocks
└── Makefile                       # 构建路径 → ./cmd/gocks
```

# 编译

```shell
# windows
mingw32-make.exe all
# linux
make all
```

编译后，直接执行对应二进制文件即可开启`:8181`监听HTTP和Socks5代理请求。

# 参数

## 端口转发

```shell
# TCP端口转发，监听192.168.100.1:8181，将数据包转发到192.168.134.1:8080
Gocks_windows_amd64.exe -L tcp://192.168.100.1:8181/192.168.134.1:8080

# UDP端口转发，监听192.168.100.1:8181，将数据包转发到192.168.134.1:8080
Gocks_windows_amd64.exe -L udp://192.168.100.1:8181/192.168.134.1:8080

# TCP端口转发也可以经过上游代理链（与代理模式一致）
Gocks_windows_amd64.exe -L tcp://:8181/10.0.0.5:3389 -F socks5://192.168.200.1:1080
```

UDP 端口转发为直连转发（每次请求新建一个上游 socket，等待响应 3 秒），不支持 `-F`。

## 代理转发

```shell
# 全零监听，端口8181，socks5+http代理，不认证
Gocks_windows_amd64.exe

# 绑定IP端口，socks5+http代理，不认证
Gocks_windows_amd64.exe -L mix://192.168.100.1:8080

# 绑定IP端口，socks5+http代理，认证
Gocks_windows_amd64.exe -L mix://username:password@192.168.100.1:8080

# 开启Socks5代理，并将其转发给上游http代理
Gocks_windows_amd64.exe -L socks5://:8080 -F http://192.168.200.1:8080

# 开启HTTP代理，并将其转发给上游需认证的socks5代理
Gocks_windows_amd64.exe -L http://:8080 -F socks5://admin:admin@192.168.200.1:8080
```

代理协议、上游协议、是否认证均可自由搭配使用。

### 多级代理链

`-F` 可重复使用（或用逗号分隔写在一个 `-F` 里），**顺序为从近到远**：第一个 `-F` 最先连接，最后一个 `-F` 负责连接最终目标。每一跳都使用自己 URL 中的协议与认证信息，互不共享。

```shell
# 三级代理链：client → :8080 → P1 → P2 → P3 → 目标
Gocks_windows_amd64.exe -L socks5://:8080 \
  -F socks5://user1:pass1@P1:1080 \
  -F http://user2:pass2@P2:8080 \
  -F socks5://P3:1080

# 与上例等价：逗号分隔写法，密码中的逗号需写成 %2C
Gocks_windows_amd64.exe -L socks5://:8080 -F "socks5://user1:pass1@P1:1080,http://user2:pass2@P2:8080,socks5://P3:1080"

# 启动日志会打印解析后的链路顺序，便于核对（不打印密码）
# forward chain: [0] socks5://P1:1080 -> [1] http://P2:8080 -> [2] socks5://P3:1080 -> target
```

说明：

- 启动时若某跳缺少协议前缀或协议不受支持，会直接报错退出并指出是第几跳，不会等到拨号时才失败。
- 链路中任一跳失败都会关闭整条连接，日志与返回错误中带有 `hop[i]` 定位。
- 跳数上限为 32；`-F ""` 仍表示不使用上游。
- UDP ASSOCIATE 只支持单级上游（中转地址只在能直达该代理的网络位置上有效），多级链下的 UDP 请求会被明确拒绝。

# 参考

[RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

[RFC1929](https://datatracker.ietf.org/doc/html/rfc1929)

[RFC7617](https://datatracker.ietf.org/doc/html/rfc7617)

# 免责

在使用本工具时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我将不承担任何法律及连带责任。
