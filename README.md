
# 简介

http/socks5代理工具，支持上游代理，支持端口转发，请在授权的安全测试活动下使用。

# 特性

- TCP端口转发，支持多级代理链
- UDP端口转发
- HTTP代理（Basic认证，支持 Keep-Alive 连接复用）
- Socks5代理（CONNECT / BIND / UDP ASSOCIATE）
- 混合代理（同一端口同时接受 HTTP 与 Socks5 请求）
- 支持多级代理链（多个 `-F`），每跳独立协议与认证
- 单进程多监听规则（重复 `-L`），连续 `-L` 共享其后的 `-F` 组，每条规则可走不同上游链
- `@参数文件`（如 `@rules.args`），便于保存和维护长命令行
- 空闲超时可配置（`--timeout`，默认 `0` 表示不因空闲断开），SIGINT/SIGTERM 优雅退出

# 目录

```plaintext
Gocks/
├── cmd/gocks/main.go              # CLI 入口（SIGINT/SIGTERM 优雅退出）
├── internal/
│   ├── config/                    # 配置定义与解析（config.go, parse.go, flag.go）
│   ├── constant/                  # 协议/超时常量（protocol.go）
│   ├── dialer/                    # 统一拨号入口（直连 + 链式上游，chain.go/http.go/socks5.go）
│   ├── netutil/                   # 网络小工具（可取消的 Sleep）
│   ├── protocol/socks5/           # SOCKS5 编解码与客户端/服务端握手
│   │                              #   codec/method/auth/addr/request/reply/udp/server/client
│   ├── proxy/                     # 代理协议
│   │   ├── http/                  #   HTTP 代理
│   │   ├── mix/                   #   混合代理
│   │   └── socks5/                #   SOCKS5 代理（CONNECT/BIND/UDP）
│   ├── runner/                    # 多规则编排（先绑定全部端口，再并发服务，统一退出）
│   ├── server/                    # 共用的 TCP accept 循环（优雅退出 + 退避重试）
│   ├── transport/                 # 端口转发
│   │   ├── tcp/                   #   经 dialer 拨号，因此同样遵守 -F
│   │   └── udp/
│   └── tunnel/                    # 数据透传核心（半关闭/超时/字节统计）+ ReaderConn
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

## 通用选项

`--timeout` 控制隧道空闲超时（任一方向有数据流动即刷新计时），默认 `0`，表示不因空闲自动断开：

```shell
# 不自动断开（默认）
Gocks_windows_amd64.exe -L :8181 --timeout 0

# 5 分钟无数据交互后关闭通道（旧版本行为）
Gocks_windows_amd64.exe -L :8181 --timeout 5m

# 30 秒无数据交互后关闭通道，可用于 TCP 端口转发
Gocks_windows_amd64.exe -L tcp://:8181/10.0.0.5:3389 --timeout 30s
```

作用范围为 HTTP CONNECT、SOCKS5 CONNECT/BIND、TCP 端口转发；SOCKS5 UDP ASSOCIATE 仍使用独立的 300 秒会话回收超时，不受该选项影响。负值会在启动时报错。

## 批量监听规则

`-L` 可以重复出现。**连续写在一起的多个 `-L` 共享紧跟其后的 `-F` 组**；一旦某段规则已经带上 `-F`，再出现 `-L` 就开始新的一段。没有 `-F` 的段表示直连。

```shell
# 一条命令等价于分别启动 5 个进程
Gocks_windows_amd64.exe ^
  -L tcp://10.10.10.10:22/192.168.1.100:22 ^
  -L tcp://10.10.10.10:23/192.168.1.100:23 ^
  -L tcp://10.10.10.10:80/192.168.1.100:80 ^
  -F socks5://10.128.123.121:8181 ^
  -L socks5://10.10.10.10:8182 ^
  -F socks5://10.128.123.122:8181 -F socks5://10.128.123.123:8181 ^
  -L socks5://10.10.10.10:8181 ^
  -F socks5://10.128.123.122:8181
```

（Linux/macOS 把行尾的 `^` 换成 `\`。）

解析结果：

| 规则 | 监听 | 上游链 |
| --- | --- | --- |
| 1 | `tcp://10.10.10.10:22/192.168.1.100:22` | `121` |
| 2 | `tcp://10.10.10.10:23/192.168.1.100:23` | `121` |
| 3 | `tcp://10.10.10.10:80/192.168.1.100:80` | `121` |
| 4 | `socks5://10.10.10.10:8182` | `122 → 123` |
| 5 | `socks5://10.10.10.10:8181` | `122` |

分段规则：

- `-L a -L b -F p`：a 与 b 都走 p。
- `-L a -F p -L b`：a 走 p，b 直连。
- `-F p -L a`：p 作为默认链，a 走 p（兼容旧写法）。
- 规则数为 1 时行为与旧版本完全一致；未写任何 `-L` 时仍默认监听 `:8181` 的 HTTP+SOCKS5 混合代理。

启动时会先绑定全部端口，再开始服务。任一端口不可用则整体退出并指出 `rule i/n`，不会出现只起来一部分规则的情况。

> 行为变更：旧版本重复 `-L` 时只有最后一个生效；现在每个 `-L` 都是一条独立规则。

### @参数文件

规则较多时可以把参数放进文件，文件中同样支持上面的分段语义：

```text
# rules.args
# '#' 开头为注释，行尾 '\' 表示续行
-L tcp://10.10.10.10:22/192.168.1.100:22
-L tcp://10.10.10.10:23/192.168.1.100:23
-F socks5://10.128.123.121:8181
-L socks5://10.10.10.10:8182
-F socks5://10.128.123.122:8181 -F socks5://10.128.123.123:8181
```

```shell
Gocks_windows_amd64.exe @rules.args
```

支持单/双引号包裹含空格的参数（如 `-F "socks5://a:1, http://b:2"`）；暂不支持文件内再引用 `@file`。

## 端口转发

```shell
# TCP端口转发，监听192.168.100.1:8181，将数据包转发到192.168.134.1:8080
Gocks_windows_amd64.exe -L tcp://192.168.100.1:8181/192.168.134.1:8080

# UDP端口转发，监听192.168.100.1:8181，将数据包转发到192.168.134.1:8080
Gocks_windows_amd64.exe -L udp://192.168.100.1:8181/192.168.134.1:8080

# TCP端口转发也可以经过上游代理链（与代理模式一致）
Gocks_windows_amd64.exe -L tcp://:8181/10.0.0.5:3389 -F socks5://192.168.200.1:1080
```

UDP 端口转发为直连转发（每次请求新建一个上游 socket，等待响应 3 秒），不支持 `-F`；给 `udp://` 规则配置 `-F` 会在启动时报错，避免误以为已走上游。

## 代理转发

```shell
# 全零监听，端口8181，socks5+http代理，不认证
Gocks_windows_amd64.exe
Gocks_windows_amd64.exe -L :8181

# 绑定IP端口，socks5+http代理，不认证
Gocks_windows_amd64.exe -L 192.168.100.1:8080

# 绑定IP端口，socks5+http代理，认证
Gocks_windows_amd64.exe -L mix://username:password@192.168.100.1:8080

# 开启Socks5代理，并将其转发给上游http代理
Gocks_windows_amd64.exe -L socks5://:8080 -F http://192.168.200.1:8080

# 开启HTTP代理，并将其转发给上游需认证的socks5代理
Gocks_windows_amd64.exe -L http://:8080 -F socks5://admin:admin@192.168.200.1:8080

# 开启socks5+http代理，并将按顺序依次转发给上游的P1代理、P2代理、P3代理，跳数上限为 32
Gocks_windows_amd64.exe -L :8080 -F socks5://user1:pass1@P1:1080 -F http://user2:pass2@P2:8080 -F socks5://P3:1080
Gocks_windows_amd64.exe -L :8080 -F "socks5://user1:pass1@P1:1080,http://user2:pass2@P2:8080,socks5://P3:1080"
```

代理协议、上游协议、是否认证均可自由搭配使用。

# 参考

[RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

[RFC1929](https://datatracker.ietf.org/doc/html/rfc1929)

[RFC7617](https://datatracker.ietf.org/doc/html/rfc7617)

# 免责

在使用本工具时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我将不承担任何法律及连带责任。
