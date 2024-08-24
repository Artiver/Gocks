
# 简介

http/socks5代理工具，支持上游代理，仅在授权的安全测试活动下使用。

# 特性

- HTTP代理（Basic认证）
- Socks5代理（用户密码认证）
- 混合代理
- 上游HTTP/Socks5代理

# 编译

```shell
# windows
mingw32-make.exe all
# linux
make all
```

编译后，直接执行对应二进制文件即可开启`:8181`监听HTTP和Socks5代理请求。

# 参数

```shell
# 全零监听，端口8181，socks5+http代理，不认证
Gocks_windows_amd64.exe

# 绑定IP端口，socks5+http代理，不认证
Gocks_windows_amd64.exe -L 192.168.100.1:8080

# 绑定IP端口，socks5+http代理，认证
Gocks_windows_amd64.exe -L mix://username:password@192.168.100.1:8080

# 开启Socks5代理，并将其转发给上游http代理
Gocks_windows_amd64.exe -L socks5://:8080 -F http://192.168.200.1:8080

# 开启HTTP代理，并将其转发给上游需认证的socks5代理
Gocks_windows_amd64.exe -L http://:8080 -F socks5://admin:admin@192.168.200.1:8080
```

代理协议、上游协议、是否认证均可自由搭配使用。

# 参考

[RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

[RFC1929](https://datatracker.ietf.org/doc/html/rfc1929)

[RFC7617](https://datatracker.ietf.org/doc/html/rfc7617)

# 免责

在使用本工具时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我将不承担任何法律及连带责任。
