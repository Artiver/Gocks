
# 简介

无外部依赖实现的代理工具，仅在授权的安全测试活动下使用。

# 特性

- HTTP代理
- HTTP代理Basic认证
- Socks5代理
- Socks5代理用户密码认证
- 混合代理

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
Gocks_windows_amd64.exe -L 192.168.100.1:8080 -u username -p password
```

# 参考

[RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

[RFC1929](https://datatracker.ietf.org/doc/html/rfc1929)