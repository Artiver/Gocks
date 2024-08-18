
# 简介

无外部依赖实现的代理工具，仅在授权的安全测试活动下使用。

# 特性

- HTTP代理
- Socks5代理
- Socks5代理用户密码认证
- 混合代理

# 运行

```shell
# windows
mingw32-make.exe all
# linux
make all
```

编译后，执行对应二进制文件即可开启`:8181`监听HTTP和Socks5代理请求。

# 参考

[RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)

[RFC1929](https://datatracker.ietf.org/doc/html/rfc1929)