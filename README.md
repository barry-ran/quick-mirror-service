# QuickMirror 无 ADB 业务服务

设备目录和连接业务服务；Peerloom 仅通过公开 API 和已发布库接入，不将临时源码子模块编入产品。

## 当前实现

- 安装身份模型与 UUID 规范化。
- Peerloom `GET /v1/device-self` HTTP 适配器：HTTPS、超时、禁止重定向、响应体上限、服务域租户校验、可信 application 到 PC/手机角色映射。
- 原产品账号 token 不参与上述校验；平台和 metadata 不作为角色证据。

目前是经过测试的服务基础模块，不是可部署的完整业务服务器。设备目录存储、业务 token 交换、会话编排、自定义 TURN 和完整联调尚未交付；没有以 mock 启动生产服务的路径。开发范围与验收门禁见 [文档入口](docs/README.md)。

## 开发验证

使用 `go.mod` 指定的 Go 版本，遵循官方工程惯例和 `gofmt`：

```sh
go test -race ./...
go vet ./...
go build ./...
```

测试通过本地 TLS 测试服务器验证真实 HTTP 请求及故障处理；它不是已部署 Peerloom 集成或真机验收。GitHub workflow 不初始化临时子模块，Windows、Linux、macOS 分别运行上述门禁。

## 仓库布局

`internal/identity` 定义服务内部身份边界，`internal/peerloom` 实现公开 HTTP 适配，`docs` 保存产品、架构和模块说明。根目录三个子模块仅为开发源码定位；最终联调验收后按用户要求移除这些链接，不删除远端仓库。
