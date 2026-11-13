# QuickMirror app 模式业务服务

通用传输由 Peerloom 提供，本仓负责安装认证、持久设备绑定、能力目录与控制意图。项目聚合入口为 [qm-app](https://github.com/barry-ran/qm-app)，本仓不含客户端或 Peerloom 源码子模块。

## 当前架构

- 所有受保护请求直接校验 Peerloom 长期安装凭据；租户及 application 映射 PC/手机角色。不签发重复业务 token，也不保存安装秘密。
- 六位持久绑定码：PC 多手机、手机唯一 PC，双向添加、手机手动刷新、离线保留、批量逐项结果。
- PostgreSQL 事务保证关系唯一、退休码不复用、操作幂等和解绑关闭 outbox；未知结果不自动重发授权。
- 在线状态通过 Peerloom 公开 presence 查询，故障返回未知；手机能力快照不是上线证据。
- 控制意图固定 binding ID/版本，复用原独占槽位、runtime proof、generation 和 drain；解绑不跳过旧资源排空。

服务端实现、测试与正式发布/客户端联调是不同阶段。当前改造不能据此宣称新 SDK 发布、PC/安卓 UI 或真机投屏控制已全部通过。Core 媒体和 TCP 桥不属于这次身份绑定改造。

## 开发

```sh
go test -race ./...
go vet ./...
go build ./...
# 仅配置专用 *_test 数据库后运行
go test -race -tags integration ./internal/...
```

模块：`identity` 可信主体，`peerloom` 公开 API，`bootstrap` 注册授权，`catalog` 手机快照，`binding` 码和关系，`control` 会话授权及恢复，`httpapi` HTTP 边界。

参见 [文档入口](docs/README.md)、[部署](docs/部署指南.md)、[用户流程](docs/使用说明.md)及[绑定 OpenAPI](api/binding.openapi.json)。验证必须对应实际提交，不把旧版本或 mock 结果当新版本端到端证据。

需要验证真实源码服务间公开API时，参见[部署指南中的双服务隔离测试](docs/部署指南.md#云端源码双服务隔离测试)。该入口不连接现场，不等于正式SDK或真机验收。
