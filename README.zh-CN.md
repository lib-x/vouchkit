# vouchkit

[English](README.md) · [简体中文](README.zh-CN.md)

[![vouchkit-core 的 crates.io 版本](https://img.shields.io/crates/v/vouchkit-core.svg?label=vouchkit-core)](https://crates.io/crates/vouchkit-core)
[![vouchkit-cli 的 crates.io 版本](https://img.shields.io/crates/v/vouchkit-cli.svg?label=vouchkit-cli)](https://crates.io/crates/vouchkit-cli)
[![vouchkit-client 的 crates.io 版本](https://img.shields.io/crates/v/vouchkit-client.svg?label=vouchkit-client)](https://crates.io/crates/vouchkit-client)
[![vouchkit-server 的 crates.io 版本](https://img.shields.io/crates/v/vouchkit-server.svg?label=vouchkit-server)](https://crates.io/crates/vouchkit-server)

Rust 离线优先软件授权库，支持动态接入签名 provider，内置 Ed25519 和 ECDSA P-256。

主私钥由作者保管。用主私钥离线签发授权，再把主公钥嵌入应用做本地验证。需要在线激活和续租时，用短期委托证书和相应签名密钥部署服务。客户端拿到租约后仍可离线验签。

| Crate | 用途 |
| --- | --- |
| [vouchkit-core](crates/vouchkit-core) | 凭证格式、签发、本地验签、委托约束、设备证明、功能槽位和吊销 |
| [vouchkit-cli](crates/vouchkit-cli) | 作者侧离线工具，提供 `vouch` 命令 |
| [vouchkit-client](crates/vouchkit-client) | 可选在线激活与续租、设备密钥存储、持久化客户端状态 |
| [vouchkit-server](crates/vouchkit-server) | 可选在线授权与席位管理，提供可替换的存储接口和 Axum 参考服务 |

## 纯离线签发和验签

```sh
cargo install vouchkit-cli --locked

vouch keygen --kind master --key-id 1 --out-dir author
vouch issue --key author/master.key.enc --class standalone \
  --product editor --subject "示例客户" --tier 1 \
  --feature-slots 1000-1099,2050 --format file --out license.vk \
  --ledger author/issued.jsonl
vouch verify license.vk --pubkey author/master.pub --product editor
```

应用侧只依赖 `vouchkit-core`。把主公钥嵌进应用，用 [最小 Rust 示例](crates/vouchkit-core) 验证令牌或授权文件。作者工具默认用 Argon2id 和 XChaCha20-Poly1305 加密主私钥。使用有期限或可吊销的凭证时，可以配合持久化状态调用 `Verifier::verify_with_store`。

`keygen` 默认生成 Ed25519 密钥。需要 ECDSA P-256 时加上 `--algorithm p256`。只有 Ed25519 的签名链和设备绑定继续用 `VK1-` 格式。新版还能验证 `VK2-` 凭证，作者、委托和设备可各自选择这两种算法。

## 动态扩展与在线授权

- 宿主可以在运行时通过 `SigningProvider` 注入作者或委托签名实现，通过 `DeviceProver` 接入软件密钥、USB 加密狗或 HSM。协议内置算法为 Ed25519 和 ECDSA P-256。主密钥应留在作者掌控的离线设备里，委托密钥可使用服务器侧 HSM 或 KMS。
- 在线模式先签发购买凭证，再调用 `Renewer::activate` 激活，用 `renew_if_needed` 续租。客户端传输可以替换。服务器只部署委托证书、对应签名器、受信主公钥和已签名 CRL。
- 服务端的 `ActivationStore` 可接入自定义事务存储。SQLite 是随包提供的默认后端，可以在构建时关闭。参考服务也提供内存后端用于临时环境。生产环境若要跨重启保留席位和重放保护，需要持久化事务后端。

查看 [服务端配置](crates/vouchkit-server) 和 [可运行示例](examples)。

## 从 0.1 升级

原有 Ed25519 密钥和 `VK1-` 凭证继续有效。`0.2` 的 `DeviceProver` 返回 `PublicKey`。若原实现返回 Ed25519 公钥，可改为返回 `raw_public_key.into()`。SQLite 后端启动时会迁移旧库，升级前可先备份。

## 功能槽位和设备

- 宿主在 `0..=65535` 分配稳定的功能槽位 ID。每张凭证最多授予 16 个互不相连的连续区间。授权整个区间也会覆盖后来分配在区间内的功能。
- 纯离线授权可以绑定设备公钥。在线席位按购买凭证下的有效设备公钥计数。复制令牌仍需对应私钥，导出并复制私钥则会复制设备身份。支持签名的不可导出硬件密钥可通过 `DeviceProver` 接入。
- 网卡地址和磁盘编号可能变化。宿主可在本地派生可选的设备提示用于排查。

## 安全边界

授权安全由数字签名链保证。委托证书限制产品、级别、功能、签发窗口和包含离线宽限期的总租约时长。在线服务继续检查原始购买凭证的权限与到期时间，客户端保存购买凭证后也能独立复核续租结果。

本地时间水位可以检测时钟回拨。恢复整个可写状态或虚拟机快照也可能回滚水位。需要严格到期判断或精确席位计数时，应由在线服务做出实时决定。离线终端收到新 CRL 后才会看到吊销。停用会阻止后续续租，已签发的租约有效到到期或吊销。

可选加固层包括分散标签校验、功能解锁密钥和自检，用来提高修改客户端的成本。有能力的攻击者仍可修改二进制，合法授权持有者也能提取其功能密钥。

详见 [授权设计](docs/design.md) 和 [互操作性测试向量](testdata)。
