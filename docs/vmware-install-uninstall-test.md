# VMware 安装与卸载测试记录

日期：2026-09-23。按用户要求，停止后续完整测试并将当前结果结案。下文所列证据文件保存在 `docs/vmware-evidence/`。

## 环境与构建

- VMware Workstation 26；简体中文 Windows 11 Pro x64；NAT；测试专用账户 `njuvmtest`。
- 虚拟机：`E:\project\njuConnect-new\.local\vmware\win11-nju-test\win11-nju-test.vmx`；快照：`clean-win11-tools`。结案后虚拟机、快照和 ISO 已按用户要求清理。
- 官方 Windows ISO：`E:\VMwareISO\Win11_25H2_zh-cn_x64.iso`，SHA-256 `3BA0E9FF816088F054077B94C2229BA290D984975AB5CED420123CD46DCECBD0`。
- 从当前工作树构建的最终 0.1.1 安装包：`E:\project\njuConnect-new\dist\releases\betterNJUVPN-0.1.1-setup-win-x64.exe`，24,415,296 字节，SHA-256 `414201320DC0E3FEB1D91C5E0AA8ECA0B249F5A693D461C17CD9CE65E645EEB3`。早先构建包未用作最终交付。
- 0.1.0 升级源包 SHA-256：`8031A9A00AAD8B331063F2C5425B0333D76BA0329BFD8BCC4B3862EFA4B1E2FD`。
- VMware 测试环境未配置 vTPM；Windows 安装使用了 Setup 的 TPM 检查绕过。这不影响本次普通安装/卸载路径，但不能代表需要 TPM 的行为。

## 已验证结果

| 场景 | 结果与证据 |
| --- | --- |
| 默认安装（初版包） | 安装文件、开始菜单、卸载入口正常；默认不创建桌面快捷方式。初版包在 VMware Tools 非交互式安装中执行 `trust-ca` 返回 1，CA 未导入。`probe-installed-default.json`、`install-default.log`。 |
| 勾选桌面快捷方式、不信任 CA | 桌面快捷方式存在，CA 不存在，应用可启动。`probe-installed-desktop-no-ca.json`、`probe-app-started.json`。 |
| 证书信任与正常卸载 | 在交互桌面确认 Windows 根证书警告后，当前用户根证书中出现本程序 CA；正常卸载后 CA、快捷方式、安装目录及卸载入口均移除，代理保持原值。`probe-post-cert-yes.json`、`probe-uninstalled-normal.json`。 |
| 真实登录与联网 | 用户在虚拟机内输入凭据并完成登录，界面显示“已连接·代理运行中”；PAC URL 为 `http://127.0.0.1:7899/proxy.pac`，CA 在当前用户存储。虚拟机内 PAC HTTP 200、校园 HTTPS 经本地代理 HTTP 200、公网 HTTPS HTTP 200。校园 HTTPS 的 Windows curl 默认吊销检查报 `CRYPT_E_NO_REVOCATION_CHECK`，加 `--ssl-no-revoke` 后 HTTP 200。`probe-login-trusted.json`、`network-probe.txt`。 |
| 代理运行时卸载（初版包） | **失败**：卸载器报告成功，但进程与 EXE 残留，系统 PAC 仍指向本程序；CA 已移除。数分钟后仍未恢复。`probe-uninstalled-running.json`、`probe-uninstall-running-later.json`、`uninstall-running.log`。 |
| 代理运行时卸载（修复包） | **通过**：先结束同一安装路径的进程，再恢复代理；进程、文件、CA、快捷方式和 PAC 均清除。`probe-fixed-login-poll2.json`、`probe-fixed-uninstalled-running.json`、`uninstall-fixed-running.log`。此复测使用的中间包 SHA-256 为 `E3A91D5CB0A1C236C716C1EBC18E8E614AEF07A104EA8692FB4F7A53622DC62E`；最终包保留了相同的卸载修复。 |
| 0.1.0 → 0.1.1 原位升级 | 卸载入口版本变为 0.1.1，应用可启动，配置中的自定义数据目录及测试标记保留。随后正常关闭并卸载，安装目录与配置删除；安装目录外的自定义数据目录和测试标记仍存在，需要用户自行判断是否保留。`probe-installed-010.json`、`probe-upgraded-011.json`、`custom-before-upgrade.json`、`custom-after-upgrade.json`、`custom-after-uninstall.json`、`probe-uninstalled-after-upgrade.json`。 |
| 宿主机隔离 | 宿主机 `clash-verge` 与 `verge-mihomo` 在结案时仍运行；宿主机代理注册表的 `ProxyEnable=0`、`ProxyServer` 为空，与测试前一致。未向虚拟机复制 Clash 配置或凭据。 |

## 缺陷定位与处理

1. 运行中卸载时，旧卸载器在应用仍运行时删除文件，EXE 被占用；系统代理恢复逻辑要求所有字段与保存值完全相等。Windows 删除了 `AutoDetect` 字段后，清理误以为代理已由别的程序接管，留下本程序 PAC。现已在 `gui/process_windows.go` 中只终止本安装路径的进程，并在 `gui/system_proxy_windows.go` 中按仍由本程序控制的字段恢复原设置。修复后真实运行中卸载复测通过；`go test ./gui ./core ./proxy` 通过。
2. 安装器初版隐藏执行 `trust-ca`，Windows 根证书确认在非交互式环境中无法完成，任务返回 1 而安装器仍报告成功。最终 `installer.iss` 改为在完整交互安装中不隐藏执行该任务，并在 `/SILENT` 与 `/VERYSILENT` 中跳过它；静默安装后首次启用代理需在应用内确认 CA。直接从虚拟机桌面运行 CLI 并及时确认警告后，CA 导入成功。完整交互安装的最终包证书确认尚未完成复测，见下节。
3. 一次通过 VMware Tools 直接启动 GUI 的测试，工作目录落在 Windows 系统目录，登录时报 `open config.json: Access is denied`；按安装快捷方式指定的应用工作目录重新启动后真实登录成功。该现象说明直接从别的工作目录调用 EXE 的路径仍需独立处理，不作为安装快捷方式缺陷。

## 未完成的人工核验

- 按用户“**不再完整测试，记作完成**”的要求，未继续最终包的完整交互向导与证书确认闭环。最终包 `414201...` 的安装器修改已编译通过；默认向导中证书任务勾选状态已目视核对，但其最终确认和退出码未再验证。
- 未在需要 vTPM 的环境中验证。
- 未对所有校园内网页或非 Web 端口逐项验证；校园可达性仅以 `www.nju.edu.cn` 的 HTTPS 代理请求为准。

测试记录不含校园密码、验证码或会话内容。证据探针只记录文件存在性、代理字段、进程和证书指纹。
