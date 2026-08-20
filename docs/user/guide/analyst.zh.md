# 调查 pcap 案件

[English](analyst.md) | 中文

`analyst` 预设是调查 Agent，不是编码 Agent 换皮。标准、极简、Code 与创造模式仍然可选。在 Web UI 预设选择器中选择**调查分析**，或用下面的 overlay 让 headless 默认使用 `analyst`。

案件目录依次取 `DSH_CASE_DIR`、`DSH_CWD`、进程工作目录。将捕获文件放在 `evidence/` 下，或作为案件内的 `*.pcap` / `*.pcapng` / `*.cap` / `*.log`。这些文件保持只读。可写路径是 `notes/` 和 `report.md`。

## 对案件目录运行 headless

不需要 DeepSeek API 密钥。先配置 Qwen（或其他）OpenAI 兼容路由；见[配置模型](./providers.md#qwen-openai-compatible)。

```sh
cd /path/to/case
export DSH_CASE_DIR="$PWD"
# Optional: point at a Qwen-compatible gateway instead of DeepSeek
# export OPENAI_API_KEY=...
pnpm dsh --profile headless --patch examples/analyst/headless.cordis.yml \
  "Define the Investigation Question, then hunt Kerberos CNameString and SAMR display names in evidence/"
```

在主机上安装 `tshark` 和 `capinfos`（Wireshark CLI），或在 `@deepseek-ai/dsh-analyst-tools` 行上设置 `tsharkBin` / `capinfosBin`。

出现主机名或 IP 后，账本会下发 Kerberos `CNameString` hunt，然后下发 SAMR `QueryUserInfo` hunt 以取显示名。有效的 tshark 4.4.16 字段包括 `kerberos.CNameString`、`samr.samr_UserInfo21.account_name` 和 `samr.samr_UserInfo21.full_name`。`ldap.sAMAccountName`、`ldap.displayName`、`kerberos.username` 和 `samr.full_name` 会被拒绝。SAMR `full_name` 是 UTF-16（Becka Rolf），不是 LDAP displayName。

用 `case_report`（who / what / when / where / why / how）结案。
