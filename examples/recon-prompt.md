# Recon Prompt

```text
使用 $wuyun 和 $wuyun-recon。
模式：recon。
范围：example.com 和 example-org，排除我列出的 out-of-scope 资产。

请生成 scoped recon dry-run 计划：GitHub/GitLab dork、证书透明度、被动子域、JS bundle 路由/feature flag/API 前缀提取、ffuf wordlist、Burp/Caido/nuclei/sqlmap 导出建议。
不要执行公网扫描，不要收集或保留搜索到的密钥，不要访问 out-of-scope 资产。

输出：侦察计划、工具命令、需要授权的主动步骤、证据保存规则和下一步验证路径。
```
