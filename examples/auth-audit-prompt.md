# Auth Audit Prompt

```text
使用 $wuyun 和 $wuyun-auth-audit。
模式：auth-audit。
目标：本地 HAR、HTTP 请求集合、源码或配置目录。

请被动梳理 JWT、OAuth/OIDC、SAML、Session/Cookie、CSRF、多租户/对象权限边界。
先运行离线分析，不要爆破 JWT 密钥，不要绕过 MFA，不要枚举用户。
如果需要验证越权，请只使用我提供的两个自有测试账号和合成对象，并先输出 dry-run 计划。

输出：认证面清单、风险假设、证据、置信度、安全验证建议和修复建议。
```
