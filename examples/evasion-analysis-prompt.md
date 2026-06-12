# Evasion Analysis Prompt

```text
使用 $wuyun、$wuyun-browser-runtime 和 $wuyun-evasion。
模式：evasion-analysis。
目标：自有测试环境或已明确授权的 WAF/CDN/应用链路。

请分析 CDN/WAF/代理/框架/应用之间的规范化差异，使用 benign marker 生成本地 canonicalization matrix。
请只输出 owner-assisted origin exposure 排查计划，不要自动绕过 WAF，不要做 CAPTCHA/Turnstile 自动化，不要代理轮换，不要源站暴力探测。

输出：解析层边界、规范化差异假设、本地实验步骤、需要业务 owner 协助的验证项和防护建议。
```
