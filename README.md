# Wuyun / 乌云

> 中文 | [English](#english)

Wuyun 是一个面向 AI 编码助手的漏洞研究 Skill。它帮助安全研究人员完成代码审计、在线 Web/API 审计、云安全在线分析、CTF/Lab 调研，并输出有证据、有置信度、有修复建议的结果。

Wuyun 不是一键扫描器，也不是攻击工具包；它更像一套研究流程：先理解系统，再梳理攻击面，生成假设，验证证据，最后形成报告。

## 项目内容

```text
wuyun/                    # 主 Skill：通用漏洞研究流程
wuyun-cloud-vuln/         # 云安全/SSRF/临时凭证分析辅助 Skill
wuyun-web-api-audit/      # Web/API 审计辅助 Skill
examples/                 # 使用提示词示例
LICENSE                   # MIT License
```

## 安装

### Codex / OpenAI Skill 目录

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.codex/skills
cp -R wuyun-skill/wuyun ~/.codex/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
```

### Claude Skill 目录

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.claude/skills
cp -R wuyun-skill/wuyun ~/.claude/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
```

安装后请重启或刷新你的 AI Agent，让它重新发现 Skill。

## 快速使用

### 本地代码审计

```text
使用 $wuyun，模式 code-audit。
范围：只检查当前本地仓库的源码、配置和测试。
不要访问外部目标。请输出攻击面、优先级假设、证据、置信度和修复建议。
```

### Web/API 审计

```text
使用 $wuyun 和 $wuyun-web-api-audit。
模式：online-web-api。
目标：https://example.com 或 https://api.example.com。
请进行低影响在线审计，梳理接口、权限、对象 ID、文件上传、SSRF、注入和业务逻辑风险。
```

### 云安全在线分析 / SSRF 分析

```text
使用 $wuyun 和 $wuyun-cloud-vuln。
模式：online-cloud。
目标：https://example.com 或 example-bucket.oss-cn-hangzhou.aliyuncs.com。
请进行低影响云安全在线分析，关注云指纹、对象存储暴露、SSRF、metadata、临时凭证和权限影响，结果需要脱敏。
```

### CTF / Lab

```text
使用 $wuyun，模式 ctf-lab。
这是 CTF/Lab 环境，范围仅限我提供的目标和题目文件。
请进行有边界的枚举、验证和复现，并输出解题步骤。
```

## 常用辅助脚本

```bash
python3 wuyun/scripts/check_tools.py
python3 wuyun/scripts/passive_repo_audit.py /path/to/repo
python3 wuyun/scripts/validate_skill.py
python3 wuyun/scripts/quality_gate.py
```

这些脚本主要用于本地检查、被动审计和发布前验证。请根据你的实际场景和责任边界谨慎使用。

## 适用场景

- 本地源码/配置安全审计
- 在线 Web/API 安全测试与审计
- CTF、靶场、实验环境
- 云安全在线分析、云 SSRF、临时凭证、权限影响分析
- 漏洞报告整理、证据归纳和修复建议输出

## 不适用场景

- 用于违法、违规或超出责任边界的第三方测试
- 扫描公网目标或批量探测
- 获取、导出或保留真实用户数据、业务数据、密钥、Token
- 编写、上传或部署 WebShell、木马、后门、勒索软件等恶意程序
- 造成拒绝服务、破坏数据、影响业务运行的测试

## 免责声明

本项目面向**合法合规的安全研究、教学、代码审计、CTF/Lab 和防御性安全工作**。

本项目只提供研究流程和辅助能力，不替代法律判断或授权判断。使用者应自行确认目标范围、使用权限和适用规则，并对自己的行为负责。因滥用工具、越界测试、破坏系统、泄露数据或其他违法违规行为造成的任何后果，均由使用者自行承担，项目作者和贡献者不承担责任。

请始终遵循：最小化验证、只收集必要证据、默认脱敏、避免业务影响、及时删除临时数据。

## License

MIT License. See [LICENSE](LICENSE).

---

# English

> [中文](#wuyun--乌云) | English

Wuyun is a vulnerability research Skill for AI coding agents. It helps security researchers perform code audits, online Web/API reviews, online cloud-security analysis, CTF/Lab investigations, and evidence-based reporting.

Wuyun is not a one-click scanner or an offensive toolkit. It is a research workflow: understand the system, map the attack surface, create hypotheses, validate evidence, and write remediation-focused findings.

## Repository Layout

```text
wuyun/                    # Main Skill: general vulnerability research workflow
wuyun-cloud-vuln/         # Companion Skill for cloud SSRF / temporary credential triage
wuyun-web-api-audit/      # Companion Skill for Web/API audits
examples/                 # Prompt examples
LICENSE                   # MIT License
```

## Installation

### Codex / OpenAI Skill Directory

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.codex/skills
cp -R wuyun-skill/wuyun ~/.codex/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.codex/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.codex/skills/wuyun-web-api-audit
```

### Claude Skill Directory

```bash
git clone <repo-url> wuyun-skill
mkdir -p ~/.claude/skills
cp -R wuyun-skill/wuyun ~/.claude/skills/wuyun
cp -R wuyun-skill/wuyun-cloud-vuln ~/.claude/skills/wuyun-cloud-vuln
cp -R wuyun-skill/wuyun-web-api-audit ~/.claude/skills/wuyun-web-api-audit
```

Restart or reload your agent after installation so it can discover the Skills.

## Quick Usage

### Local Code Audit

```text
Use $wuyun, mode code-audit.
Scope: only inspect the current local repository source, configs, and tests.
Do not access external targets. Output attack surface, prioritized hypotheses, evidence, confidence, and remediation.
```

### Web/API Audit

```text
Use $wuyun and $wuyun-web-api-audit.
Mode: online-web-api.
Target: https://example.com or https://api.example.com.
Run a low-impact online audit and map endpoints, authorization, object IDs, uploads, SSRF, injection, and business logic risks.
```

### Online Cloud Security / SSRF Triage

```text
Use $wuyun and $wuyun-cloud-vuln.
Mode: online-cloud.
Target: https://example.com or example-bucket.s3.amazonaws.com.
Run low-impact online cloud-security analysis for cloud fingerprinting, object storage exposure, SSRF, metadata, temporary credentials, and permission impact. Redact sensitive values.
```

### CTF / Lab

```text
Use $wuyun, mode ctf-lab.
This is a CTF/Lab target. Scope is limited to the target and challenge files I provide.
Perform bounded enumeration, validation, and replayable solution steps.
```

## Helper Scripts

```bash
python3 wuyun/scripts/check_tools.py
python3 wuyun/scripts/passive_repo_audit.py /path/to/repo
python3 wuyun/scripts/validate_skill.py
python3 wuyun/scripts/quality_gate.py
```

Use these scripts for local preflight checks, passive review, and release validation. Stay within your actual scope and responsibility boundary.

## Intended Use

- Local source/config security review
- Online Web/API testing and auditing
- CTF, lab, and sandbox research
- Online cloud-security analysis and cloud SSRF / temporary credential impact analysis
- Vulnerability report drafting and remediation guidance

## Not Intended For

- Illegal, abusive, or out-of-scope third-party testing
- Internet-wide scanning or mass probing
- Collecting or retaining real user data, business data, secrets, or tokens
- Creating or deploying webshells, trojans, backdoors, ransomware, or malware
- Causing denial of service, data damage, or business disruption

## Disclaimer

This project is intended for **lawful and compliant security research, education, code auditing, CTF/Lab work, and defensive security activities**.

This project provides research workflow guidance and helper capability; it does not replace legal or permission decisions. You are responsible for determining your target scope, usage rights, and applicable rules. The authors and contributors are not responsible for misuse, out-of-scope testing, data exposure, system damage, business disruption, or legal consequences caused by your actions.

Always minimize validation, collect only necessary evidence, redact sensitive data by default, avoid business impact, and remove temporary artifacts when no longer needed.

## License

MIT License. See [LICENSE](LICENSE).
