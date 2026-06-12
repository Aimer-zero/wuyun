# AI Audit Prompt

```text
使用 $wuyun 和 $wuyun-ai-audit。
模式：ai-audit。
目标：包含 LLM / RAG / Agent / 工具调用 / 多模态输入的本地项目。

请被动分析 AI 攻击面：输入渠道、系统/开发者提示词拼装、RAG 数据源、向量库、Agent 文件/HTTP/Shell 工具、记忆、输出 Sink。
请生成 benign canary 测试用例，不要诱导泄露真实系统提示、密钥、用户数据或私有文档。
如果涉及 RAG 投毒，请只设计可删除的合成测试文档流程。

输出：AI 攻击面、提示注入/RAG/工具滥用假设、可复现安全测试、证据和修复建议。
```
