# AI Security RAG Agent — LLM应用安全防护与评测系统

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![LangGraph](https://img.shields.io/badge/LangGraph-StateGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![Chroma](https://img.shields.io/badge/Chroma-Vector_DB-purple.svg)](https://www.trychroma.com/)
[![Model](https://img.shields.io/badge/LLM-Qwen3.5--35B-red.svg)](https://modelscope.cn)

> **面向企业 RAG Agent 的 AI 安全防护与评测系统。** 覆盖 Prompt 注入、文档投毒、工具滥用、输出幻觉和多租户泄露五大风险面，实现"输入防火墙 → 知识库扫描 → 工具策略引擎 → 输出过滤 → 审计日志"纵深防御链。

---

## 5秒速览

```
攻击面         →  防御层          →  核心数据
─────────────────────────────────────────────
Prompt注入     →  双层防火墙       →  93.3% 拦截率 (105 payloads)
文档投毒       →  L1/L2级联扫描    →  12 场景覆盖, 58% L1检测率
工具滥用       →  Tool Policy Engine →  4 危险工具, 10/10 策略测试
输出幻觉       →  fact_check + 三级粒度 →  93.8% 判定准确率
多租户泄露     →  collection + thread_id →  5 项隔离测试通过
日志篡改       →  SHA256 哈希链     →  精确检测篡改条目索引
```

---

## 架构

```
                    ┌──────────────┐
                    │  用户输入     │
                    └──────┬───────┘
                           ▼
              ┌────────────────────────┐
              │  guardrail_node        │  ← Phase 3.1 双层防火墙
              │  L1关键词+L2 LLM+L3后检查 │     93.3% 拦截率
              └────────────┬───────────┘
                           ▼
              ┌────────────────────────┐
              │  agent_node            │  ← LangGraph ReAct Agent
              │  LLM选工具/RAG检索      │     Function Calling
              └────────────┬───────────┘
                           ▼
         ┌─────────────────────────────────┐
         │  tool_node                       │
         │  ┌──────────────────────────┐   │
         │  │ Policy Engine (4.1)      │   │  ← 操作级安全检查
         │  │ SQL白名单/路径黑名单/      │   │     <1ms 纯规则
         │  │ API域名过滤/邮件检查      │   │
         │  └──────────────────────────┘   │
         └────────────┬────────────────────┘
                      ▼
         ┌────────────────────────┐
         │  output_filter_node    │  ← Phase 3.4 输出安全
         │  可执行拦截+fact_check  │     3级粒度控制
         │  +敏感信息脱敏          │
         └────────────┬───────────┘
                      ▼
         ┌────────────────────────┐
         │  finalize_node         │  ← Phase 4.3 审计日志
         │  哈希链写审计日志       │     SHA256 防篡改
         └────────────────────────┘
```

### RAG 检索链路

```
BM25 + 向量检索 (多路召回)
    ↓ RRF 融合
BGE-Reranker 重排序 (Cross-Encoder)
    ↓ top_k 选最优
上下文窗口 → LLM 生成 → fact_check 事实核查
```

---

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动 Streamlit 界面
streamlit run app.py

# 3. 命令行模式
python main.py
```

**默认配置** (`core/config.py`):
- LLM: `Qwen/Qwen3.5-35B-A3B` (ModelScope API)
- Embedding: `BAAI/bge-small-zh-v1.5`
- Reranker: `BAAI/bge-reranker-base`
- 向量库: ChromaDB (持久化到 `chroma_db/`)

---

## 核心模块

### Phase 1-2: RAG 基础设施 + Agent 架构

| 模块 | 技术栈 | 核心数据 |
|------|------|------|
| PDF 解析 | PyMuPDF + EasyOCR 扫描件 | 13 安全场景对比 |
| 检索链路 | BM25 + 向量 RRF 融合 + BGE-Reranker | **80.0% 准确率** (C4: k=8+r=5) |
| Agent 框架 | LangGraph StateGraph (5节点) | ReAct + Function Calling + 自愈 |
| 记忆管理 | 滑动窗口 + 摘要 + 精准遗忘 + SQLite Checkpointer | 12条消息持久化验证 |

### Phase 3: AI 安全攻防核心

| 模块 | 定位 | 核心数据 | 报告 |
|------|------|------|:---:|
| 3.1 防火墙 | 输入端 | 105 payloads, **93.3%** 拦截, 0% 误拦 | [报告](D_deliverables/AI防火墙攻防对抗报告.md) |
| 3.2 投毒防护 | 知识库端 | 12 场景, L1+L2 级联, 58% L1检测 | [报告](D_deliverables/RAG投毒防护报告.md) |
| 3.3 自适应攻击 | 攻击变体 | 5 多轮场景, 11 角色, classify_with_context() | — |
| 3.4 输出评测 | 输出端 | 21 边界测试, 3 级粒度, 幻觉探测 | [报告](D_deliverables/模型输出安全深度评测报告.md) |
| 3.5 基准对标 | 业界对比 | HackAPrompt 30 + Garak 20, OWASP 5/10 | [报告](D_deliverables/业界基准对标报告.md) |

### Phase 4: 工具安全 + 企业化

| 模块 | 定位 | 核心数据 | 报告 |
|------|------|------|:---:|
| 4.1 策略引擎 | 工具执行层 | 4 危险工具, 10/10 测试, JSON可配置 | [报告](D_deliverables/Tool Policy Engine攻防报告.md) |
| 4.2 多租户隔离 | 数据层 | 5 项测试, 3 设计假设分析 | [报告](D_deliverables/多租户数据隔离安全验证报告.md) |
| 4.3 审计日志 | 可追溯 | SHA256 哈希链, 精确篡改检测 | [报告](D_deliverables/审计日志防篡改报告.md) |

---

## 关键实验数据

### 防火墙消融实验思路 (Phase 3.1)

| 指标 | 旧版关键词 | 新版防火墙 | 提升 |
|------|:---:|:---:|:---:|
| 拦截率 | 8.6% | **93.3%** | +84.7pp |
| 误拦率 | 0% | 0% | — |
| 91% payload绕过旧版关键词 | — | — | — |

### RAG 检索最优配置 (Phase 1)

| 配置 | 准确率 | 召回率 | 幻觉率 |
|------|:---:|:---:|:---:|
| C4: k=8+r=5 (Hybrid+Rerank) | **80.0%** | 84.4% | 42.0% |
| Reranker 单独贡献 | +29.6pp | — | — |

### OWASP Top 10 for LLM Apps 覆盖

| 覆盖 | 未覆盖 |
|------|------|
| LLM01 Prompt注入, LLM02 不安全输出, LLM03 训练数据投毒, LLM06 敏感信息泄露, LLM09 过度依赖 | LLM04 DoS, LLM05 供应链, LLM07 不安全插件(→Phase 4.1), LLM08 过度代理(→Phase 4.1), LLM10 模型盗窃 |

---

## 目录结构

```
ai-sec-rag/
├── core/                   # 核心 RAG + Agent 逻辑
│   ├── graph_agent.py      # LangGraph StateGraph (5节点)
│   ├── rag.py              # RAG 检索引擎 + 安全钩子
│   ├── tools.py            # 4 个安全扫描工具
│   ├── dangerous_tools.py  # 4 个模拟危险工具 (4.1)
│   └── config.py           # LLM/RAG 配置
├── ai_security/            # AI 安全攻防模块
│   ├── classifier.py       # 3 层防火墙 (L1+L2+L3 + classify_with_context)
│   ├── adversarial.py      # 对抗样本生成 (4 种混淆技术)
│   ├── adaptive_attack.py  # 多轮越狱 + 角色扮演 (3.3)
│   ├── doc_poison.py       # 12 种 RAG 投毒场景 + PDF 生成 (3.2)
│   ├── doc_scanner.py      # L1/L2 文档安全扫描 (3.2)
│   ├── doc_poison_eval.py  # 投毒防护评估框架 (3.2)
│   ├── output_eval.py      # 输出安全评测 (3.4)
│   ├── benchmark.py        # 业界基准 + OWASP 映射 (3.5)
│   ├── evaluate.py         # 防火墙评估框架
│   └── payloads/           # 105+ 攻击载荷库
├── security/               # 安全基础设施
│   ├── policy_engine.py    # Tool Policy Engine (4.1)
│   ├── audit_log.py        # 审计日志 + SHA256 哈希链 (4.3)
│   ├── permission.py       # RBAC 3 角色权限
│   ├── input_check.py      # 旧版关键词检测
│   └── output_filter.py    # 敏感信息脱敏 + 合规检查
├── D_deliverables/         # 7 份攻防报告
├── R_raw/                  # 实验原始数据
├── T_tools/                # 评估/演示入口脚本
├── C_context/              # QA_log + bug.md + rag.md
├── app.py                  # Streamlit Web 界面
├── main.py                 # CLI 入口
└── ROADMAP.md              # 项目路线图 + 每日进度
```

---

## 面试30秒电梯演讲

> 我做的是一个面向企业 RAG Agent 的 AI 安全防护与评测系统。核心覆盖五大攻击面：Prompt 注入（防火墙 93.3% 拦截率）、文档投毒（12 场景 L1+L2 扫描）、工具滥用（Tool Policy Engine 10/10 策略测试）、输出幻觉（fact_check + 三级粒度 93.8% 准确率）、多租户泄露（5 项隔离测试）。纵深防御架构：输入端→知识库端→工具执行端→输出端→审计端，每层独立、漏过率相乘。

---

## License

MIT
