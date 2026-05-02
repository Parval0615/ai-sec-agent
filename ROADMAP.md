# AI安全Agent项目深度成长计划

> 不设时间限制，唯一原则：**深度优先于进度**。  
> 每阶段达到“完成标准”后再进入下一阶段，宁可慢，务求透。

---

## 第一阶段：核心基石 — RAG原理与工程深挖

**目标**  
能讲清每一行代码背后的原理，并拿出对比实验数据。

**核心任务**

1. **PDF解析深度优化**
   - 用 PyMuPDF 替代 PyPDF，重点解决表格提取、扫描件OCR、文档结构识别。
   - 编写对比脚本，量化新旧解析器在不同类型PDF上的解析准确率。

2. **分块策略与检索重排序**
   - 实现关键词(BM25) + 向量(语义)多路召回融合。
   - 引入 BGE-Reranker 重排序模型。
   - 设计实验，对比不同分块大小、重叠度、召回策略下的命中率、MRR等指标，输出《RAG检索策略性能对比报告》。

3. **向量数据库升级**
   - 从 FAISS 迁移到 Chroma 或 Milvus-lite，实现向量持久化与元数据过滤。
   - 为后续多租户和数据隔离打下基础。

4. **RAG幻觉与溯源**
   - 实现引用溯源，精确到源文档的页码和段落。
   - 通过API调用小模型校验生成答案是否忠实于检索片段，形成“事实一致性校验”模块。

**完成标准**
- 能画出完整的RAG数据流图，说明每个环节的选型理由与坑点。
- 能演示同一问题在不同策略下的答案差异。
- 仓库中有 `rag_evaluation/` 目录，包含对比脚本和报告。

**完成状态** (2026-05-01)
- [x] PDF解析：PyMuPDF 替代 PyPDF，含安全视角对比脚本（13场景: 注入/越狱/SQLi/命令注入/混淆/元数据投毒）
- [x] 分块策略：BM25 + 向量多路召回(RRF) + BGE-Reranker 重排序
- [x] 向量数据库：Chroma 持久化 + collection_name 参数隔离（chunk_size/chunk_overlap 编码）
- [x] 引用溯源：精确到源文档页码 + fact_check 事实一致性校验
- [x] `rag_evaluation/` 包：test_cases.py (15用例) + run_comparison.py (3组×11配置) + pdf_parser_comparison.py (13安全场景)
- [x] 对比实验：4轮完整实验 (qwen2:7b → Qwen3.5-35B → +Reranker)，准确率 26% → 80%
- [x] RAG检索策略性能对比报告 (v4 最终版)
- [x] `rag.md`：RAG 模块深度解析文档（架构/原理/坑点/实验数据）
- [ ] **待做**：OCR 扫描件支持、表格提取量化对比

---

## 第二阶段：智能体核心逻辑与生产级重构

**目标**  
将脆弱的调用链升级为健壮、可控、可解释的Agent架构。

**核心任务**

1. **框架升级：LangGraph**
   - 用 LangGraph 重写 Agent，实现可视化工作流。
   - 重点实现条件分支（如恶意代码走专用链）和循环调用（自动优化关键词重试检索）。

2. **深度工具调用能力**
   - 并行调用：同时扫描漏洞与收集子域名。
   - 长文本处理：工具返回超长时自动摘要与分片。
   - 错误自愈：工具失败时分析错误并修正参数重试。

3. **长对话记忆管理**
   - 实现滑动窗口 + 对话摘要的混合记忆。
   - 增加精准遗忘机制：用户説“忘掉之前那个IP”，Agent能精确移除对应记忆。

**完成标准**
- 可在 LangGraph Studio 中可视化任务分解与执行路径。
- 可演示工具调用失败后的自动重试与恢复。
- 能讲清楚 ReAct、Function Calling 等原理及选型原因。

---

## 第三阶段：AI安全硬核攻防 — 打造项目“压舱石”

**目标**  
产生与AI安全直接相关、可量化的深度产出，拉开与普通项目的差距。

**核心任务**

1. **Prompt注入攻防靶场与防御库**
   - 搭建本地攻击靶场，收集100+各类注入/越狱Payload。
   - 实现基于LLM的输入意图分类器，作为智能防火墙。
   - 设计攻防实验，量化拦截率、误拦率、响应延迟，形成《AI防火墙攻防对抗报告》。

2. **大模型安全脆弱性探究**
   - 实践对抗样本生成（如同义词替换绕过审核），探究模型幻觉导致的信息泄露风险。
   - 将研究成果工具化：开发自动化脚本批量检测LLM在特定安全场景的表现。

3. **AI驱动的代码安全审计工具**
   - 让Agent具备代码理解能力，能分析潜在SQL注入、XSS、命令注入等漏洞。
   - 必须工具化，而非简单调用通用大模型。

**完成标准**
- 能熟练演示10种绕过简单防护Prompt的方法并解释原理。
- 项目中出现 `ai_security/` 目录，含攻击库、防御分类器、测试脚本和报告。
- 对OWASP Top 10 for LLM Apps有脱稿讲解的能力。

---

## 第四阶段：安全工具集深度整合

**目标**  
将传统安全工具Agent化编排，体现攻防思维与工具链理解。

**核心任务**

1. **核心安全工具Agent化封装**
   - 信息收集：Nmap、Subfinder。
   - 漏洞检测：自研XSS/SQL注入POC，集成Nuclei。
   - 结果处理：Agent对工具返回结果自动摘要、去重、关联分析、攻击面排序。

2. **自动化攻击链演示**
   - 发现端口开放后，自动触发弱口令爆破或漏洞检测，形成简单的自动化攻击链。

**完成标准**
- 可通过自然语言指令：“扫描example.com前1000端口，发现Web服务后做轻量级漏洞扫描”，Agent自动编排 Nmap、子域名工具和漏洞POC完成任务。

---

## 第五阶段：企业级工程化落地

**目标**  
让项目脱离学生作业感，体现生产环境意识。

**核心任务**

1. **前后端分离与多租户**
   - FastAPI 重写后端，提供RESTful API与Swagger文档。
   - Vue3/React + Element Plus 重写前端，替代纯Streamlit。
   - 接入MySQL，实现注册登录、RBAC三级权限、多租户数据隔离。

2. **专业日志与监控**
   - 审计日志仅追加写入，考虑哈希链式防篡改。
   - 集成系统仪表盘：API请求量、P99延迟、Agent任务成功率等。

3. **容器化与一键部署**
   - 编写高质量 `Dockerfile` 和 `docker-compose.yml`。
   - README中加入构建、覆盖率、License等徽章。

**完成标准**
- 访问URL看到现代化登录页，不同角色登录后功能与数据隔离。
- 危险操作在管理员界面可查详细、不可篡改的审计日志。

---

## 第六阶段：包装、布道与外部验证

**目标**  
让项目“活起来”，获取真实反馈，积累面试故事素材。

**核心任务**

1. **GitHub仓库专业化**
   - 中英双语README：背景、架构图、功能GIF、快速开始、API文档、技术选型理由。
   - 录制3-5分钟项目演示视频，上传B站/YouTube，链接放入README。

2. **技术博客与社区输出**
   - 将第一、三阶段的对比报告整理为技术文章，发布到掘金/知乎/Medium。

3. **主动寻求外部反馈**
   - 将Agent发给安全朋友试用，收集反馈并改进。
   - 在合法SRC场景下用Prompt攻击库测试公开AI应用，有效发现即为硬通货。

**完成标准**
- 仓库有清晰README、架构图和演示视频。
- 发表的技术文章获得一定阅读与讨论。
- 能讲出他人使用反馈驱动改进的具体案例。

---

## 终极阶段：面试火力全开

**目标**  
将项目价值和个人能力最大化展现，对齐面试官考核标准。

**核心任务**

1. **STAR+L 简历重构**
   - 每个项目经历用“情境-任务-行动-结果-学到”法则重写。
   - 示例：“为解决RAG安全场景检索不准（S），设计混合检索+重排序方案（T），对比BM25与3种Embedding在千条数据上的表现（A），Top5命中率从61%提升至89%（R），深刻理解稀疏与稠密检索互补性（L）。”

2. **构建“面试脑图”**
   - 对项目任何技术点（如向量数据库）能向下深挖三层（CAP、索引类型、相似度算法）。
   - 总结10个项目中遇到的最棘手问题及解决思路。

**完成标准**
- 针对AI安全、后端开发、安全研发岗有定制简历版本。
- 能脱稿完成30秒、3分钟、10分钟的项目介绍。
- 简历上每个技术名词都做了被追问两次的深度准备。

---

> **全程提醒**：  
> - 每阶段结束后留出缓冲反思，主动进行模拟面试检验掌握程度。  
> - 遇到困难卡点，宁愿回头补基础，不可跳过留坑。  
> - 记住：在安全+AI这个交叉领域，**深度和可量化的产出，远胜于功能罗列。**

---

# 每日进度记录

## 2026-05-01

### 今日任务
- [x] 修复 Reranker 模型路径 → 从 HF 缓存加载 BGE-Reranker-Base
- [x] 重跑 B+C 组实验（Reranker 激活）→ C4: k=8+r=5 达 80.0% 准确率
- [x] 补跑 A 组实验（Reranker 激活）→ A2: chunk=800 达 76.7%
- [x] 撰写 `rag.md` — RAG 模块深度解析文档（架构/原理/8个坑/实验数据）
- [x] 更新《RAG检索策略性能对比报告》至 v4 最终版（全11配置+Reranker）
- [x] 整理 ROADMAP.md 进度区
- [x] CDTR 文件分类整理：创建四层目录，拆分 rag_evaluation/，修复 3 处 import，根目录仅保留 2 个 .py + 3 个 .md
- [x] **LangGraph Agent 重构 v1**：StateGraph 替代过程式 agent_invoke()（5节点/LLM选工具/多轮记忆修复）

### 实验最终数据（Qwen3.5-35B + BGE-Reranker）

| 配置 | 准确率 | 召回率 | 幻觉率 |
|------|:---:|:---:|:---:|
| A1: chunk=400 | 69.4% | 77.8% | 44.5% |
| A2: chunk=800 | 76.7% | 82.8% | 42.1% |
| A3: chunk=1200 | 76.7% | 76.1% | 42.7% |
| B1: Vector-only | 66.7% | 68.3% | 44.7% |
| B2: BM25-only | 37.8% | 41.7% | 64.2% |
| B3: Hybrid (no Rerank) | 61.7% | 73.3% | 49.5% |
| B4: Hybrid+Rerank | 76.7% | 82.8% | 44.8% |
| C1: k=3+r=3 | 73.3% | 77.8% | 45.3% |
| C2: k=5+r=3 | 76.7% | 82.8% | 43.5% |
| C3: k=5+r=5 | 76.7% | 82.8% | 46.7% |
| **C4: k=8+r=5** | **80.0%** | **84.4%** | **42.0%** |

### LangGraph Agent 重构 v1 详情

**新文件**: `core/graph_agent.py` — 5 节点 StateGraph（guardrail/agent/tools/output_filter/finalize）

**核心改进**:
- LLM `bind_tools` 选工具，替代 `if/elif` 关键词路由
- 多轮记忆修复：`chat_history` + `add_messages` → 第二轮正确记住用户名
- ReAct 循环：agent ⇄ tools 条件边
- 权限预过滤：越权工具对 LLM 不可见（guest 看不到 SQL 注入工具）
- RAG 工具化：`search_document` 让 LLM 自主决定检索
- 输出过滤：仅拦截可执行 payload，不误拦安全术语讨论
- 5/5 测试通过（SQL检测/XSS问答/权限/越狱/多轮记忆）

**保留**: `core/agent.py` 原样不动（向后兼容）

### LangGraph Agent v2 详情（工具自愈 + 并行 + 滑动窗口）

**改动**: 仅 `core/graph_agent.py`

- **重试上限**：State 增加 `tool_call_count`，agent_node 在 count>=3 时强制不绑工具，防止无限 ReAct 循环烧 API
- **自定义 tool_node**：替换内置 ToolNode，捕获异常返回结构化错误 ToolMessage，每次执行递增计数器
- **并行调用**：system prompt 引导 LLM 同时调多个独立工具，LangGraph 自动并发执行（实测：扫描+SQL检测同时返回）
- **滑动窗口**：`graph_invoke` 新增 `max_history=20`，超过阈值裁剪旧消息，防止长对话溢出上下文
- 4/5 测试通过（1 个因 API 限流中断，非代码 bug）
- **删除**: `from langgraph.prebuilt import ToolNode`（已不用内置版）

### LangGraph Agent v3 详情（摘要记忆 + 精准遗忘 + 长文本截断）

**改动**: 仅 `core/graph_agent.py`

- **对话摘要**：State 新增 `conversation_summary`，graph_invoke 在 history 超 max_history 时调用 `_generate_summary()` 压缩旧消息为 2-3 句中文摘要，agent_node 注入 system prompt
- **精准遗忘**：graph_invoke 正则检测 `忘掉|忘记|forget` 命令，分词匹配从 history 中删除相关消息，更新 caller 的 chat_history 引用
- **长文本截断**：tool_node 中 `MAX_TOOL_RESULT=2000`，工具返回超长自动截断并标注原始长度
- 测试：遗忘精度验证通过（4 条消息中 3 条含 IP 的被准确删除，不含 IP 的保留）
- API 限流影响摘要测试（ModelScope Qwen3.5-35B 日配额耗尽），代码逻辑正确

### 明日任务
- [ ] Phase 2 Day 4：LangGraph Checkpointer 持久化（SQLite 存储对话状态） + 工具长文本 LLM 摘要

---

## 2026-04-30

### 任务完成清单

**Bug 修复 (8项)**
- [x] langchain 1.x 迁移：手写 ConversationBufferMemory + 安装 5 个缺失依赖
- [x] emoji GBK 崩溃：6 文件中 30+ emoji → ASCII（⚠→[!], ✅→[OK], ❌→[X]）
- [x] Chroma 索引污染：collection_name 编码 chunk_size/chunk_overlap
- [x] B 组 monkey-patch 无效：rag_query() 增加 strategy 字段
- [x] Reranker 模型路径：`models/` → `BAAI/bge-reranker-base`（HF 缓存加载）
- [x] RAG init 异常阻塞非 RAG 工具：`_get_default_retriever()` 加 try-except
- [x] `requirements.txt` 补 `langchain-openai` + `rank_bm25` + `reportlab` + `pypdf`

**模型升级**
- [x] 本地 qwen2:7b → ModelScope API Qwen/Qwen3.5-35B-A3B
- [x] 备选：SiliconFlow API deepseek-ai/DeepSeek-V4-Flash（可用但略慢）

**评测框架建设**
- [x] `rag_evaluation/pdf_parser_comparison.py`：13 个安全测试场景，运行时生成 PDF
- [x] `run_pdf_comparison.py`：CLI 入口
- [x] 重跑全量 RAG 对比实验（Qwen3.5-35B，无 Rerank）：A+B+C = 11 配置
- [x] 更新《RAG检索策略性能对比报告》v1-v3

**文档**
- [x] `bug.md`：记录 3 个 Bug 的根因与修复
- [x] `QA_log.md`：混合检索原理、Python import 机制、PDF 攻击面等苏格拉底讨论
- [x] `rag.md`：RAG 模块深度解析

**关键发现**
- Reranker 是单因子最大贡献者：C4 从 50.4% → 80.0% (+29.6pp)
- BM25 在中文场景严重不足 (38%)，纯 Vector 反而更优 (67%)
- 有 Reranker 时 chunk 大小不再敏感，A2/A3 持平
- DeepSeek-V4-Flash 在 ModelScope 上返回空 choices（API 协议不兼容），SiliconFlow 可用

---

## 2026-04-29

### 任务完成清单
- [x] `core/rag.py`: init_rag_retriever() 增加 chunk_size/chunk_overlap/enable_rerank/vec_top_k/rerank_top_n 参数
- [x] `core/rag.py`: rag_query() 增加 enable_rerank/rerank_top_n 参数
- [x] `core/rag.py`: emoji → ASCII，修复 Windows GBK 编码报错
- [x] `core/tools.py`: pydantic.BaseModel → pydantic.v1.BaseModel，修复 langchain tool 加载
- [x] `core/rag_evaluator.py`: emoji → ASCII
- [x] `rag_evaluation/` 包搭建：`__init__.py` + `test_cases.py`(12用例) + `run_comparison.py`
- [x] `run_evaluation.py`: CLI 入口
- [x] QA_log.md: "召回率是什么" 苏格拉底问答 