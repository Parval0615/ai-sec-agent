# QA Log

## 2026-05-07

### 苏格拉底问答：哈希链——为什么能防篡改但防不住全链替换？

围绕 Phase 4.3 审计日志哈希链实现的讨论。

**1. 哈希链为什么能精确检测篡改？**

每条日志的 hash = SHA256(本条内容 + 上一条的hash)。修改任何一条日志 → 该条的hash变了 → 下一条的prev_hash不匹配 → 链断裂。校验函数从第一条开始重算，遇到的第一处不匹配就是被篡改的条目。

这实际上是 Git 和区块链的核心数据结构——每个 commit/block 包含 parent 的 hash。

**2. 哈希链防不住什么？**

全链替换：攻击者删除全部日志，重新构造一条完整的新链（从头计算所有hash）。因为哈希链只能验证内部一致性，不能验证链本身的真实性——需要外部锚定（定期将 last_hash 写入只读存储）。

类比：Git 的 commit hash 能验证历史完整性，但如果你 force push 一个全新的历史，旧 commit 还在 reflog 里——审计日志没有 reflog，需要外部备份。

**3. 为什么选 JSON 而不是二进制？**

审计日志的核心需求是人类可读——安全审计人员需要能直接查看日志。JSON 比二进制（Protobuf/MessagePack）更可读，比纯文本（旧版管道分隔）更结构化。代价是体积更大——但对于审计日志这种写入频率低的场景，体积不是瓶颈。

**4. 旧版 3000+ 条日志怎么办？**

校验函数跳过旧版管道分隔行——它们不受哈希链保护。生产环境需要一次性迁移。但迁移会改变旧日志的原始格式和时间戳——有些合规场景要求保留原始日志不变。权衡方案：保留原始 audit.log 为只读归档，新日志写入 audit_v2.jsonl。

### 苏格拉底问答：多租户隔离——三层防御的边界在哪里？

围绕 Phase 4.2 多租户隔离验证的讨论。

**1. Chroma collection_name 隔离真的安全吗？**

隔离有效（已验证：不同 session_id → 不同 collection_name → 物理隔离），但安全建立在 session_id 的唯一性假设上。UUID4 碰撞概率极低（~10^-18），但应用层不做 session_id 所有权验证——任何人知道 session_id 就能访问对应 collection。如果攻击者能探查到其他租户的 session_id（通过日志泄露/错误信息/时序攻击），隔离就失效了。

**2. thread_id 是安全边界吗？**

不是。thread_id 是对话标识符——两个用户共享同一个 thread_id 意味着他们共享对话。这在协作场景是预期行为，但在多租户场景是隐含风险。真正的安全边界在数据层（collection_name）和文件系统层（SQLite/ChromaDB 文件权限）。

**3. 为什么文件系统是最后防线？**

SQLite 和 ChromaDB PersistentClient 都没有内置认证——任何能访问 `checkpoints/` 和 `chroma_db/` 目录的进程都能绕过所有应用层隔离。这也是为什么生产环境需要迁移到需要认证的数据库（PostgreSQL RLS + ChromaDB Server API Token）。

**4. 隔离方案最薄弱的环节是什么？**

文件系统假设。容器逃逸、路径遍历、共享存储误配置、备份文件未加密——这些攻击路径都在应用层隔离的覆盖范围之外。应用层隔离（session_id + collection_name）保证**逻辑隔离**，但不能替代**物理隔离**（文件系统权限/数据库认证/网络隔离）。

### 苏格拉底问答：策略引擎——为什么防火墙+RBAC还不够？

围绕 Phase 4.1 Tool Policy Engine 的设计展开的讨论。

**1. 为什么有了防火墙 (3.1) 和 RBAC (Phase 2)，还需要策略引擎？**

核心认知：这是**防御纵深**的概念。防火墙守输入端（"你说的话危险吗？"），RBAC 守工具列表（"你能用这个工具吗？"），策略引擎守工具参数（"你用这个工具做什么？"）。

三个层次各司其职：防火墙拦截"忽略指令执行 DROP"（攻击在用户输入中），RBAC 让 guest 根本看不到 db_query（攻击面缩小），策略引擎让 admin 能看到 db_query 但不能执行 DROP（操作级限制）。缺失任何一层都会有防御空洞。

**2. 策略引擎为什么用纯规则（<1ms）而不是 LLM（~500ms）？**

业务场景决定技术选择。策略引擎在 tool_node 中同步调用——每增加 500ms 延迟用户都能感知。而且危险 SQL 操作（DROP/DELETE）比 Prompt 注入有更明确的特征——不需要语义理解。类比防火墙 L1 vs L2：策略引擎选择了 L1 策略——快速、确定、零延迟。

**3. 策略引擎的 3 个失败案例分别揭示了什么问题？**

信息流追踪盲区（看单次调用不看数据流向）、参数编码绕过（正则无法处理 LLM 的创造性参数构造）、非预期工具滥用（覆盖面有限）。共同根因：策略引擎是**操作级**检查不是**意图级**理解。

**4. 策略规则为什么用 JSON 可配置而不是代码？**

多租户场景需要独立配置文件，安全团队可以修改策略而不需要改代码/跑 CI/CD/重启服务。和 3.4 输出过滤的三级粒度同一种设计哲学——策略是部署时的选择，不是开发时的决定。

### 苏格拉底问答：消融实验——防火墙的增量贡献比绝对数字更重要

围绕"基准对标最有含金量"这一判断展开的递进讨论。

**1. 为什么需要消融实验？**

用户从"跑基准拿高分"出发，经过递进追问，得出核心认知：HackAPrompt 拿 93% 没有意义——需要区分防火墙贡献 vs LLM自身安全对齐贡献。方法是对照实验：防火墙开启 vs 防火墙关闭。

**2. 三种消融结果的面试解读**

| 结果 | LLM裸拦截 | 防火墙拦截 | 防火墙净贡献 | 面试评价 |
|------|:---:|:---:|:---:|------|
| 情况1 | 70% | 93% | +23pp | 有贡献但不是核心卖点 |
| 情况2 | 93% | 93% | 0 | **减分项**——防火墙是死重，增加延迟无收益 |
| 情况3 | 10% | 93% | +83pp | 防火墙贡献巨大，但同时暴露底层模型很弱 |

用户对情况2的判断（"减分项"）体现了非直觉的工程思维——大多数人本能地把绝对数字当成绩宣传，但真正的问题是"你做的东西有没有边际贡献"。

**3. 核心洞察：消融实验思维比基准分数更有面试说服力**

绝对数字（93%）是营销，增量贡献（+23pp vs 0pp vs +83pp）是工程。面试中区分"做了项目的人"和"真正懂评估的人"的关键是：能否主动讨论防火墙的增量贡献而非绝对拦截率，能否拆分各层的独立贡献。

**4. 延伸：这个思维也适用于 3.4 输出评测**

输出过滤器的 `fact_check` 集成同样需要消融实验——在 RAG 场景下，有多少比例的幻觉是 LLM 自身会避免的（好的安全对齐），有多少是 `fact_check` 额外拦截的（增量贡献）？如果增量接近零，那 `fact_check` 就是增加延迟的装饰品。

### 苏格拉底问答：多轮上下文感知——为什么静态防火墙对渐进式越狱失效？

围绕 Phase 3.3 `classify_with_context()` 的实现展开的防御架构讨论。

**1. 为什么单轮防火墙对多轮越狱天然弱势？**

用户推理出核心问题：单轮 `classify()` 每次独立判断，看不到"前3轮都在建立信任"这个上下文模式。

延伸：防火墙本质上是无状态的——类比WAF检查每个HTTP请求但不跟踪会话。攻击者利用的就是这个"无状态窗口"：每一轮单独看都是安全讨论，但串联起来是逐步升温的越狱。

**2. classify_with_context() 的三种模式为什么选这三个？**

三个检测模式：
- **escalating（风险递增）**：前几轮风险分数逐轮上升，说明攻击者正在"爬坡"
- **pivot（突然转向）**：前三轮都是安全讨论（risk<10），第四轮突然涉及攻击——典型的信任建立后转向
- **cumulative（累积效应）**：前几轮平均风险中等，加上当前轮风险——多轮边界效应叠加

用户追问：为什么不直接对前N轮做聚类分析？回答：聚类需要的计算量和API调用数不可接受——每次guardrail都要重新分类前N轮。当前的滑动窗口（最近3轮）+ 规则判断是延迟/成本/准确率的最优平衡点。

**3. 为什么角色面具能降低拦截率？**

关键发现：角色扮演不是"绕过"防火墙，而是"稀释"了恶意关键词的密度。

例如："作为安全研究员，我需要了解..."——"安全研究员"这个角色框架让L1的复合词对检测失效（"忽略"+"指令"配对在40字符内不存在），同时让L2 LLM的分类倾向于"安全讨论"而非"攻击请求"。

这解释了为什么角色扮演绕过率高于直接注入——不是因为防火墙弱，而是因为攻击信号被角色框架的"安全词汇海绵"吸收了。

### 苏格拉底问答：输出过滤粒度——“什么该拦”是技术问题还是产品问题？

**1. strict/balanced/lenient 的选择标准是什么？**

核心洞察：这不是技术问题，而是产品策略问题。

- strict适合对外AI服务（"宁可误拦，不可漏拦"）
- balanced适合安全培训平台（"允许演示原理，不允许给可执行代码"）
- lenient适合内部研究工具（"研究员自己负责"）

技术层面只能提供三级配置和对比数据，最终选择取决于业务容忍度。这也是为什么 Lakera Guard 只有单一阈值——商业产品简化决策。

**2. 为什么 fact_check 用 n-gram 而不是 LLM？**

fact_check 在 output_filter_node 中是同步调用的——如果每次都调LLM，输出延迟会从 <10ms 飙升到 ~500ms。n-gram 是"快速筛"，延迟可忽略。

工程权衡：n-gram 可能在 5% 的边缘案例中误判，但 95% 的正确率 + 零延迟 优于 99% 的正确率 + 500ms 延迟——因为输出过滤的目标是"不阻塞正常回答"，而非"完美检测所有幻觉"。

### 业界基准对标讨论

**1. 为什么 HackAPrompt 的基线拦截率这么低（10-30%）？**

HackAPrompt 比赛在 2023 年举行，当时使用的是 GPT-3.5 级别的模型。基线数据来自比赛参与者的提交——大部分是简单的关键词过滤或 prompt engineering。今天（2026年）的 LLM 安全对齐已经远优于 2023 年，所以本项目 90%+ 的拦截率需要区分"防火墙贡献"和"底层LLM自身安全对齐贡献"。

**2. OWASP Top 10 覆盖了 6/10，剩下的 4 项为什么不覆盖？**

未覆盖的 LLM04/05/07/08 都是基础设施/供应链层面的风险：
- LLM04 (DoS): 需要资源限制，不是检测问题
- LLM05 (供应链): 需要 SBOM/签名验证，不是 Prompt 检测
- LLM07 (不安全插件): Phase 4 Tool Policy Engine 将覆盖
- LLM08 (过度代理): Phase 4 RBAC+策略引擎将覆盖

明确项目的边界——"我不知道"比"我假装覆盖了"更有面试说服力。

---

## 2026-05-06

### 苏格拉底问答：PDF投毒检测——白字攻击的规则设计取舍

围绕 Phase 3.2 白字攻击（ps_003）L1漏检展开的防御架构讨论。

**1. 白字攻击检测应该放在哪一层？**

用户选择 A（PDF解析层，`page.get_text("dict")`）而非 B（L1扫描器）或 C（标注已知局限）。

理由：白字攻击属于"渲染层"问题——文字颜色是 PDF 渲染属性，信息在解析时天然存在，丢弃后再在 L1 做文本层面检测是不可逆的信息损失。放在解析层是从信息源头解决问题，代价是解析逻辑更复杂、与 PyMuPDF 内部 API 耦合。

**2. 隐藏文字的判定标准：为什么选 3+4**

四种判定方法中，用户选择 3（`size < 1pt`）+ 4（`ΔE < 5`）：

- 规则3（字号）：攻击者不可能把字号设得太小同时正常用户也能看到——物理上限是 0.5pt，阈值设 1pt 留有安全余量。少数正常文档可能有极小字号（水印、页脚），但通常 < 1pt 同时出现 ΔE 小才是投毒——仅靠字号会误报。
- 规则4（ΔE）：覆盖"近色隐藏"——攻击者把颜色设得非常接近背景色（`#FEFEFE` vs `#FFFFFF`），肉眼不可见但解析器正常提取。ΔE < 5 是印刷行业公认的"人眼不可分辨"阈值。

两者互补：规则3拦字号攻击，规则4拦颜色攻击。单独使用各有盲区——规则3漏正常字号+近色攻击，规则4漏正常色+极小字号攻击。

**3. 边界情况：`color=0` 是什么？**

场景C：PyMuPDF 返回 `color=0`。这不是 `#000000` 黑色，而是"字段缺失时的整数值 0"。对应 RGB `(0,0,0)` 即纯黑，与白色背景 ΔE 很大，不会触发规则4。

追问：攻击者能反向利用吗？上传 `color` 全为 0 的 PDF——正常黑色文字写恶意指令，规则3+4 都拦不住。

**4. 核心架构洞察：三层纵深**

这不是 Bug，这是分层设计的意图：

```
规则3+4 (PDF渲染层) → 拦"看不见"的文字
    ↓ 漏了
L1 复合词对       → 拦"看得见但模式可疑"的文字  
    ↓ 漏了  
L2 LLM语义       → 拦"长得正常但语义危险"的文字
```

每层有自己不可替代的检测维度。攻击者绕过上层，下层兜底。这和一个"完美检测"的幻想不同——现实的安全架构就是层层削减、管理剩余风险。

**相关引用**：`ai_security/doc_scanner.py` — `scan_chunk_l1()` L1规则实现；`ai_security/doc_poison.py` — ps_003 场景定义；`D_deliverables/RAG投毒防护报告.md` 第6章失败案例分析。

---

## 2026-05-02

### 苏格拉底问答：Checkpointer 双路径、错误自愈、关键词重试、ReAct vs 关键词路由

围绕 Phase 2 Day 4-5 四个新特性逐层讨论。

**1. Checkpointer 双路径：为什么有 chat_history 时用唯一 thread_id**

用户推演了"有 chat_history 用固定 thread_id"的后果：第一次 checkpoint 存 2 条消息，第二次追加完整 chat_history+新消息（4 条），第三次追加 6 条……第 N 次调用后在 checkpoint 里追加约 2N 条消息，"你好"出现 3 次。增长模式是 O(n²) 二次增长——因为 `add_messages` reducer 把 state 里的消息全部追加到 checkpoint，不做去重。

解决方案：有 `chat_history` 时每次生成唯一 `thread_id`（`uuid4().hex[:8]` 后缀），checkpointer 找不到旧状态，从零开始——避免重复叠加。无 `chat_history` 时用固定 `thread_id`，checkpointer 的 `add_messages` 只在已有消息后面追加新的 HumanMessage + AI 回答，天然正确。

关键认知：Streamlit 旧代码传 `chat_history` → 每次唯一 thread_id → checkpoint 只写不读 → 持久化名存实亡。改为纯 checkpointer 模式（固定 thread_id + `get_thread_messages` 恢复）后，SQLite 才真正发挥作用。

**2. 错误自愈：结构化错误信息的三个必要条件**

旧错误消息 `[ERROR] TypeError: ... Try different parameters.` 漏了三件事中的两件：工具名（不知道哪个调用出错）、实际参数（不知道自己传了什么）、修复提示（仅一句模糊的 "try different"）。LLM 面对多条并行调用时，无法将错误对应到具体调用，也就无法修正。

新 `_format_tool_error()` 补齐三件套：`Tool 'xxx' failed` / `Called with: {"url": "example.com"}` / `Hint: Check that 'url' starts with http://`。每个工具一个专属 Hint。加上 system prompt 的 Self-healing 段明确指引 LLM "读 Hint → 改参数 → 重试"。

**3. 关键词重试检索：为什么第一遍没找到不能直接告诉用户**

用户列出三种策略：(1) 换词重试 (2) 调其他工具 (3) 告诉用户没找到。我们选策略 (1)。

选 (1) 而非 (2)：search_document 和其他工具职责不同，调了也无用。
选 (1) 而非 (3)：第一遍没找到可能是用词不匹配（用户说"数据保护"而文档写"隐私保护"），换近义词重试可能命中。直接告诉用户会错失正确答案。

实现：`search_document` 返回 `[SEARCH_RETRY]` 标记 + 具体换词建议，system prompt 加 "Keyword retry" 段，最多 2 次重试。测试验证 LLM 自动从"安全策略"换到"策略"再换到"安全"，最终找到相关内容。

**4. ReAct (Function Calling) vs 关键词路由：架构级差异**

用户推演了同一个输入 "帮我检查一下网站有没有SQL注入风险 https://example.com" 在两种架构下的行为：
- 关键词路由：命中第一个 `if "sql注入"`，只调 SQL 工具，网站扫描被忽略
- Function Calling：LLM 理解意图 = SQL检测 + 漏洞扫描，一次返回两个 tool_call，并行执行并合并结果

核心差异：关键词路由是字符串匹配（只看到关键词，看不到组合意图），Function Calling 是语义理解（LLM 从完整句子中提取要做什么 + 参数怎么填 + 能不能并行）。这也是为什么 ReAct Pattern（Think → Act → Observe → Think → ...）比一次性路由更强大：每一步都基于上一步的观察结果重新推理，而非第一次匹配后就定格。

### 关联引用
- `core/graph_agent.py:L310-L370`: graph_invoke 双路径实现
- `core/graph_agent.py:L83-L97`: `_summarize_tool_result()` 工具 LLM 摘要
- `core/graph_agent.py:L227-L257`: `_format_tool_error()` + `tool_node` 错误自愈
- `core/graph_agent.py:L36-L53`: `search_document` 的 `[SEARCH_RETRY]` 重试逻辑
- `core/graph_agent.py:L142-L160`: agent_node system prompt 完整规则
- `app.py:L27-L29`: Streamlit 首次加载从 checkpointer 恢复对话
- `main.py`: CLI 纯 checkpointer 模式 + `clear_history()` 集成

---

## 2026-05-01

### 苏格拉底问答：工具自愈 + 并行调用 + 滑动窗口 vs 精准遗忘

围绕 Phase 2 Day 2 的三个新特性逐层讨论。

**1. RETRY_LIMIT：为什么需要重试上限**

没有上限时，ReAct 循环可能无限运行——LLM 对工具结果不满意时反复调用不同工具，每一轮都是 API 消耗（数百 tokens + 1-2 秒延迟）。`RETRY_LIMIT=3` 是硬刹车：`agent_node` 检查 `tool_call_count >= 3` 后不绑工具，强制 LLM 直接回答。

注意不是"最多 3 次重试"而是"最多 3 次工具调用总次数（含首次）"。并行调用时 LLM 可以一次发多个 tool_calls，count 一次性加 N，下一轮 count=N >= 3 直接终止。设计意图是限制迭代轮数而不限制并行度。

**2. 自定义 tool_node：异常不崩溃，封装成消息**

内置 `ToolNode` 不暴露计数器、不包装异常。自定义版本：
```python
try:
    result = tool_fn.invoke(tool_args)
    tool_messages.append(ToolMessage(content=str(result), ...))
except Exception as e:
    error_msg = f"[ERROR] {type(e).__name__}: {str(e)}. Try different parameters."
    tool_messages.append(ToolMessage(content=error_msg, ...))
```

异常被捕获后以 `ToolMessage` 形式返回给 LLM。LLM 看到 `[ERROR] ValueError: invalid URL` 后有三个选择：修正参数重试、换另一个工具、告知用户无法完成。决策权完全在 LLM，不是硬编码的 fallback 逻辑。

**3. 滑动窗口：简单但有代价**

```python
if len(history) > max_history:
    history = history[-max_history:]
```

超过阈值时直接丢弃旧消息，保留最近 N 条。代价：早期包含关键上下文的对话（如"我是安全管理员，在审计内网"）会被丢弃，导致后续回答脱离背景。

用户准确指出了滑动窗口的问题："重要信息可能会放在第一句话，描述整体的背景，就会导致后面的对话会忘记掉背景前提"。

**4. 滑动窗口 vs 精准遗忘 vs 对话摘要**

三种记忆管理策略的区别：

| 策略 | 谁发起 | 机制 | 解决的问题 |
|------|--------|------|-----------|
| 滑动窗口 | 系统自动 | 超过 N 条裁旧消息 | 防止 token 无限增长 |
| 精准遗忘 | 用户主动 | 用户说"忘掉 X"→删除指定内容 | 立即删除某条敏感/错误信息 |
| 对话摘要 | 系统自动 | 早期对话压缩为摘要嵌入 prompt | 保留语义同时省 token |

三者互补而非替代：
- 纯压缩不遗忘：压缩后的摘要也会无限积累，仍需上限
- 纯遗忘不压缩：用户不提就永远不删，token 无限增长
- 滑动窗口+压缩：窗口内的保留原文，窗口外的压成摘要
- 滑动窗口+精准遗忘：系统管总量，用户管内容

**相关引用**：`core/graph_agent.py` agent_node（RETRY_LIMIT）、tool_node（异常包装）、graph_invoke（max_history）

---

### 苏格拉底问答：LangGraph Agent 架构深度讲解

围绕 `core/graph_agent.py` 的整体架构、核心概念和代码实现逐层讨论。

**1. 新旧架构对比：加一个工具需要改几处？**

旧架构 (`agent_invoke`)：需在 `core/agent.py` 新增 `elif` 分支（~15 行，含关键词匹配、权限检查、参数提取、try/except、LLM 格式化），加上 `core/tools.py` 定义工具，共 2 个文件 ~20 行。每个分支内的 4 步流程（关键词→权限→调工具→LLM格式化）硬编码重复。

新架构 (`graph_agent.py`)：只需在 `core/tools.py` 定义工具并加入 `SEC_AGENT_TOOLS`。`agent_node` 通过 `bind_tools(available_tools)` 自动感知新工具，路由逻辑零修改。

根源区别：旧架构靠开发者的 `if/elif` 关键词匹配分发工具，新架构让 LLM 通过 function calling 自主决定。

**2. ReAct 循环：agent ⇄ tools 的工作原理**

`START → guardrail → agent ⇄ tools → output_filter → finalize → END`

消息流转示例（用户问"扫描 URL 并检测 SQL 注入"）：
```
[HumanMessage]                                    ← 用户输入
[AIMessage(tool_calls=[scan])]                    ← LLM 第1次决策
[ToolMessage("扫描结果")]                          ← 工具返回
[AIMessage(tool_calls=[check_sql_injection])]     ← LLM 第2次决策
[ToolMessage("SQL检测结果")]                       ← 工具返回
[AIMessage(content="综合评估")]                    ← LLM 最终回答（tool_calls为空）
```

关键函数 `route_after_agent`：检查最后一条 AIMessage 的 `tool_calls` 是否非空 → 非空走 tools 继续循环，为空走 output_filter 结束。

与旧架构的单向单选对比：旧架构的 `if/elif` 并列只能命中一个分支，新架构可多轮调用不同工具形成工具链。

**3. add_messages：为什么多轮记忆"修好了"**

旧架构 `save_context()` 只写到内存 list 但从不读回 Prompt，每次 LLM 调用只看到当前单条消息。

`add_messages` 是 LangGraph 的 reducer（合并器）——每次节点返回新消息时**追加**而非**覆盖**：
```
无 reducer: [A, B] + [C] → [C]           # 覆盖
add_messages: [A, B] + [C] → [A, B, C]   # 追加
```

效果：多轮对话自动累积，ReAct 循环中的 ToolMessage 自动追加到历史，LLM 每次都能看到完整上下文。

验证：第二轮问"我叫什么名字？"正确回答"小明"，证明历史消息被正确传递。

**4. ContextVar：retriever 为什么不放 AgentState**

retriever 包含 Chroma 数据库连接、BM25Retriever 对象、几百个 Document——不可序列化，放 State 会在未来启用 Checkpointer 时炸裂。

也不能让 LLM 传 retriever 参数——LLM 根本不知道 retriever 是什么，只会传 `query` 字符串。

普通全局变量：多用户同时使用时互相覆盖（Streamlit 多会话共享进程）。

`ContextVar`：Python 的 `contextvars` 模块为每个线程/协程维护独立的变量副本。用户 A `set(retriever_A)` 后 `get()` 返回 A，用户 B `set(retriever_B)` 后 `get()` 返回 B，互不干扰。

```python
_current_retriever: contextvars.ContextVar = contextvars.ContextVar('current_retriever', default=None)
```

**5. 权限预过滤 vs 调用时拒绝**

旧架构：LLM 不知道要调哪个工具（关键词匹配决定的），在工具调用前 `check_tool_permission()` 拒绝。

新架构：`agent_node` 在 `bind_tools()` **之前**按角色过滤工具列表：
```python
allowed_names = get_allowed_tools(role)
available_tools = [t for t in SEC_AGENT_TOOLS if t.name in allowed_names]
```

guest 用 `bind_tools()` 时 LLM 收到的工具列表里根本没有 `check_sql_injection`——不是"调了被拒"，而是"根本不知道这个工具存在"。符合安全最小信息暴露原则。

**核心概念速查表**：

| 概念 | 一句话 |
|------|--------|
| StateGraph | 用节点+边描述 Agent 流程，替代过程式 if/elif |
| ReAct 循环 | agent ⇄ tools，LLM 反复决策直到不需要工具 |
| `route_after_agent` | `tool_calls` 非空→继续循环，为空→最终回答 |
| `add_messages` | 消息追加而非覆盖，多轮记忆和工具历史自动累积 |
| ContextVar | 线程安全的"全局变量"，每个请求独立副本 |
| 权限预过滤 | `bind_tools` 前过滤，越权工具对 LLM 不可见 |

**相关引用**：`core/graph_agent.py`（完整实现），`core/agent.py`（旧架构对比参考）

---

## 2026-04-30

### Q: 什么是混合检索？为什么 BM25 + 向量检索的混合 RRF 在某些场景下优于纯向量检索？

**讨论过程**：
1. 用户从 B 组实验结果引入问题：BM25 (31%) vs Vector (68%)，为什么 BM25 在中文上差距这么大
2. 解释 BM25 是字面匹配（TF-IDF 变体），向量检索是语义匹配
3. RRF (Reciprocal Rank Fusion) 的数学原理：`score = sum(1/(k+rank))`，k=60 是标准平滑参数
4. 两种路径的互补性：精确匹配（BM25 优势：工单编号、API 名称、代码片段）vs 语义泛化（向量优势：同义词、跨语言、模糊查询）
5. 用户被问到：混合检索什么场景下优于纯向量？→ BM25 解精确匹配问题，向量解语义泛化问题，RRF 让同时被两者排在前面的文档胜出

**结论**：
- BM25 + 向量是互补关系，不是替代关系
- 纯向量在中文通用问答上更优（实验证明 68% vs 31%），但在含大量精确标识符（ID/编号/API名/代码）的文档上混合检索会反超
- RRF 的核心价值是同时被两个路径认可的结果获得最高分，实现互相纠错
- 当前实验 PDF 缺少精确查询用例（如「查询INC-2026-0042」），这解释了为什么 BM25 表现极差

**相关引用**：`core/rag.py` rag_query() 中的 `_rrf_merge()` 实现，`rag_evaluation/reports/RAG_检索策略性能对比报告.md`

---

### Q: 为什么 PDF 文本提取对比中 PyMuPDF 和 PyPDF 表现完全一致？什么情况下才会出现差距？

**苏格拉底讨论过程**：
1. 用户注意到两个解析器 match_rate 都是 97.35%、security_detectable 都是 8/8
2. 提问：我们生成的 PDF 有什么共同特征？→ 用户回答：都是纯文字的
3. 追问：如果攻击者想绕过检测，会利用 PDF 的哪些容器特性？→ 用户回答：图片
4. 补充 PDF 格式的其他攻击面：JavaScript、嵌入式附件、表单、隐藏注释
5. 追问：当前 `get_text()` 能提取到藏在 JS/附件/注释里的 payload 吗？→ 用户正确回答：提取不到

**结论**：
- 对比脚本在纯文本 PDF 上两个解析器表现一致是合理结论，不是 bug
- 真正的安全盲区不在「选哪个解析器」，而在「只提取了文本层」
- 未来改进方向：`extract_pymupdf` 应扩展为提取 annotations、embedded files、JS 脚本内容，形成多层安全扫描
- PDF 格式本身就是攻击面——需要组合多个 fitz API (`page.get_annot_text()`, `doc.embfile_names()`, `doc.xref_get_keys()`) 而非仅 `page.get_text()`

**相关引用**：`rag_evaluation/pdf_parser_comparison.py`, `core/rag.py` init_rag_retriever()

---

### Q: Python 的 `from X import Y` 和 `import X; X.Y` 有什么区别？为什么 monkey-patch 不生效？

**苏格拉底讨论过程**：
1. 用简单例子切入（`from module_a import x` 后改 `module_a.x`，旧引用不变）
2. 用户正确判断 `print(x)` 输出 10 而非 20
3. 迁移到真实 bug 场景：`agent.py` 中 `from core.rag import rag_query` 创建了本地引用，`run_comparison.py` 中 `rag_mod.rag_query = vector_only_query` 只改了模块属性，agent.py 的本地变量不受影响
4. 用户最终理解了核心区别：`from X import Y` 是「拷贝引用」，`import X; X.Y` 是「每次通过 X 找」

**结论**：`from X import Y` 在导入瞬间把 Y 的引用绑定到本地名字空间，之后对模块属性的修改不会自动传播。这等价于：`import X; Y = X.Y; del X`。我们的修复方案是放弃 monkey-patch，改为在 retriever dict 中传递 strategy 字段，让函数内部自行判断分支。

**相关引用**：`core/rag.py` rag_query(), `rag_evaluation/run_comparison.py` run_experiment_b()

---

## 2026-04-29

### Q: 召回率是什么？
召回率衡量检索环节中，期望找到的关键信息实际被检索到了多少。公式：`召回率 = 检索到的相关关键词数 / 期望关键词总数`。例如期望关键词有 ["暴力", "恐怖", "报错"] 共 3 个，检索回来的上下文里只出现了 "报错"，召回率 = 1/3 ≈ 33.3%。

相关引用：`core/rag_evaluator.py` `run_single_test()` 方法中的 recall 计算逻辑。

---

### 苏格拉底问答总结：RAG 检索参数深度讨论

围绕对比实验结果（三组实验 × 11 个配置），逐层追问 RAG 核心参数的含义与相互作用关系。

**1. rerank_top_n 从 3 提升到 5 为什么会提高准确率？**
rerank_top_n=5 给了 LLM 更多高质量的相关片段，覆盖正确答案的概率增大，准确率上升、幻觉率下降。

**2. 为什么 C4 (k=8, rerank=5) 幻觉率反而比 C3 (k=5, rerank=5) 更差？**
k=8 多出来的 3 条初检候选进入了重排序，虽然 rerank 后仍然只取前 5 条给 LLM，但多出来的候选可能是噪音（字面命中但语义垃圾），它们在重排序时分数不稳定，可能挤掉原本 k=5 时能排进前 5 的好文档。

**3. BGE-Reranker vs BM25 的根本区别和各自弱点**
- BM25：基于字面匹配 + 关键词稀缺度打分，完全不看语义。"苹果手机"和"iPhone"对它无关。
- BGE-Reranker (CrossEncoder)：把 query 和 doc 同时喂进 BERT，输出语义相关性分数，能理解同义词和换说法。
- Reranker 的弱点：面对"字面全命中、语义零相关"的文档时排序不稳定，k 过大时噪声暴增会削弱其效果。

**4. 为什么不能把 k 设得巨大（如 50）？**
k 增大意味着重排序计算量线性增长（CrossEncoder 每对都需推理）。更致命的是，k 越大，语义垃圾文档被捞进来的概率越高，Reranker 无法稳定区分它们，排序质量下降。

**5. 解决方案：重排序前加一层过滤**
在 Reranker 之前用 MMR（Maximal Marginal Relevance）去噪，选取"相关但不是已选内容的简单重复"的文档。代码中向量检索阶段已在使用 MMR（`lambda_mult=0.7`）。

**6. rerank_top_n 的决定依据**
应综合考虑：Reranker 质量、文档总块数、chunk_size（每块信息量）、LLM 上下文处理能力。小文档上总块数影响不明显（A 组三个 chunk_size 结果完全一样），大文档上 chunk_size 会产生显著差异。

**7. 召回率公式和直观理解**
`召回率 = 检索到的相关关键词数 / 期望关键词总数`，k=3 时有一条用例 recall=0，因为初检回来的文档里恰好没包含任何期望关键词。
