# QA Log

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
