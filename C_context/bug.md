# Bug 记录

## 2026-04-30

### BUG-003: 不同实验配置共用 Chroma collection 导致索引污染
**原因**: `init_rag_retriever()` 的 collection_name 只取了 PDF 文件名前缀 (`pdf_basename`)，不同 chunk_size/chunk_overlap 的配置共用一个 collection。即使 `force_reindex=True` 删除重建，由于 Chroma 持久化 key 相同，多个配置先后运行时后者覆盖前者，但索引内容因 embedding 相同而召回率无差异。
**修复**: collection_name 编码 `chunk_size` 和 `chunk_overlap` (`{basename}_cs{size}_co{overlap}`)，确保不同配置使用独立索引。
**影响范围**: `core/rag.py` init_rag_retriever() 行 194-197

### BUG-002: B 组评测 monkey-patch 不生效
**原因**: `run_comparison.py` 通过 `rag_mod.rag_query = custom_func` 覆盖函数，但 `agent.py` 使用 `from core.rag import rag_query` 模块级导入。Python 的模块级 import 会创建本地引用副本，修改 `rag_mod.rag_query` 不会更新 `agent.py` 中的引用。因此 `agent_invoke` 内部仍调用原始 `rag_query`，B1/B2 策略从未真正生效。
**修复**: 移除 monkey-patch，在 `rag_query` 中新增 `strategy` 字段支持 (`"vector_only"` / `"bm25_only"` / 默认 hybrid)。`run_comparison.py` 改为设置 `retriever["strategy"]` 传递策略。
**影响范围**: `core/rag.py` rag_query(), `rag_evaluation/run_comparison.py` run_experiment_b()

### BUG-001: langchain 1.x 不兼容 — 多个依赖缺失
**原因**:
1. `langchain-community` 未安装 → 所有 RAG 组件 (BM25Retriever, Chroma, PyMuPDFLoader, HuggingFaceEmbeddings) 无法加载
2. `rank_bm25` 未安装 → BM25Retriever.from_documents() 内部依赖，且报错后 `_default_retriever` 初始化失败，阻塞所有请求（包括非 RAG 的 SQL 注入检测、敏感信息检测）
3. `ConversationBufferMemory` 在 langchain 1.2.x 中被移除，`agent.py` 和 `app.py` 仍从 `langchain.memory` 导入
4. emoji 字符 (✅❌⚠️📚🔄→等) 在 Windows GBK 终端/日志写入时抛出 `UnicodeEncodeError`
5. `requirements.txt` 缺少 `langchain-openai` 和 `rank_bm25`
**修复**:
1. `pip install langchain-community rank_bm25` (chromadb, pymupdf, sentence-transformers 也一并安装)
2. 在 `agent.py` 中手写最小 `ConversationBufferMemory` 替代类，`app.py` 改从 `core.agent` 导入
3. `_get_default_retriever()` 加 try-except + 失败标记，RAG 初始化失败不阻塞其他工具
4. 所有 emoji 替换为 ASCII 等价文本 (`[!]`, `[OK]`, `[X]`, `[*]`, `->`, `--`)
5. 补充 `requirements.txt`
**影响范围**: `core/agent.py`, `app.py`, `core/tools.py`, `core/rag.py`, `security/input_check.py`, `security/output_filter.py`, `security/permission.py`, `main.py`, `requirements.txt`
