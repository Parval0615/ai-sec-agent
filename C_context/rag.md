# RAG 模块深度解析

## 架构总览

```
PDF文件
  │
  ▼
┌──────────────────────────────────────────────────────┐
│ 1. 文档加载 (Document Loading)                        │
│    PyMuPDFLoader → Document[] (按页)                  │
│    每页注入 file_name, page 元数据                     │
└──────────────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────────────┐
│ 2. 文本分块 (Text Splitting)                          │
│    RecursiveCharacterTextSplitter                     │
│    分隔符: \n\n\n → \n\n → \n → 。→ ！→ ？→ ；→ ，    │
│    可配置: chunk_size, chunk_overlap                   │
└──────────────────────────────────────────────────────┘
  │
  ├──────────────────┬──────────────────┐
  ▼                  ▼                  │
┌──────────┐  ┌──────────────┐          │
│ 向量索引  │  │ BM25 索引     │          │
│ Chroma   │  │ BM25Retriever│          │
│ MMR检索   │  │ 关键词匹配    │          │
└──────────┘  └──────────────┘          │
  │                  │                  │
  └──────────┬───────┘                  │
             ▼                          │
┌──────────────────────────────────────┐│
│ 3. 多路召回融合 (RRF)                  ││
│    score = Σ 1/(k + rank + 1)        ││
│    k=60 (平滑参数)                    ││
└──────────────────────────────────────┘│
             │                          │
             ▼                          │
┌──────────────────────────────────────┐│
│ 4. 重排序 (BGE-Reranker) ──可选       ││
│    Cross-Encoder 精排                 ││
│    过滤 BM25 噪声，提升语义相关性       ││
└──────────────────────────────────────┘│
             │                          │
             ▼                          │
┌──────────────────────────────────────┐│
│ 5. 上下文窗口构建                     ││
│    max_chars=2048 预算内填入文档片段   ││
│    拼接 _extract_categories_hint 预处理││
└──────────────────────────────────────┘│
             │                          │
             ▼                          │<── splits (原始文档)
┌──────────────────────────────────────┐
│ 6. LLM 生成                           │
│    Prompt = 检索上下文 + 用户问题       │
│    → fact_check (幻觉校验)             │
│    → 引用溯源 (页码/文件名)            │
└──────────────────────────────────────┘
```

## 模块详解

### 1. 文档加载 (`core/rag.py:init_rag_retriever`)

**选用 PyMuPDF 而非 PyPDF**：
- PyPDF 对 CJK 文本的 font encoding 处理有缺陷，部分字符会变成乱码
- PyMuPDF (fitz) 直接读取 PDF 的 CMap 表，CJK 提取准确率 >97%
- 我们的 PDF 解析器对比脚本（`rag_evaluation/pdf_parser_comparison.py`）量化验证了这一结论

**延迟加载设计**：
```python
_default_retriever = None
_retriever_init_failed = False

def _get_default_retriever():
    # 首次调用才加载 embedding 模型 + 建索引
    # 失败后标记，不再重试，非 RAG 工具不受影响
```

### 2. 文本分块

**RecursiveCharacterTextSplitter** 的分隔符是逐级降级的：

```
\n\n\n  → 段落间空行优先断开
  \n\n  → 段落内换行
    \n  → 单行换行
    。！？；， → 中文标点
      空格
        无分隔符 (强制截断)
```

**chunk_size 对效果的影响（实验验证）**：
- 小模型(qwen2:7b)：chunk=400 最优 (30%)，大块会因上下文噪声降低精度
- 大模型(Qwen3.5-35B)：chunk=1200 最优 (65%)，大模型能处理更丰富上下文

### 3. 向量检索 (Chroma + MMR)

**为什么选 Chroma 而非 FAISS**：
- FAISS 是纯内存索引，进程重启后丢失
- Chroma 基于 SQLite 持久化，重启后直接加载
- Chroma 支持 collection_name 级别的多租户隔离

**MMR (Maximal Marginal Relevance) 参数**：
```python
search_kwargs={
    "k": vec_top_k,         # 最终返回文档数
    "fetch_k": vec_top_k*3, # 候选池大小 (3倍过采样)
    "lambda_mult": 0.7      # 相关性多样性平衡 (0=最大多样性, 1=最大相关性)
}
```

### 4. BM25 检索

**BM25 原理**：TF-IDF 的改进版，考虑了词频饱和度和文档长度归一化。

```
BM25(D, Q) = Σ IDF(qi) × (f(qi,D) × (k1+1)) / (f(qi,D) + k1×(1-b+b×|D|/avgdl))
```

**在中文场景的局限性（实验验证）**：
- 中文无天然空格分词，BM25 的 tokenization 依赖字符级切分
- 向量检索准确率 68% vs BM25 仅 38%
- 但 BM25 在精确 ID/代码/API名查询上有不可替代的优势

### 5. RRF 融合 (Reciprocal Rank Fusion)

```python
# k=60 是学术界标准参数
score(doc) = Σ 1 / (60 + rank_in_each_list + 1)
```

**为什么 RRF 优于简单的分数归一化**：
- 不需要知道每条路径的原始分数分布
- 对排名变化鲁棒——单条路径的异常高分不会主导最终排序
- 同时被两条路径排在前面的文档自动获得最高分

### 6. BGE-Reranker (Cross-Encoder)

**Cross-Encoder vs Bi-Encoder (Embedding模型)**：

| | Bi-Encoder (bge-small-zh) | Cross-Encoder (bge-reranker) |
|---|---|---|
| 编码方式 | query 和 doc 独立编码 | query+doc 拼接后联合编码 |
| 速度 | 快 (向量已算好) | 慢 (每次都要重新编码) |
| 精度 | 中等 | 高 (全注意力交互) |
| 用途 | 召回 (从海量文档中筛选) | 精排 (对候选列表重新打分) |

**实验验证**：Reranker 是单因子最大贡献者——C4 配置从 50.4% 提升到 80.0% (+29.6pp)。

### 7. 上下文窗口构建 (`build_context_window`)

- 预算 max_chars=2048，逐文档填入直到预算耗尽
- 优先填入 Reranker 排在前面的文档
- 每个文档块标注 `[ID] 【文件名 第N页】` 用于溯源
- 额外拼接 `_extract_categories_hint`——从文档中自动提取的分类/类型值

### 8. 文档结构预分析 (`generate_document_guide` + `_extract_categories_hint`)

**`_extract_categories_hint`**（纯启发式，不调 LLM）：
- 从每行末尾提取 2-4 字的 CJK 短语
- 统计出现频次 ≥2 的作为候选分类值
- 同时提取重复出现的短词作为状态值/列名

**`generate_document_guide`**（调 LLM，有缓存）：
- 取前 3 个文档片段(≤1500字) 发给 LLM 提取结构化信息
- 结果缓存在 `_doc_guide_cache` 中，同一文档只调一次

### 9. 幻觉校验 (`fact_check`)

```
提取答案中的 2/3/4-gram → 检查在检索上下文中是否存在 → 
匹配率 < min_phrase_match_ratio(0.05) → 判定为幻觉 → 返回 fallback
```

**设计权衡**：阈值极低(0.05)避免误杀，只拦截答案与上下文完全脱钩的极端情况。

### 10. 引用溯源

```
📚 引用来源：
[1] large_test.pdf 第1页
[2] large_test.pdf 第3页
```

每个 source_doc 包含：id、file_name、page、content 摘要。页码从 PyMuPDFLoader 的 metadata 获取。

### 11. strategy 字段 — 检索策略可插拔

```python
retriever["strategy"] = "vector_only"  # 仅向量
retriever["strategy"] = "bm25_only"    # 仅BM25
# 不设置或 None → 默认 Hybrid RRF
```

替代了之前的 monkey-patch 方案（monkey-patch 在 Python 的 `from X import Y` 语义下无法生效）。

---

## 遇到的问题与解决方案

### 问题 1: Monkey-Patch 不生效

**现象**：B 组实验中 B1/B2 策略结果与默认配置完全相同（准确率均为 26.1%）

**根因**：
```python
# agent.py 中的导入
from core.rag import rag_query   # 创建本地引用副本

# run_comparison.py 中的 patch
import core.rag as rag_mod
rag_mod.rag_query = custom_func  # 只改了模块属性，agent.py 的本地引用不受影响
```

**解决**：在 `rag_query()` 中增加 `strategy` 字段判断，通过 retriever dict 传递策略，agent_invoke 内部自动识别。

### 问题 2: Chroma 索引污染

**现象**：不同 chunk_size 的实验配置召回率完全相同 (41.7%)

**根因**：collection_name 仅用 PDF 文件名，所有配置复用同一 Chroma 持久化索引

**解决**：`collection_name = f"{pdf_basename}_cs{chunk_size}_co{chunk_overlap}"`

### 问题 3: Reranker 模型无法加载

**现象**：`ENABLE_RERANK` 始终为 False，B4 和 B3 指标完全相同

**根因**：`RERANK_MODEL_LOCAL_PATH = "models/bge-reranker-base"` — 路径不存在；实际模型在 HF 缓存 (`~/.cache/huggingface/hub/models--BAAI--bge-reranker-base`)

**解决**：改为 `RERANK_MODEL_PATH = "BAAI/bge-reranker-base"`，让 CrossEncoder 直接从 HF 缓存加载

### 问题 4: 小模型幻觉率过高

**现象**：qwen2:7b 准确率 26-30%，幻觉率 72-78%

**根因**：7B 模型无法从结构化文本中准确提取信息，即使检索命中也输出"未找到相关信息"

**解决**：升级到 Qwen3.5-35B-A3B (ModelScope API)，准确率提升至 42-80%

### 问题 5: reportlab 生成 PDF 中文乱码

**现象**：PyMuPDF 从 reportlab 生成的 PDF 中提取中文全为乱码

**根因**：reportlab 默认不嵌入中文字体，PDF 中的 CJK 文本使用未注册的 CID 字体

**解决**：注册 SimHei/Deng/SimKai 字体后生成 PDF

### 问题 6: ConversationBufferMemory 被 langchain 1.x 移除

**现象**：`from langchain.memory import ConversationBufferMemory` 报 ImportError

**根因**：langchain 1.2.x 彻底移除了 `langchain.memory` 模块，记忆功能迁移到 LangGraph checkpoint 系统

**解决**：手写最小替代类（约 10 行），仅保留 `save_context` / `clear` 两个方法

### 问题 7: Windows GBK 编码导致 emoji 崩溃

**现象**：`write_audit_log` 写入审计日志时报 `UnicodeEncodeError`

**根因**：Python 在 Windows 上默认使用 GBK 编码打开文件，emoji 字符(⚠️✅❌📚)全部超出 GBK 码表

**解决**：全局替换为 ASCII 等价物 (`[!]` / `[OK]` / `[X]` / `[*]`)

### 问题 8: RAG 初始化失败阻塞非 RAG 工具

**现象**：BM25/Bloomberg 依赖缺失导致 `_get_default_retriever()` 抛异常，SQL 注入检测也全部无法使用

**根因**：`agent_invoke` 开头就调用 `_get_default_retriever()`，异常向上传播

**解决**：加 try-except + `_retriever_init_failed` 标记，失败后返回 None，非 RAG 路径继续工作

---

## 实验数据总结

### 模型对准确率的影响

| 模型 | A组平均准确率 | B组最高准确率 | 幻觉率 |
|------|:---:|:---:|:---:|
| qwen2:7b | 27% | 26% | 75-78% |
| Qwen3.5-35B | 56% | 77% | 45-55% |

### Reranker 对准确率的影响

| 配置 | 无 Rerank | 有 Rerank | Delta |
|------|:---:|:---:|:---:|
| Hybrid RRF (k=8) | 50% | **80%** | +30pp |
| Hybrid RRF (k=5) | 58% | 77% | +18pp |
| Vector-only | 68% | 67% | -1pp |

### 检索策略对比 (有 Reranker)

| 策略 | 准确率 | 适用场景 |
|------|:---:|------|
| Vector-only | 67% | 通用中文语义查询 |
| BM25-only | 38% | 精确 ID/代码匹配 |
| Hybrid+RRF+Rerank | **77%** | 生产推荐 |

---

## 关键配置参数

| 参数 | 默认值 | 推荐值 | 说明 |
|------|--------|--------|------|
| CHUNK_SIZE | 800 | 800-1200 | 大模型用大块 |
| CHUNK_OVERLAP | 150 | 150 | 块间重叠 |
| TOP_K | 5 | 8 | 候选池大小 |
| RERANK_TOP_N | 3 | 5 | Rerank 后保留数 |
| RRF k | 60 | 60 | 融合平滑参数 |
| MMR lambda_mult | 0.7 | 0.7 | 相关性/多样性平衡 |
| context max_chars | 2048 | 2048 | LLM 上下文预算 |
| fact_check threshold | 0.05 | 0.05 | 幻觉拦截阈值 |
