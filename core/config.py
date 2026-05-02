# 模型配置
EMBEDDING_MODEL = "BAAI/bge-small-zh-v1.5"
LLM_MODEL = "Qwen/Qwen3.5-35B-A3B"

# ModelScope API (OpenAI 兼容)
LLM_API_BASE = "https://api-inference.modelscope.cn/v1"
LLM_API_KEY = "ms-598b7f06-048b-4e3c-87c3-d68b986f2b63"

# RAG
CHUNK_SIZE = 800
CHUNK_OVERLAP = 150
TOP_K = 5
# RAG重排序配置
RERANK_TOP_N = 3