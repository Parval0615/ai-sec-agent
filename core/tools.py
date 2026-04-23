from langchain_core.tools import tool
from core.rag import init_rag_retriever, rag_query

# 初始化全局检索器（启动时加载一次）
retriever = init_rag_retriever()


@tool
def search_knowledge_base(query: str) -> str:
    """
    用于查询本地知识库PDF内容，仅当问题需要文档内信息时使用
    """
    return rag_query(retriever, query)


# 工具列表（后续新增安全工具直接往这里加）
SEC_AGENT_TOOLS = [search_knowledge_base]