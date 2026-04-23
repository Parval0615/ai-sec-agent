from langchain_core.tools import tool
from core.rag import init_rag_retriever, rag_query

# 初始化全局检索器（启动时加载一次）
retriever = init_rag_retriever()


@tool
def search_knowledge_base(query: str) -> str:
    """
    用于查询已加载的PDF文档内容，只要用户问文档里的内容、页面上写了什么、PDF相关的问题，必须调用这个工具
    """
    return rag_query(retriever, query)


# 工具列表（后续新增安全工具直接往这里加）
SEC_AGENT_TOOLS = [search_knowledge_base]