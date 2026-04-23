from langchain_core.tools import tool
from core.rag import init_rag_retriever, rag_query
from security.output_filter import detect_sensitive_info

# 初始化全局检索器（启动时加载一次）
retriever = init_rag_retriever()


@tool
def search_knowledge_base(query: str) -> str:
    """
    用于查询已加载的PDF文档内容，只要用户问文档里的内容、页面上写了什么、PDF相关的问题，必须调用这个工具
    """
    return rag_query(retriever, query)


@tool
def check_sensitive_information(text: str) -> str:
    """
    用于检测文本中的敏感信息，包括手机号、身份证号、银行卡号、API密钥、内网IP等
    只要用户要求检测敏感信息、识别隐私内容，必须调用这个工具
    """
    has_risk, result = detect_sensitive_info(text)
    return result


# 工具列表（后续新增安全工具直接往这里加）
SEC_AGENT_TOOLS = [search_knowledge_base, check_sensitive_information]