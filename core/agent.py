from langchain_community.llms import Ollama
from langchain.memory import ConversationBufferMemory
from core.config import LLM_MODEL
from core.tools import SEC_AGENT_TOOLS
from core.rag import init_rag_retriever, rag_query
from security.permission import check_tool_permission, DEFAULT_ROLE, get_allowed_tools
from security.input_check import check_malicious_input
from security.output_filter import mask_sensitive_info, check_output_compliance
from security.audit_log import write_audit_log

# 1. 初始化大模型
llm = Ollama(model=LLM_MODEL, temperature=0.05)

# 2. 全局对话记忆（命令行用）
memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True
)

# 3. 工具映射字典
TOOL_MAP = {tool.name: tool for tool in SEC_AGENT_TOOLS}

# 4. 命令行默认retriever
default_retriever = init_rag_retriever()

# 5. 终版Agent核心逻辑（RAG直接集成，彻底解决问题）
def agent_invoke(
    user_input: str,
    role: str = DEFAULT_ROLE,
    custom_memory=None,
    custom_retriever=None,
    user_id: str = "default"
) -> str:
    # 记忆处理
    use_memory = custom_memory if custom_memory else memory
    # 检索器处理：优先用会话级retriever，没有则用默认全局retriever
    use_retriever = custom_retriever if custom_retriever else default_retriever
    # 获取当前角色允许的工具列表
    allowed_tools = get_allowed_tools(role)
    
    # 第一步：输入安全检测+审计
    is_risk, risk_msg = check_malicious_input(user_input)
    if is_risk:
        write_audit_log(
            user_id=user_id, role=role, operation="安全拦截",
            input_content=user_input, result=risk_msg, risk_level="high"
        )
        return risk_msg
    
    # 第二步：精准意图识别
    user_input_lower = user_input.lower()
    tool_result = ""
    operation_type = "对话"
    
    # ---------------------- 核心修复：RAG知识库问答直接处理，不走工具调用 ----------------------
    if any(keyword in user_input_lower for keyword in ["pdf", "文档", "资料", "写了什么", "内容是什么", "文档里"]):
        # 直接调用RAG检索，彻底避开工具参数传递问题
        rag_content = rag_query(use_retriever, user_input)
        tool_result = rag_content
        operation_type = "RAG知识库问答"
    
    # ---------------------- 其他安全工具正常调用 ----------------------
    # 1. SQL注入检测意图
    elif any(keyword in user_input_lower for keyword in ["sql注入", "注入检测", "sql检测", "注入风险", "sql漏洞"]):
        tool_to_call = "check_sql_injection"
        # 权限校验
        has_permission, permission_msg = check_tool_permission(tool_to_call, role)
        if not has_permission:
            write_audit_log(
                user_id=user_id, role=role, operation="权限拒绝",
                input_content=user_input, result=permission_msg, risk_level="low"
            )
            return permission_msg
        # 调用工具
        try:
            tool_result = TOOL_MAP[tool_to_call].invoke({"content": user_input})
            operation_type = "工具调用"
        except Exception as e:
            tool_result = f"工具调用出错：{str(e)}"
    
    # 2. 漏洞扫描意图
    elif any(keyword in user_input_lower for keyword in ["扫描漏洞", "网站扫描", "url扫描", "漏洞检测", "web扫描"]):
        tool_to_call = "simple_vuln_scan"
        # 权限校验
        has_permission, permission_msg = check_tool_permission(tool_to_call, role)
        if not has_permission:
            write_audit_log(
                user_id=user_id, role=role, operation="权限拒绝",
                input_content=user_input, result=permission_msg, risk_level="low"
            )
            return permission_msg
        # 提取URL
        import re
        url_match = re.search(r"https?://[^\s]+", user_input)
        if not url_match:
            result = "请提供以 http:// 或 https:// 开头的完整URL"
            write_audit_log(
                user_id=user_id, role=role, operation="对话",
                input_content=user_input, result=result, risk_level="normal"
            )
            return result
        # 调用工具
        try:
            tool_result = TOOL_MAP[tool_to_call].invoke({"url": url_match.group()})
            operation_type = "工具调用"
        except Exception as e:
            tool_result = f"工具调用出错：{str(e)}"
    
    # 3. 敏感信息检测意图
    elif any(keyword in user_input_lower for keyword in ["检测敏感", "检测隐私", "手机号检测", "身份证检测", "敏感信息", "隐私信息"]):
        # 判断是检测文本还是PDF
        if any(keyword in user_input_lower for keyword in ["pdf", "文档", "上传的文件"]):
            # 网页端：直接用会话级retriever处理
            all_docs = use_retriever.invoke("")
            full_text = "\n".join([doc.page_content for doc in all_docs])
            from security.output_filter import detect_sensitive_info
            has_risk, result = detect_sensitive_info(full_text)
            tool_result = result
            operation_type = "PDF敏感信息检测"
        else:
            # 检测文本敏感信息
            tool_to_call = "check_sensitive_information"
            # 权限校验
            has_permission, permission_msg = check_tool_permission(tool_to_call, role)
            if not has_permission:
                write_audit_log(
                    user_id=user_id, role=role, operation="权限拒绝",
                    input_content=user_input, result=permission_msg, risk_level="low"
                )
                return permission_msg
            # 调用工具
            try:
                tool_result = TOOL_MAP[tool_to_call].invoke({"text": user_input})
                operation_type = "工具调用"
            except Exception as e:
                tool_result = f"工具调用出错：{str(e)}"
    
    # ---------------------- 大模型生成最终回答 ----------------------
    if tool_result:
        prompt = f"""
你是专业的AI安全智能助手，根据以下内容，整理成简洁、专业的最终回答。
禁止编造内容外的任何信息，禁止添加无关信息，禁止输出高危操作代码。

参考内容：
{tool_result}

用户问题：{user_input}
"""
    else:
        prompt = f"""
你是专业的AI安全智能助手，仅回答与网络安全、信息安全、数据合规相关的问题。
无关问题请礼貌拒绝，禁止编造内容，禁止输出高危操作代码。

用户问题：{user_input}
"""
    
    final_answer = llm.invoke(prompt)
    
    # 输出合规校验+脱敏
    is_compliance, compliance_msg = check_output_compliance(final_answer)
    if not is_compliance:
        write_audit_log(
            user_id=user_id, role=role, operation="输出拦截",
            input_content=user_input, result=compliance_msg, risk_level="high"
        )
        return compliance_msg
    
    final_answer = mask_sensitive_info(final_answer)
    
    # 保存记忆+审计
    use_memory.save_context({"input": user_input}, {"output": final_answer})
    write_audit_log(
        user_id=user_id, role=role, operation=operation_type,
        input_content=user_input, result=final_answer, risk_level="normal"
    )
    
    return final_answer