"""
LangGraph-based Agent — replaces the procedural agent_invoke() with a StateGraph.

Architecture:
  START -> guardrail -> agent <=> tools -> output_filter -> finalize -> END
"""

import contextvars
import operator
import os
import re
import sqlite3
from typing import Annotated, Optional, TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.sqlite import SqliteSaver

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage, ToolMessage
from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI

from core.config import LLM_MODEL, LLM_API_BASE, LLM_API_KEY
from core.tools import SEC_AGENT_TOOLS
from core.rag import rag_query
from security.permission import get_allowed_tools, DEFAULT_ROLE
from security.input_check import check_malicious_input
from security.output_filter import mask_sensitive_info
from security.audit_log import write_audit_log

# ContextVar lets the RAG tool access the session's retriever without
# putting non-serializable objects in LangGraph state.
_current_retriever: contextvars.ContextVar = contextvars.ContextVar('current_retriever', default=None)


@tool
def search_document(query: str) -> str:
    """Search the uploaded PDF document for information. Use when the user asks
    about document content, policies, rules, or specific topics in the uploaded file."""
    retriever = _current_retriever.get()
    if not retriever or not retriever.get("docs"):
        return "No document is currently loaded. Ask the user to upload a PDF first."

    context, source_docs = rag_query(retriever, query)
    if not source_docs or "未找到" in context:
        return "No relevant content found in the document for this query."

    result = context
    if source_docs:
        result += "\n\n---\n[*] Reference sources:\n"
        for doc in source_docs[:5]:
            result += f"[{doc['id']}] {doc['file_name']} page {doc['page']}\n"
    return result


# Global tool name -> function mapping (tool_node needs it independent of role filtering)
_ALL_TOOLS_BY_NAME = {t.name: t for t in SEC_AGENT_TOOLS}
_ALL_TOOLS_BY_NAME["search_document"] = search_document


llm = ChatOpenAI(
    model=LLM_MODEL,
    temperature=0.0,
    max_tokens=1024,
    openai_api_base=LLM_API_BASE,
    openai_api_key=LLM_API_KEY
)


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    user_role: str
    security_blocked: bool
    audit_entries: Annotated[list, operator.add]
    tool_call_count: int
    conversation_summary: str


RETRY_LIMIT = 3
MAX_TOOL_RESULT = 2000


def _summarize_tool_result(tool_name: str, full_content: str) -> str:
    """Summarize long tool output via LLM instead of blind truncation."""
    prompt = f"""Summarize this tool output concisely. Keep ALL specific data (numbers, URLs, IPs, names, findings, risk levels, file paths). Only remove redundancy. Output in Chinese, ~600 chars max.

Tool: {tool_name}
Output ({len(full_content)} chars):
{full_content[:4000]}

Concise summary:"""

    try:
        response = llm.invoke(prompt)
        return response.content.strip() if hasattr(response, 'content') else full_content[:MAX_TOOL_RESULT] + "..."
    except Exception:
        return full_content[:MAX_TOOL_RESULT] + f"\n...[truncated, {len(full_content)} chars total]"


def guardrail_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    user_input = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

    is_risk, risk_msg = check_malicious_input(user_input)
    if is_risk:
        return {
            "security_blocked": True,
            "messages": [AIMessage(content=risk_msg)],
            "audit_entries": [f"SEC_BLOCK | {state['user_role']} | {user_input[:80]}"]
        }
    return {"security_blocked": False}


def agent_node(state: AgentState) -> dict:
    role = state.get("user_role", DEFAULT_ROLE)
    retriever = _current_retriever.get()
    count = state.get("tool_call_count", 0)

    allowed_names = get_allowed_tools(role)
    available_tools = [t for t in SEC_AGENT_TOOLS if t.name in allowed_names]

    if retriever and retriever.get("docs") and "search_knowledge_base" in allowed_names:
        available_tools.append(search_document)

    role_labels = {
        "guest": "Guest (knowledge base only)",
        "user": "User (KB + sensitive info detection)",
        "admin": "Admin (all security tools)"
    }

    summary = state.get("conversation_summary", "")
    summary_block = f"[Prior conversation context]\n{summary}\n\n" if summary else ""

    tool_desc = ", ".join(t.name for t in available_tools) if available_tools else "none"
    system_prompt = f"""{summary_block}You are an AI security assistant. Answer in Chinese.

User role: {role_labels.get(role, role)}
Available tools: {tool_desc}
Tools used this turn: {count}/{RETRY_LIMIT}

Rules:
- Use tools when the user asks for scanning, detection, or document search
- When the user asks for MULTIPLE independent tasks at once (e.g. scan a URL AND check SQL injection), call all relevant tools simultaneously in one response
- If the user asks something unrelated to your tools, answer directly
- If a tool fails, try to fix the parameters and retry once. If it fails again, explain the issue to the user
- Be concise and professional"""

    full_messages = [SystemMessage(content=system_prompt)] + list(state["messages"])

    if count >= RETRY_LIMIT:
        response = llm.invoke(full_messages)
    else:
        model = llm.bind_tools(available_tools) if available_tools else llm
        response = model.invoke(full_messages)
    return {"messages": [response]}


def output_filter_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    answer = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

    # Minimal filter: as a security education tool, discussing attack techniques
    # in an educational context is expected. Only block actual executable payloads.
    import re as _re
    EXEC_PATTERNS = [
        r'xp_cmdshell', r'exec\s+master\.', r'execute\s+sp_',
        r'shell_exec\(', r'passthru\(', r'popen\(', r'system\(',
    ]
    blocked = any(_re.search(p, answer.lower()) for p in EXEC_PATTERNS)
    if blocked:
        return {
            "messages": [AIMessage(content="[!] 输出内容包含可执行高危代码，已拦截")],
            "audit_entries": ["OUT_BLOCK"]
        }

    masked = mask_sensitive_info(answer)
    if masked != answer:
        return {"messages": [AIMessage(content=masked)]}
    return {}


def finalize_node(state: AgentState, config: RunnableConfig) -> dict:
    user_id = config.get("configurable", {}).get("user_id", "default")
    role = state.get("user_role", DEFAULT_ROLE)
    messages = state["messages"]

    user_input = ""
    for m in messages:
        if isinstance(m, HumanMessage):
            user_input = m.content if hasattr(m, 'content') else str(m)

    final_answer = ""
    for m in reversed(messages):
        if isinstance(m, AIMessage) and not (hasattr(m, 'tool_calls') and m.tool_calls):
            final_answer = m.content if hasattr(m, 'content') else str(m)
            break

    has_tool = any(
        isinstance(m, AIMessage) and hasattr(m, 'tool_calls') and m.tool_calls
        for m in messages
    )
    op_type = "Agent工具调用" if has_tool else "对话"
    if any("search_document" in str(m) for m in messages):
        op_type = "RAG知识库问答"

    write_audit_log(user_id, role, op_type, user_input, final_answer, "normal")

    for entry in state.get("audit_entries", []):
        write_audit_log(user_id, role, "审计", entry[:200], "", "high" if "BLOCK" in entry else "low")

    return {}


def route_after_guardrail(state: AgentState) -> str:
    return "finalize" if state.get("security_blocked") else "agent"


def route_after_agent(state: AgentState) -> str:
    last_msg = state["messages"][-1]
    if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
        return "tools"
    return "output_filter"


def tool_node(state: AgentState) -> dict:
    messages = state["messages"]
    last_msg = messages[-1]
    if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
        return {}

    count = state.get("tool_call_count", 0)
    tool_messages = []

    for tc in last_msg.tool_calls:
        tool_name = tc["name"]
        tool_args = tc["args"]
        count += 1

        tool_fn = _ALL_TOOLS_BY_NAME.get(tool_name)
        if not tool_fn:
            tool_messages.append(ToolMessage(
                content=f"Tool '{tool_name}' not available.", tool_call_id=tc["id"]
            ))
            continue

        try:
            result = tool_fn.invoke(tool_args)
            content_str = str(result)
            if len(content_str) > MAX_TOOL_RESULT:
                content_str = _summarize_tool_result(tool_name, content_str)
            tool_messages.append(ToolMessage(content=content_str, tool_call_id=tc["id"]))
        except Exception as e:
            error_msg = f"[ERROR] {type(e).__name__}: {str(e)}. Try different parameters."
            tool_messages.append(ToolMessage(content=error_msg, tool_call_id=tc["id"]))

    return {"messages": tool_messages, "tool_call_count": count}


def _build_graph(checkpointer=None):
    builder = StateGraph(AgentState)

    builder.add_node("guardrail", guardrail_node)
    builder.add_node("agent", agent_node)
    builder.add_node("tools", tool_node)
    builder.add_node("output_filter", output_filter_node)
    builder.add_node("finalize", finalize_node)

    builder.add_edge(START, "guardrail")
    builder.add_conditional_edges("guardrail", route_after_guardrail, {
        "agent": "agent",
        "finalize": "finalize"
    })
    builder.add_conditional_edges("agent", route_after_agent, {
        "tools": "tools",
        "output_filter": "output_filter"
    })
    builder.add_edge("tools", "agent")
    builder.add_edge("output_filter", "finalize")
    builder.add_edge("finalize", END)

    return builder.compile(checkpointer=checkpointer)


_graph = None
_checkpointer = None


def _get_graph():
    global _graph, _checkpointer
    if _graph is None:
        os.makedirs("checkpoints", exist_ok=True)
        conn = sqlite3.connect("checkpoints/graph_state.db", check_same_thread=False)
        _checkpointer = SqliteSaver(conn)
        _graph = _build_graph(checkpointer=_checkpointer)
    return _graph


def clear_history(thread_id: str) -> bool:
    """Delete checkpoint state for a given thread_id."""
    global _checkpointer
    _get_graph()  # ensure initialized
    if _checkpointer is None:
        return False
    try:
        _checkpointer.delete_thread(thread_id)
        return True
    except Exception:
        return False


FORGET_PATTERN = re.compile(r"(?:忘掉|忘记|forget|删除.*(?:记录|记忆|对话))[：:\s]*(.+)", re.IGNORECASE)


def _generate_summary(messages: list) -> str:
    """Compress old conversation messages into a 2-3 sentence Chinese summary."""
    if not messages:
        return ""
    lines = []
    for m in messages:
        role = "用户" if isinstance(m, HumanMessage) else "助手"
        content = m.content if hasattr(m, 'content') else str(m)
        lines.append(f"[{role}]: {content[:300]}")
    text = "\n".join(lines)

    prompt = f"""Summarize the key context from this conversation in 2-3 Chinese sentences.
Focus on: who the user is, what they are working on, any important facts or decisions.
Do NOT re-execute or continue the conversation — only summarize the existing content.

Conversation:
{text}

Summary (2-3 sentences in Chinese):"""

    try:
        response = llm.invoke(prompt)
        return response.content.strip() if hasattr(response, 'content') else ""
    except Exception:
        return ""


def graph_invoke(
    user_input: str,
    role: str = DEFAULT_ROLE,
    retriever: Optional[dict] = None,
    user_id: str = "default",
    chat_history: Optional[list] = None,
    max_history: int = 20,
    thread_id: str = None,
) -> str:
    _current_retriever.set(retriever)
    graph = _get_graph()

    # When chat_history is provided (Streamlit), caller manages state.
    # Use a unique per-call thread_id to avoid merging with prior checkpoint.
    # When chat_history is None (CLI), rely entirely on checkpointer.
    has_caller_history = chat_history is not None
    if has_caller_history:
        history = list(chat_history)
        tid = f"{thread_id or user_id}_{hash(tuple())}"  # unique per call
        saved_summary = ""
        # Each call gets a fresh checkpoint ID to avoid message duplication
        import uuid
        tid = f"{thread_id or user_id}_{uuid.uuid4().hex[:8]}"
    else:
        history = []
        tid = thread_id or user_id
        saved = graph.get_state({"configurable": {"thread_id": tid}})
        if saved and saved.values:
            history = list(saved.values.get("messages", []))
            saved_summary = saved.values.get("conversation_summary", "")
        else:
            saved_summary = ""

    config = {"configurable": {"thread_id": tid, "user_id": user_id}}

    # Precise forgetting: user says "forget X" -> remove matching messages
    forget_match = FORGET_PATTERN.search(user_input)
    if forget_match:
        target = forget_match.group(1).strip()
        tokens = [t for t in re.split(r'[\s,，。]+', target) if len(t) >= 4]
        tokens.append(target)
        new_history = []
        for m in history:
            content = m.content if hasattr(m, 'content') else str(m)
            if any(t in content for t in tokens):
                continue
            new_history.append(m)
        removed = len(history) - len(new_history)
        if has_caller_history:
            chat_history.clear()
            chat_history.extend(new_history)
        return f"已遗忘 {removed} 条与「{target}」相关的对话记录。"

    # Summary generation: compress old messages when exceeding max_history
    summary = saved_summary
    if len(history) > max_history:
        old = history[:-max_history]
        history = history[-max_history:]
        summary = _generate_summary(old)
        if has_caller_history:
            chat_history.clear()
            chat_history.extend(history)

    # Build state messages:
    # - Caller-managed: pass full history + new msg (no checkpoint merge risk with unique tid)
    # - Checkpointer-managed: pass only new msg (add_messages appends to checkpoint)
    if has_caller_history:
        state_messages = history + [HumanMessage(content=user_input)]
    else:
        state_messages = [HumanMessage(content=user_input)]

    state = {
        "messages": state_messages,
        "user_role": role,
        "security_blocked": False,
        "audit_entries": [],
        "tool_call_count": 0,
        "conversation_summary": summary,
    }

    result = graph.invoke(state, config)

    result_messages = result["messages"]
    for m in reversed(result_messages):
        if isinstance(m, AIMessage) and not (hasattr(m, 'tool_calls') and m.tool_calls):
            return m.content

    return "Agent did not produce a response."
