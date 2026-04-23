import streamlit as st
from core.agent import agent_executor, memory
from security.input_check import check_malicious_input

# 页面配置
st.set_page_config(
    page_title="AI安全智能助手",
    page_icon="🔒",
    layout="wide"
)

# 页面标题
st.title("🔒 AI安全智能助手")
st.caption("Agent + RAG + 全链路安全防护 | 基于LangChain构建")

# 初始化会话状态（解决刷新页面记忆丢失问题）
if "messages" not in st.session_state:
    st.session_state.messages = []
if "memory_cleared" not in st.session_state:
    st.session_state.memory_cleared = False

# 清空对话记忆按钮
with st.sidebar:
    st.header("操作面板")
    if st.button("清空对话记忆", type="primary", use_container_width=True):
        memory.clear()
        st.session_state.messages = []
        st.session_state.memory_cleared = True
        st.success("✅ 对话记忆已清空")
    
    st.divider()
    st.subheader("功能说明")
    st.markdown("""
    - ✅ 知识库PDF问答
    - ✅ 多轮对话记忆
    - ✅ Prompt注入拦截
    - ✅ 敏感信息检测
    - ✅ 越狱攻击防护
    """)

# 渲染历史对话
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# 用户输入框
user_input = st.chat_input("请输入你的问题...")

# 处理用户输入
if user_input:
    # 重置清空标记
    st.session_state.memory_cleared = False
    
    # 添加用户消息到历史
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # 第一步：安全检测，恶意输入直接拦截
    is_risk, risk_msg = check_malicious_input(user_input)
    if is_risk:
        with st.chat_message("assistant"):
            st.error(risk_msg)
        st.session_state.messages.append({"role": "assistant", "content": f"❌ {risk_msg}"})
    
    # 第二步：正常输入传入Agent处理
    else:
        with st.chat_message("assistant"):
            with st.status("Agent思考中...", expanded=True) as status:
                try:
                    # 调用Agent
                    result = agent_executor.invoke({"input": user_input})
                    answer = result["output"]
                    
                    # 更新状态
                    status.update(label="✅ 回答完成", state="complete", expanded=False)
                    st.markdown(answer)

                except Exception as e:
                    status.update(label="❌ 处理失败", state="error", expanded=False)
                    answer = f"处理请求时出错：{str(e)}"
                    st.error(answer)
        
        # 添加助手消息到历史
        st.session_state.messages.append({"role": "assistant", "content": answer})