from langchain_core.prompts import PromptTemplate
from langchain_community.llms import Ollama
from langchain.agents import create_react_agent, AgentExecutor, Tool
from core.config import *
from core.rag import init_rag_retriever, rag_query

# 初始化 RAG
retriever = init_rag_retriever("docs/test.pdf")

# 知识库检索工具
def search_knowledge_base(query: str) -> str:
    return rag_query(retriever, query)

SEC_AGENT_TOOLS = [
    Tool(
        name="search_knowledge_base",
        func=search_knowledge_base,
        description="优先使用！从本地PDF文档检索信息"
    )
]

# ✅ 官方标准模板（必带 tool_names，100%不报错）
template = '''Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought: {agent_scratchpad}
'''

prompt = PromptTemplate(
    input_variables=["input", "tools", "tool_names", "agent_scratchpad"],
    template=template
)

# 模型
llm = Ollama(model=LLM_MODEL)

# 构建 Agent
agent = create_react_agent(llm, SEC_AGENT_TOOLS, prompt)
agent_executor = AgentExecutor(
    agent=agent,
    tools=SEC_AGENT_TOOLS,
    verbose=True,
    handle_parsing_errors=True
)