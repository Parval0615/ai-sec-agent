from core.agent import agent_executor

if __name__ == "__main__":
    print("=" * 50)
    print("AI Security Agent 已启动")
    print("输入 'q' 退出对话")
    print("=" * 50)

    while True:
        user_input = input("\n请输入问题：")
        if user_input.strip().lower() == "q":
            print("程序已退出")
            break

        try:
            result = agent_executor.invoke({"input": user_input})
            print("\n【Agent回答】：", result["output"])
        except Exception as e:
            print("\n【错误】：", str(e))