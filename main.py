from core.agent import agent_executor, memory
from security.input_check import check_malicious_input

if __name__ == "__main__":
    print("=" * 50)
    print("AI Security Agent 已启动 | 已开启安全防护+对话记忆")
    print("输入 'q' 退出对话 | 输入 'clear' 清空对话记忆")
    print("=" * 50)

    while True:
        user_input = input("\n请输入问题：")
        user_input = user_input.strip()

        # 退出指令
        if user_input.lower() == "q":
            print("程序已退出")
            break
        
        # 清空记忆指令
        if user_input.lower() == "clear":
            memory.clear()
            print("✅ 对话记忆已清空")
            continue

        # 第一步：安全检测，恶意输入直接拦截
        is_risk, risk_msg = check_malicious_input(user_input)
        if is_risk:
            print(f"\n【安全拦截】：{risk_msg}")
            continue

        # 第二步：正常输入传入Agent处理
        try:
            result = agent_executor.invoke({"input": user_input})
            print("\n【Agent回答】：", result["output"])
        except Exception as e:
            print("\n【错误】：", str(e))