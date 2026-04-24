import os
from datetime import datetime

# 日志文件路径
LOG_FILE = "logs/audit.log"

# 初始化日志目录
def init_log_dir():
    if not os.path.exists("logs"):
        os.makedirs("logs")

# 写入审计日志
def write_audit_log(
    user_id: str = "default",
    role: str = "user",
    operation: str = "",
    input_content: str = "",
    result: str = "",
    risk_level: str = "normal"
):
    """
    写入操作审计日志
    :param user_id: 用户ID（多用户用）
    :param role: 用户角色
    :param operation: 操作类型（对话/工具调用/安全拦截/权限拒绝）
    :param input_content: 用户输入内容
    :param result: 操作结果
    :param risk_level: 风险等级（normal/low/high/critical）
    """
    init_log_dir()
    # 日志格式：时间 | 用户ID | 角色 | 操作类型 | 风险等级 | 输入 | 结果
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"{log_time} | {user_id} | {role} | {operation} | {risk_level} | {input_content[:50]} | {result[:100]}\n"
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

# 读取审计日志
def read_audit_log(line_count: int = 20) -> str:
    """读取最新的审计日志"""
    init_log_dir()
    if not os.path.exists(LOG_FILE):
        return "暂无审计日志"
    
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
        # 返回最新的N条
        latest_lines = lines[-line_count:] if len(lines) >= line_count else lines
        return "".join(latest_lines)