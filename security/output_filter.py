import re

# 敏感信息正则规则（修复版：所有分组改为非捕获组）
SENSITIVE_PATTERNS = {
    "手机号": r"1[3-9]\d{9}",
    "身份证号": r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
    "银行卡号": r"\d{16,19}",
    "邮箱": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "API密钥/Token": r"(?:sk-|api_key|token|secret|key)[\w-]{16,}",
    "内网IP": r"(?:192\.168|10|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}"
}


def detect_sensitive_info(text: str) -> tuple[bool, str]:
    """
    检测文本中的敏感信息
    返回：(是否包含敏感信息, 检测结果详情)
    """
    result = []
    for name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            # 去重+脱敏
            unique_matches = list(set(matches))
            masked_matches = []
            for match in unique_matches:
                # 确保match是字符串
                match_str = str(match)
                if len(match_str) > 7:
                    masked = match_str[:3] + "****" + match_str[-4:]
                else:
                    masked = "****"
                masked_matches.append(masked)
            result.append(f"检测到【{name}】：{', '.join(masked_matches)}")
    
    if not result:
        return False, "未检测到敏感信息"
    
    return True, "\n".join(result)


def mask_sensitive_info(text: str) -> str:
    """
    脱敏文本中的敏感信息，替换为****
    """
    for name, pattern in SENSITIVE_PATTERNS.items():
        text = re.sub(pattern, lambda m: (m.group()[:3] + "****" + m.group()[-4:]) if len(m.group()) > 7 else "****", text)
    return text