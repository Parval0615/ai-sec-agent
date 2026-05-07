"""审计日志模块 — 哈希链防篡改 + JSON结构化。

v2 (Phase 4.3): 每条日志包含上一条的 SHA256 哈希，形成哈希链。
修改任意一条日志后，校验函数能精确检测到被篡改的条目。

格式:
  JSONL (每行一个JSON对象):
  {"ts":"...","user":"...","role":"...","op":"...","risk":"...","input":"...","result":"...","idx":N,"prev":"sha256","hash":"sha256"}

向后兼容: write_audit_log() 签名不变，内部升级为结构化写入。
"""

import os
import json
import hashlib
from datetime import datetime

LOG_FILE = "logs/audit.log"
GENESIS_HASH = "GENESIS_AUDIT_LOG_CHAIN_V2"


def _ensure_dir():
    if not os.path.exists("logs"):
        os.makedirs("logs")


def _get_last_entry() -> dict | None:
    """Read the last JSON entry from the log file (for hash chaining)."""
    _ensure_dir()
    if not os.path.exists(LOG_FILE):
        return None
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        # Read backwards to find last valid JSON line
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            # Skip legacy pipe-delimited lines
    except Exception:
        pass
    return None


def write_audit_log(
    user_id: str = "default",
    role: str = "user",
    operation: str = "",
    input_content: str = "",
    result: str = "",
    risk_level: str = "normal",
):
    """写入审计日志（JSON结构化 + 哈希链）。

    签名与旧版完全兼容，内部升级为结构化JSON行格式。
    """
    _ensure_dir()

    prev = _get_last_entry()
    prev_hash = prev["hash"] if prev else GENESIS_HASH
    next_idx = (prev["idx"] + 1) if prev else 0

    # Build entry (without hash first — hash covers all other fields)
    entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user_id,
        "role": role,
        "op": operation,
        "risk": risk_level,
        "input": input_content[:200],
        "result": result[:200],
        "idx": next_idx,
        "prev": prev_hash,
    }

    # Compute hash: SHA256(all_fields_except_hash + "|" + prev_hash)
    payload = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "|" + prev_hash
    entry["hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def verify_audit_integrity() -> dict:
    """验证审计日志哈希链完整性。

    重新计算每条日志的哈希，检测是否被篡改。

    Returns:
        dict with:
        - valid: bool — 整体是否完整
        - total_entries: int — JSON条目总数
        - tampered_at: list[int] — 被篡改的条目索引
        - first_tampered: int | None — 第一个被篡改条目的索引
        - details: list[str] — 详细信息
    """
    _ensure_dir()
    if not os.path.exists(LOG_FILE):
        return {"valid": True, "total_entries": 0, "tampered_at": [], "first_tampered": None, "details": ["日志文件不存在（空链视为有效）"]}

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = []
    skipped_legacy = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                skipped_legacy += 1
        else:
            skipped_legacy += 1  # Legacy pipe-delimited lines — skipped

    if not entries:
        return {
            "valid": True,
            "total_entries": 0,
            "tampered_at": [],
            "first_tampered": None,
            "details": [f"无JSON格式条目（跳过 {skipped_legacy} 条旧版日志）"],
        }

    tampered = []
    expected_prev = GENESIS_HASH

    for entry in sorted(entries, key=lambda e: e.get("idx", 0)):
        idx = entry.get("idx", -1)
        stored_hash = entry.get("hash", "")
        stored_prev = entry.get("prev", "")

        # Check prev hash chain link
        if stored_prev != expected_prev:
            tampered.append(idx)
            expected_prev = stored_hash if stored_hash else expected_prev
            continue

        # Recompute hash
        entry_without_hash = {k: v for k, v in entry.items() if k != "hash"}
        payload = json.dumps(entry_without_hash, ensure_ascii=False, sort_keys=True) + "|" + stored_prev
        computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            tampered.append(idx)

        # Update expected_prev for next entry (use stored hash even if tampered —
        # this ensures we detect the FIRST tampered entry precisely)
        expected_prev = stored_hash if stored_hash else expected_prev

    details = []
    if tampered:
        for t_idx in tampered:
            details.append(f"条目 #{t_idx} 被篡改：哈希不匹配")
        details.append(f"共 {len(tampered)} 条日志被篡改，跳过 {skipped_legacy} 条旧版日志")
    else:
        details.append(f"哈希链完整，共 {len(entries)} 条日志，跳过 {skipped_legacy} 条旧版日志")

    return {
        "valid": len(tampered) == 0,
        "total_entries": len(entries),
        "tampered_at": tampered,
        "first_tampered": tampered[0] if tampered else None,
        "details": details,
    }


def read_audit_log(line_count: int = 20) -> str:
    """读取最新的审计日志（JSON格式 → 人类可读文本）。"""
    _ensure_dir()
    if not os.path.exists(LOG_FILE):
        return "暂无审计日志"

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    result_lines = []
    for line in lines[-line_count:]:
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                entry = json.loads(line)
                result_lines.append(
                    f"{entry.get('ts', '?')} | {entry.get('user', '?')} | "
                    f"{entry.get('role', '?')} | {entry.get('op', '?')} | "
                    f"{entry.get('risk', '?')} | {entry.get('input', '')[:50]} | "
                    f"{entry.get('result', '')[:80]}"
                )
            except json.JSONDecodeError:
                result_lines.append(line[:150])
        else:
            result_lines.append(line[:150])

    return "\n".join(result_lines) if result_lines else "暂无审计日志"


def read_audit_log_json(line_count: int = 20) -> list[dict]:
    """读取最新的审计日志（原始JSON格式，用于程序解析）。"""
    _ensure_dir()
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                entries.append(json.loads(line))
                if len(entries) >= line_count:
                    break
            except json.JSONDecodeError:
                continue

    return list(reversed(entries))
