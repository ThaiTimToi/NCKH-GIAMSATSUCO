"""
agent_investigator.py
----------------------
AGENT 2: INVESTIGATOR AGENT (Điều tra & đối chiếu MITRE ATT&CK)

Nhiệm vụ:
- Nhận: log gốc (raw_log) + kết quả Triage (Agent 1) + (tuỳ chọn) danh sách
  các log liên quan khác (context_logs) để tìm chuỗi sự kiện (attack chain)
- Đối chiếu nội dung log với bộ luật security_rules/ (MITRE ATT&CK mapping)
- Tìm các sự kiện liên quan (cùng host/user/IP, xảy ra gần nhau về thời gian)
  để dựng lại "chuỗi tấn công" (attack chain) sơ bộ
- Trả về kết quả có cấu trúc để Agent 3 (Explainer) dịch sang ngôn ngữ tự nhiên

Framework: LangGraph (StateGraph) + LangChain (ChatModel wrapper, tuỳ chọn)

============================================================
GIẢ ĐỊNH VỀ CẤU TRÚC security_rules/ (MITRE ATT&CK mapping)
============================================================
File này giả định bạn (Security) sẽ cung cấp 1 file JSON tại:
    security_rules/mitre_rules.json
(đường dẫn có thể đổi qua biến môi trường SECURITY_RULES_PATH)

Với cấu trúc như sau (list các rule):
[
  {
    "rule_id": "R001",
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactic": "Execution",
    "keywords": ["powershell -enc", "invoke-expression", "iex ("],
    "description": "Phát hiện thực thi PowerShell được encode/obfuscate.",
    "severity_weight": 20
  },
  {
    "rule_id": "R002",
    "technique_id": "T1003",
    "technique_name": "OS Credential Dumping",
    "tactic": "Credential Access",
    "keywords": ["mimikatz", "lsass.exe dump", "sekurlsa"],
    "description": "Phát hiện hành vi dump credential từ bộ nhớ.",
    "severity_weight": 30
  }
]

NẾU cấu trúc thực tế của bạn khác đi (tên field khác, thêm field...),
chỉ cần sửa lại hàm `_normalize_rule()` bên dưới cho khớp - phần logic
đối chiếu (matching) và các node khác KHÔNG cần thay đổi.
Nếu chưa có file này, hệ thống sẽ tự dùng DEFAULT_RULES (rule mẫu tối
thiểu) để vẫn chạy được pipeline demo.
"""

from __future__ import annotations

import os
import json
from datetime import datetime
from typing import TypedDict, Optional, List, Dict, Any

from langgraph.graph import StateGraph, END


# =========================================================
# 1. ĐỊNH NGHĨA STATE CHO GRAPH
# =========================================================
class InvestigatorState(TypedDict, total=False):
    raw_log: Dict[str, Any]              # log gốc đang điều tra
    triage_result: Dict[str, Any]        # kết quả từ Agent 1 (severity, score...)
    context_logs: List[Dict[str, Any]]   # các log khác để tương quan (có thể rỗng)

    rules: List[Dict[str, Any]]          # rule MITRE đã load & chuẩn hoá
    matched_techniques: List[Dict[str, Any]]   # kỹ thuật MITRE khớp được
    attack_chain: List[Dict[str, Any]]         # chuỗi sự kiện liên quan, sắp theo thời gian
    correlation_reasoning: Optional[str]       # giải thích kỹ thuật (sẽ đưa cho Explainer)
    confidence: Optional[float]                # độ tin cậy tổng hợp (0-100)
    error: Optional[str]


# =========================================================
# 2. RULE MẶC ĐỊNH (dùng khi chưa có security_rules/mitre_rules.json)
# =========================================================
DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "R001",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "keywords": ["powershell -enc", "invoke-expression", "iex ("],
        "description": "Phát hiện thực thi PowerShell được encode/obfuscate.",
        "severity_weight": 20,
    },
    {
        "rule_id": "R002",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "keywords": ["mimikatz", "lsass.exe dump", "sekurlsa"],
        "description": "Phát hiện hành vi dump credential từ bộ nhớ (LSASS).",
        "severity_weight": 30,
    },
    {
        "rule_id": "R003",
        "technique_id": "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "keywords": ["psexec", "admin$", "wmic"],
        "description": "Phát hiện di chuyển ngang qua admin shares / PsExec / WMIC.",
        "severity_weight": 25,
    },
    {
        "rule_id": "R004",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "keywords": ["failed login", "multiple login attempts", "brute force"],
        "description": "Phát hiện nhiều lần đăng nhập thất bại liên tiếp.",
        "severity_weight": 15,
    },
]


def _normalize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Chuẩn hoá 1 rule đọc từ security_rules/mitre_rules.json về format thống nhất.
    SỬA HÀM NÀY nếu cấu trúc file rules thực tế của bạn khác với giả định ở trên
    (ví dụ tên field "technique" thay vì "technique_id", v.v.)
    """
    return {
        "rule_id": rule.get("rule_id", "UNKNOWN"),
        "technique_id": rule.get("technique_id", "UNKNOWN"),
        "technique_name": rule.get("technique_name", ""),
        "tactic": rule.get("tactic", ""),
        "keywords": [kw.lower() for kw in rule.get("keywords", [])],
        "description": rule.get("description", ""),
        "severity_weight": rule.get("severity_weight", 10),
    }


def _load_rules() -> List[Dict[str, Any]]:
    """
    Đọc file security_rules/mitre_rules.json (đường dẫn tuỳ chỉnh qua env
    SECURITY_RULES_PATH). Nếu không tìm thấy file hoặc lỗi parse -> fallback
    về DEFAULT_RULES để pipeline vẫn chạy được (phục vụ demo/test).
    """
    rules_path = os.getenv("SECURITY_RULES_PATH", "security_rules/mitre_rules.json")
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            raw_rules = json.load(f)
        return [_normalize_rule(r) for r in raw_rules]
    except (FileNotFoundError, json.JSONDecodeError):
        return [_normalize_rule(r) for r in DEFAULT_RULES]


# =========================================================
# 3. LLM WRAPPER (lazy, dùng chung pattern với agent_triage.py)
# =========================================================
def _get_llm():
    """Giống agent_triage._get_llm() - ưu tiên Anthropic, sau đó OpenAI."""
    if os.getenv("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
    if os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o-mini", temperature=0)
    return None


INVESTIGATOR_SYSTEM_PROMPT = """Bạn là chuyên gia Threat Hunting / Incident Response.
Bạn nhận được:
1. Một bản ghi log gốc và kết quả phân loại mức độ ban đầu (Triage)
2. Danh sách các kỹ thuật MITRE ATT&CK đã khớp qua đối chiếu từ khoá
3. Danh sách các sự kiện liên quan khác (nếu có) theo thứ tự thời gian

Nhiệm vụ: viết một đoạn phân tích kỹ thuật ngắn gọn (3-5 câu, tiếng Việt)
mô tả khả năng đây là một phần của chuỗi tấn công nào, dựa trên các kỹ thuật
MITRE đã khớp và trình tự sự kiện liên quan. Chỉ trả lời DUY NHẤT bằng JSON:
{
  "correlation_reasoning": "<phân tích kỹ thuật ngắn gọn>",
  "confidence": <số từ 0 đến 100, thể hiện độ tin cậy của bạn>
}
Không thêm bất kỳ văn bản nào khác ngoài JSON."""


# =========================================================
# 4. CÁC NODE CỦA GRAPH
# =========================================================
def node_load_and_match_rules(state: InvestigatorState) -> InvestigatorState:
    """Node 1: load rule MITRE + đối chiếu từ khoá với log gốc."""
    rules = _load_rules()
    state["rules"] = rules

    raw_log = state.get("raw_log", {})
    log_text = json.dumps(raw_log, ensure_ascii=False).lower()

    matched: List[Dict[str, Any]] = []
    for rule in rules:
        hit_keywords = [kw for kw in rule["keywords"] if kw in log_text]
        if hit_keywords:
            matched.append({
                "rule_id": rule["rule_id"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "tactic": rule["tactic"],
                "matched_keywords": hit_keywords,
                "description": rule["description"],
            })

    state["matched_techniques"] = matched
    return state


def _parse_timestamp(log: Dict[str, Any]) -> Optional[datetime]:
    """Cố gắng parse timestamp từ log (hỗ trợ vài field tên phổ biến)."""
    for field in ("timestamp", "time", "@timestamp", "event_time"):
        val = log.get(field)
        if val:
            try:
                return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def node_correlate_events(state: InvestigatorState) -> InvestigatorState:
    """
    Node 2: tương quan (correlate) log hiện tại với các log khác (context_logs)
    để dựng lại chuỗi sự kiện (attack chain) sơ bộ.

    Tiêu chí tương quan đơn giản (heuristic):
    - Cùng "host" HOẶC cùng "user" HOẶC cùng "src_ip"/"ip" với log gốc
    - Sắp xếp theo thời gian (nếu parse được timestamp)

    LƯU Ý: context_logs hiện do backend/main.py truyền vào (ví dụ: các log
    gần nhất của cùng host/user, do bạn - Security - truy vấn từ data/).
    Nếu không có context_logs, attack_chain sẽ chỉ gồm chính log hiện tại.
    """
    raw_log = state.get("raw_log", {})
    context_logs = state.get("context_logs", []) or []

    ref_host = raw_log.get("host")
    ref_user = raw_log.get("user")
    ref_ip = raw_log.get("src_ip") or raw_log.get("ip")

    related = [raw_log]  # log hiện tại luôn là 1 phần của chuỗi
    for log in context_logs:
        if log is raw_log:
            continue
        same_host = ref_host is not None and log.get("host") == ref_host
        same_user = ref_user is not None and log.get("user") == ref_user
        same_ip = ref_ip is not None and (log.get("src_ip") == ref_ip or log.get("ip") == ref_ip)
        if same_host or same_user or same_ip:
            related.append(log)

    # Sắp xếp theo thời gian nếu có thể parse được (log không parse được xếp cuối)
    def _sort_key(log: Dict[str, Any]):
        ts = _parse_timestamp(log)
        return (ts is None, ts or datetime.min)

    related_sorted = sorted(related, key=_sort_key)

    attack_chain = [
        {
            "timestamp": log.get("timestamp") or log.get("time") or "N/A",
            "event": log.get("event", str(log)),
            "host": log.get("host"),
            "user": log.get("user"),
        }
        for log in related_sorted
    ]

    state["attack_chain"] = attack_chain
    return state


def node_llm_correlate(state: InvestigatorState) -> InvestigatorState:
    """
    Node 3 (tuỳ chọn): dùng LLM để viết phân tích tương quan kỹ thuật.
    Nếu không có API key -> fallback sang tóm tắt rule-based đơn giản.
    """
    matched = state.get("matched_techniques", [])
    attack_chain = state.get("attack_chain", [])
    llm = _get_llm()

    if llm is None:
        if matched:
            techniques_str = ", ".join(f"{m['technique_id']} ({m['technique_name']})" for m in matched)
            state["correlation_reasoning"] = (
                f"[Rule-based] Log khớp với {len(matched)} kỹ thuật MITRE ATT&CK: "
                f"{techniques_str}. Chuỗi sự kiện liên quan gồm {len(attack_chain)} bản ghi."
            )
            state["confidence"] = min(90.0, 40.0 + 15.0 * len(matched))
        else:
            state["correlation_reasoning"] = (
                "[Rule-based] Không khớp với kỹ thuật MITRE ATT&CK nào trong bộ rule hiện có."
            )
            state["confidence"] = 20.0
        return state

    payload = {
        "triage_result": state.get("triage_result", {}),
        "matched_techniques": matched,
        "attack_chain": attack_chain,
    }

    try:
        response = llm.invoke([
            {"role": "system", "content": INVESTIGATOR_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
        ])
        content = response.content if hasattr(response, "content") else str(response)
        parsed = json.loads(content)
        state["correlation_reasoning"] = parsed.get("correlation_reasoning")
        state["confidence"] = parsed.get("confidence")
    except Exception as e:
        state["error"] = f"LLM investigation error, fallback to rule-based summary: {str(e)}"
        techniques_str = ", ".join(f"{m['technique_id']} ({m['technique_name']})" for m in matched) or "không có"
        state["correlation_reasoning"] = f"[Fallback] Kỹ thuật MITRE khớp được: {techniques_str}."
        state["confidence"] = 30.0 if matched else 10.0

    return state


# =========================================================
# 5. XÂY DỰNG GRAPH
# =========================================================
def build_investigator_graph():
    """
    START -> load_and_match_rules -> correlate_events -> llm_correlate -> END
    """
    graph = StateGraph(InvestigatorState)

    graph.add_node("load_and_match_rules", node_load_and_match_rules)
    graph.add_node("correlate_events", node_correlate_events)
    graph.add_node("llm_correlate", node_llm_correlate)

    graph.set_entry_point("load_and_match_rules")
    graph.add_edge("load_and_match_rules", "correlate_events")
    graph.add_edge("correlate_events", "llm_correlate")
    graph.add_edge("llm_correlate", END)

    return graph.compile()


_investigator_graph = build_investigator_graph()


# =========================================================
# 6. HÀM ENTRY POINT - được backend/main.py gọi
# =========================================================
def run_investigator_agent(
    raw_log: Dict[str, Any],
    triage_result: Dict[str, Any],
    context_logs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Input:
        raw_log: log gốc đang điều tra
        triage_result: kết quả trả về từ run_triage_agent() (Agent 1)
        context_logs: (tuỳ chọn) danh sách log khác để tìm sự kiện liên quan
                       (ví dụ: log gần nhất của cùng host/user, do main.py truy vấn)

    Output: dict gồm
        - matched_techniques: list các kỹ thuật MITRE ATT&CK khớp được
        - attack_chain: chuỗi sự kiện liên quan, sắp theo thời gian
        - reasoning: phân tích kỹ thuật (dùng cho Agent Explainer)
        - confidence: độ tin cậy tổng hợp (0-100)
        - error: (optional) lỗi nếu có
    """
    initial_state: InvestigatorState = {
        "raw_log": raw_log,
        "triage_result": triage_result,
        "context_logs": context_logs or [],
    }

    final_state = _investigator_graph.invoke(initial_state)

    return {
        "matched_techniques": final_state.get("matched_techniques", []),
        "attack_chain": final_state.get("attack_chain", []),
        "reasoning": final_state.get("correlation_reasoning"),
        "confidence": final_state.get("confidence"),
        "error": final_state.get("error"),
    }


# =========================================================
# 7. TEST NHANH ĐỘC LẬP
# =========================================================
if __name__ == "__main__":
    sample_log = {
        "timestamp": "2026-08-25T10:05:00+00:00",
        "host": "WIN-SRV-01",
        "user": "admin",
        "event": "Process executed: powershell -enc SQBFAFgA...",
    }
    sample_triage = {"severity": "HIGH", "severity_score": 85.0}
    sample_context = [
        {
            "timestamp": "2026-08-25T10:00:00+00:00",
            "host": "WIN-SRV-01",
            "user": "admin",
            "event": "Multiple login attempts failed for user admin",
        },
        {
            "timestamp": "2026-08-25T10:10:00+00:00",
            "host": "WIN-SRV-01",
            "user": "admin",
            "event": "psexec used to connect to \\\\WIN-SRV-02\\admin$",
        },
    ]

    result = run_investigator_agent(sample_log, sample_triage, sample_context)
    print(json.dumps(result, ensure_ascii=False, indent=2))
