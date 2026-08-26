"""
agent_triage.py
----------------
AGENT 1: TRIAGE AGENT (Phân loại mức độ nghiêm trọng)

Nhiệm vụ:
- Nhận 1 bản ghi log (dict) từ backend/main.py
- Dùng LLM (qua LangGraph) kết hợp với luật heuristic đơn giản để phân loại
  mức độ rủi ro: LOW / MEDIUM / HIGH / CRITICAL
- Trả về kết quả có cấu trúc (severity, score, lý do sơ bộ) để Agent 2
  (Investigator) dùng tiếp trong pipeline.

Framework: LangGraph (StateGraph) + LangChain (ChatModel wrapper)

Lưu ý quan trọng: Agent này chạy được NGAY CẢ KHI CHƯA có API key
(sẽ tự động fallback về chế độ heuristic-only), để bạn có thể test luồng
chạy pipeline (tests/simulate_pipeline.py) mà không cần cấu hình LLM trước.
"""

from __future__ import annotations

import os
import json
from typing import TypedDict, Optional, Literal, List, Dict, Any

from langgraph.graph import StateGraph, END


# =========================================================
# 1. ĐỊNH NGHĨA STATE CHO GRAPH (LangGraph State Schema)
# =========================================================
class TriageState(TypedDict, total=False):
    """
    State được truyền xuyên suốt qua các node trong LangGraph.
    Đây là "bộ nhớ dùng chung" của Agent Triage trong quá trình xử lý.
    """
    raw_log: Dict[str, Any]          # Log JSON gốc đầu vào (1 event)
    severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]]
    severity_score: Optional[float]  # điểm số 0-100 do agent tính toán
    triage_reasoning: Optional[str]  # lý do ngắn gọn (Agent Explainer sẽ dùng lại)
    matched_indicators: List[str]    # các dấu hiệu/từ khoá nghi vấn tìm được
    error: Optional[str]


# =========================================================
# 2. HEURISTIC RULES (lớp lọc nhanh, dùng khi chưa/không gọi LLM)
# =========================================================
# Đây CHỈ là bộ từ khoá đơn giản để demo pipeline.
# KHÔNG thay thế cho security_rules/ (MITRE ATT&CK mapping) mà bạn
# sẽ cung cấp sau — Agent Investigator (Bước sau) sẽ đối chiếu với
# bộ rule chính thức đó.
HIGH_RISK_KEYWORDS = [
    "mimikatz", "powershell -enc", "psexec", "wmic", "reverse shell",
    "privilege escalation", "lateral movement", "ransomware",
    "certutil -urlcache", "rundll32", "regsvr32 /s /u",
]
MEDIUM_RISK_KEYWORDS = [
    "failed login", "brute force", "port scan", "unauthorized access",
    "suspicious process", "multiple login attempts",
]


def _heuristic_pre_screen(log_text: str) -> tuple[str, float, List[str]]:
    """
    Quét nhanh log (dạng text) theo từ khoá để đưa ra 1 mức triage sơ bộ.
    Trả về (severity, score, matched_keywords).
    """
    text_lower = log_text.lower()
    matched: List[str] = []

    for kw in HIGH_RISK_KEYWORDS:
        if kw in text_lower:
            matched.append(kw)
    if matched:
        return "HIGH", 85.0, matched

    for kw in MEDIUM_RISK_KEYWORDS:
        if kw in text_lower:
            matched.append(kw)
    if matched:
        return "MEDIUM", 55.0, matched

    return "LOW", 15.0, matched


# =========================================================
# 3. LLM WRAPPER (khởi tạo "lazy" - chỉ tạo khi thực sự cần)
# =========================================================
def _get_llm():
    """
    Khởi tạo LLM client theo biến môi trường.
    Ưu tiên: ANTHROPIC_API_KEY -> dùng Claude (langchain-anthropic)
             OPENAI_API_KEY    -> dùng GPT   (langchain-openai)
    Nếu không có key nào -> trả về None (agent chạy ở chế độ heuristic-only).

    TODO (bổ sung sau khi có security_rules/):
    - Đưa danh sách MITRE ATT&CK techniques vào system prompt
    - Tinh chỉnh model/temperature cho phù hợp
    """
    if os.getenv("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
    if os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o-mini", temperature=0)
    return None


TRIAGE_SYSTEM_PROMPT = """Bạn là một chuyên gia SOC (Security Operations Center).
Nhiệm vụ: đọc 1 bản ghi log (JSON) và phân loại mức độ rủi ro an ninh mạng.
Chỉ trả lời DUY NHẤT bằng JSON hợp lệ theo format:
{
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "severity_score": <số từ 0 đến 100>,
  "reasoning": "<giải thích ngắn gọn 1-2 câu bằng tiếng Việt>"
}
Không thêm bất kỳ văn bản nào khác ngoài JSON."""


# =========================================================
# 4. CÁC NODE CỦA GRAPH
# =========================================================
def node_heuristic_screen(state: TriageState) -> TriageState:
    """Node 1: quét nhanh bằng heuristic, luôn chạy trước (không tốn chi phí API)."""
    raw_log = state.get("raw_log", {})
    log_text = json.dumps(raw_log, ensure_ascii=False)

    severity, score, matched = _heuristic_pre_screen(log_text)

    state["severity"] = severity          # có thể bị ghi đè nếu LLM chạy thành công
    state["severity_score"] = score
    state["matched_indicators"] = matched
    state["triage_reasoning"] = (
        f"[Heuristic] Phát hiện {len(matched)} dấu hiệu nghi vấn: {matched}."
        if matched else "[Heuristic] Không phát hiện từ khoá rủi ro rõ ràng."
    )
    return state


def node_llm_classify(state: TriageState) -> TriageState:
    """
    Node 2: dùng LLM để phân loại chi tiết & chính xác hơn (nếu có API key).
    Nếu KHÔNG có LLM khả dụng -> giữ nguyên kết quả heuristic từ node 1.
    """
    llm = _get_llm()
    if llm is None:
        state["triage_reasoning"] = (
            (state.get("triage_reasoning") or "")
            + " (Chưa cấu hình LLM API key, dùng kết quả heuristic.)"
        )
        return state

    raw_log = state.get("raw_log", {})
    user_prompt = f"Log JSON cần phân tích:\n{json.dumps(raw_log, ensure_ascii=False, indent=2)}"

    try:
        response = llm.invoke([
            {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ])
        content = response.content if hasattr(response, "content") else str(response)
        parsed = json.loads(content)

        state["severity"] = parsed.get("severity", state.get("severity"))
        state["severity_score"] = parsed.get("severity_score", state.get("severity_score"))
        state["triage_reasoning"] = parsed.get("reasoning", state.get("triage_reasoning"))
    except Exception as e:
        # Nếu LLM lỗi (JSON parse fail, API lỗi, timeout...) -> giữ kết quả heuristic,
        # đồng thời ghi lại lỗi để backend có thể log/debug.
        state["error"] = f"LLM triage error, fallback to heuristic: {str(e)}"

    return state


# =========================================================
# 5. XÂY DỰNG GRAPH (LangGraph StateGraph)
# =========================================================
def build_triage_graph():
    """
    Xây dựng đồ thị (graph) cho Agent Triage:

        START -> heuristic_screen -> llm_classify -> END

    Tách heuristic và LLM thành 2 node riêng biệt giúp:
    - Dễ debug từng bước độc lập
    - Dễ mở rộng thêm node sau này, ví dụ: node đối chiếu trực tiếp với
      security_rules/ (MITRE ATT&CK mapping) khi bạn cung cấp dữ liệu đó.
    """
    graph = StateGraph(TriageState)

    graph.add_node("heuristic_screen", node_heuristic_screen)
    graph.add_node("llm_classify", node_llm_classify)

    graph.set_entry_point("heuristic_screen")
    graph.add_edge("heuristic_screen", "llm_classify")
    graph.add_edge("llm_classify", END)

    return graph.compile()


# Compile graph 1 lần duy nhất khi module được import, tái sử dụng cho mọi request
# (tránh build lại graph mỗi lần gọi -> tối ưu hiệu năng cho backend FastAPI)
_triage_graph = build_triage_graph()


# =========================================================
# 6. HÀM ENTRY POINT - được backend/main.py import và gọi trực tiếp
# =========================================================
def run_triage_agent(log_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Hàm chính mà backend/main.py sẽ gọi cho mỗi request /analyze_log.

    Input:
        log_data: dict - 1 bản ghi log JSON (đã được main.py parse từ file/body)

    Output: dict gồm
        - severity: LOW / MEDIUM / HIGH / CRITICAL
        - severity_score: điểm số 0-100
        - reasoning: giải thích sơ bộ (dùng lại cho Agent Explainer)
        - matched_indicators: các từ khoá/dấu hiệu nghi vấn tìm được
        - error: (optional) lỗi nếu có trong quá trình xử lý LLM
    """
    initial_state: TriageState = {
        "raw_log": log_data,
        "matched_indicators": [],
    }

    final_state = _triage_graph.invoke(initial_state)

    return {
        "severity": final_state.get("severity"),
        "severity_score": final_state.get("severity_score"),
        "reasoning": final_state.get("triage_reasoning"),
        "matched_indicators": final_state.get("matched_indicators", []),
        "error": final_state.get("error"),
    }


# =========================================================
# 7. TEST NHANH ĐỘC LẬP (chạy trực tiếp: python ai_agents/agent_triage.py)
# =========================================================
if __name__ == "__main__":
    sample_log = {
        "timestamp": "2026-08-25T10:00:00Z",
        "host": "WIN-SRV-01",
        "event": "Process executed: powershell -enc SQBFAFgA...",
        "user": "admin",
    }
    result = run_triage_agent(sample_log)
    print(json.dumps(result, ensure_ascii=False, indent=2))
