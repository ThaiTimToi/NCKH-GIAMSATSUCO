"""
agent_explainer.py
--------------------
AGENT 3: EXPLAINER AGENT (Explainable AI - XAI)

Nhiệm vụ:
- Nhận kết quả từ Agent 1 (Triage) + Agent 2 (Investigator)
- "Dịch" các kết quả kỹ thuật (severity, MITRE technique, attack chain...)
  sang ngôn ngữ tự nhiên, dễ hiểu cho người không chuyên (quản lý, khách hàng...)
- Đưa ra khuyến nghị hành động (recommended actions) cụ thể

Đây chính là thành phần "XAI" (Explainable AI) của hệ thống: mục tiêu không
chỉ là phát hiện, mà còn phải GIẢI THÍCH được TẠI SAO hệ thống kết luận như vậy.

Framework: LangGraph (StateGraph) + LangChain (ChatModel wrapper, tuỳ chọn)

Thiết kế "graceful degradation": giống 2 agent trước, Agent này LUÔN cho ra
kết quả (qua template rule-based) ngay cả khi CHƯA cấu hình LLM API key -
LLM chỉ giúp làm văn bản giải thích tự nhiên & mượt hơn.
"""

from __future__ import annotations

import os
import json
from typing import TypedDict, Optional, List, Dict, Any

from langgraph.graph import StateGraph, END


# =========================================================
# 1. ĐỊNH NGHĨA STATE CHO GRAPH
# =========================================================
class ExplainerState(TypedDict, total=False):
    raw_log: Dict[str, Any]
    triage_result: Dict[str, Any]         # từ Agent 1
    investigation_result: Dict[str, Any]  # từ Agent 2

    explanation_summary: Optional[str]    # 1 câu tóm tắt (hiển thị ở dashboard)
    explanation_detail: Optional[str]     # đoạn giải thích chi tiết, dễ hiểu
    recommended_actions: List[str]        # danh sách hành động khuyến nghị
    error: Optional[str]


# =========================================================
# 2. MAP MỨC ĐỘ SANG MÔ TẢ / KHUYẾN NGHỊ MẶC ĐỊNH (rule-based, luôn chạy được)
# =========================================================
SEVERITY_DESCRIPTIONS = {
    "LOW": "mức độ THẤP - khả năng cao là hoạt động bình thường hoặc rủi ro không đáng kể",
    "MEDIUM": "mức độ TRUNG BÌNH - có dấu hiệu bất thường, cần được rà soát thêm",
    "HIGH": "mức độ CAO - có dấu hiệu rõ ràng của hành vi tấn công, cần xử lý sớm",
    "CRITICAL": "mức độ NGHIÊM TRỌNG - khả năng cao hệ thống đang bị xâm nhập, cần xử lý NGAY LẬP TỨC",
}

DEFAULT_ACTIONS_BY_SEVERITY = {
    "LOW": [
        "Theo dõi thêm, chưa cần hành động khẩn cấp.",
        "Ghi nhận vào lịch sử để đối chiếu nếu có sự kiện tương tự trong tương lai.",
    ],
    "MEDIUM": [
        "Rà soát lại log liên quan đến host/user trong khoảng thời gian gần nhất.",
        "Xác minh với chủ tài khoản/thiết bị xem hoạt động có hợp lệ không.",
    ],
    "HIGH": [
        "Cách ly (isolate) thiết bị/host liên quan khỏi mạng nếu có thể.",
        "Đổi mật khẩu tài khoản liên quan và kiểm tra các phiên đăng nhập đang hoạt động.",
        "Thu thập thêm bằng chứng (forensics) trước khi xử lý triệt để.",
    ],
    "CRITICAL": [
        "Kích hoạt quy trình phản ứng sự cố (Incident Response) khẩn cấp.",
        "Cách ly ngay lập tức host/tài khoản liên quan.",
        "Thông báo cho đội ngũ quản lý & các bên liên quan theo quy trình escalation.",
        "Bắt đầu thu thập bằng chứng phục vụ điều tra sau sự cố (post-incident forensics).",
    ],
}


def _build_template_explanation(
    triage_result: Dict[str, Any],
    investigation_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Sinh giải thích XAI theo template rule-based (LUÔN chạy được, không cần LLM).
    Đây là baseline đảm bảo hệ thống luôn trả về kết quả có thể đọc được.
    """
    severity = triage_result.get("severity", "LOW")
    score = triage_result.get("severity_score", 0)
    matched_techniques = investigation_result.get("matched_techniques", [])
    attack_chain = investigation_result.get("attack_chain", [])

    severity_desc = SEVERITY_DESCRIPTIONS.get(severity, SEVERITY_DESCRIPTIONS["LOW"])
    summary = f"Sự kiện được đánh giá ở {severity_desc} (điểm rủi ro: {score}/100)."

    detail_parts = [summary]

    if matched_techniques:
        technique_names = [f"{t['technique_id']} - {t['technique_name']}" for t in matched_techniques]
        detail_parts.append(
            "Hệ thống phát hiện hành vi tương ứng với các kỹ thuật tấn công theo khung "
            f"MITRE ATT&CK sau: {', '.join(technique_names)}."
        )
    else:
        detail_parts.append(
            "Hệ thống chưa tìm thấy kỹ thuật tấn công cụ thể nào theo khung MITRE ATT&CK "
            "khớp với sự kiện này trong bộ luật hiện có."
        )

    if len(attack_chain) > 1:
        detail_parts.append(
            f"Sự kiện này nằm trong một chuỗi gồm {len(attack_chain)} sự kiện liên quan "
            "(cùng thiết bị/tài khoản), cho thấy khả năng đây là một chuỗi hành vi có chủ đích "
            "thay vì một sự kiện đơn lẻ ngẫu nhiên."
        )

    detail = " ".join(detail_parts)
    actions = DEFAULT_ACTIONS_BY_SEVERITY.get(severity, DEFAULT_ACTIONS_BY_SEVERITY["LOW"])

    return {
        "explanation_summary": summary,
        "explanation_detail": detail,
        "recommended_actions": actions,
    }


# =========================================================
# 3. LLM WRAPPER (lazy, cùng pattern với 2 agent trước)
# =========================================================
def _get_llm():
    if os.getenv("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model="claude-sonnet-4-6", temperature=0.3)
    if os.getenv("OPENAI_API_KEY"):
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o-mini", temperature=0.3)
    return None


EXPLAINER_SYSTEM_PROMPT = """Bạn là chuyên gia SOC, đóng vai trò "người phiên dịch" giữa
kết quả phân tích kỹ thuật và người đọc KHÔNG chuyên về bảo mật (ví dụ: quản lý cấp cao).
Bạn sẽ nhận dữ liệu JSON gồm: kết quả triage, các kỹ thuật MITRE ATT&CK khớp được,
và chuỗi sự kiện liên quan.

Nhiệm vụ: viết lại thành giải thích DỄ HIỂU bằng tiếng Việt, tránh thuật ngữ khó,
có ví von nếu cần, và đề xuất hành động cụ thể. Chỉ trả lời DUY NHẤT bằng JSON:
{
  "explanation_summary": "<1 câu tóm tắt ngắn gọn, dễ hiểu>",
  "explanation_detail": "<đoạn giải thích chi tiết 4-6 câu, ngôn ngữ đơn giản, không thuật ngữ khó>",
  "recommended_actions": ["<hành động 1>", "<hành động 2>", "..."]
}
Không thêm bất kỳ văn bản nào khác ngoài JSON."""


# =========================================================
# 4. CÁC NODE CỦA GRAPH
# =========================================================
def node_template_explanation(state: ExplainerState) -> ExplainerState:
    """Node 1: LUÔN chạy - tạo baseline giải thích bằng template rule-based."""
    result = _build_template_explanation(
        state.get("triage_result", {}),
        state.get("investigation_result", {}),
    )
    state["explanation_summary"] = result["explanation_summary"]
    state["explanation_detail"] = result["explanation_detail"]
    state["recommended_actions"] = result["recommended_actions"]
    return state


def node_llm_refine(state: ExplainerState) -> ExplainerState:
    """
    Node 2 (tuỳ chọn): dùng LLM viết lại giải thích cho tự nhiên & dễ hiểu hơn.
    Nếu không có LLM hoặc lỗi -> GIỮ NGUYÊN kết quả template từ node 1
    (đảm bảo luôn có output hợp lệ).
    """
    llm = _get_llm()
    if llm is None:
        return state

    payload = {
        "triage_result": state.get("triage_result", {}),
        "investigation_result": state.get("investigation_result", {}),
    }

    try:
        response = llm.invoke([
            {"role": "system", "content": EXPLAINER_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
        ])
        content = response.content if hasattr(response, "content") else str(response)
        parsed = json.loads(content)

        state["explanation_summary"] = parsed.get("explanation_summary", state.get("explanation_summary"))
        state["explanation_detail"] = parsed.get("explanation_detail", state.get("explanation_detail"))
        actions = parsed.get("recommended_actions")
        if actions:
            state["recommended_actions"] = actions
    except Exception as e:
        # Giữ nguyên kết quả template (đã có ở node 1), chỉ ghi nhận lỗi
        state["error"] = f"LLM explanation error, kept template-based explanation: {str(e)}"

    return state


# =========================================================
# 5. XÂY DỰNG GRAPH
# =========================================================
def build_explainer_graph():
    """
    START -> template_explanation -> llm_refine -> END
    """
    graph = StateGraph(ExplainerState)

    graph.add_node("template_explanation", node_template_explanation)
    graph.add_node("llm_refine", node_llm_refine)

    graph.set_entry_point("template_explanation")
    graph.add_edge("template_explanation", "llm_refine")
    graph.add_edge("llm_refine", END)

    return graph.compile()


_explainer_graph = build_explainer_graph()


# =========================================================
# 6. HÀM ENTRY POINT - được backend/main.py gọi
# =========================================================
def run_explainer_agent(
    raw_log: Dict[str, Any],
    triage_result: Dict[str, Any],
    investigation_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Input:
        raw_log: log gốc
        triage_result: kết quả từ run_triage_agent() (Agent 1)
        investigation_result: kết quả từ run_investigator_agent() (Agent 2)

    Output: dict gồm
        - explanation_summary: 1 câu tóm tắt (hiển thị nhanh trên dashboard)
        - explanation_detail: đoạn giải thích chi tiết, dễ hiểu
        - recommended_actions: list hành động khuyến nghị
        - error: (optional) lỗi nếu có trong bước LLM refine
    """
    initial_state: ExplainerState = {
        "raw_log": raw_log,
        "triage_result": triage_result,
        "investigation_result": investigation_result,
        "recommended_actions": [],
    }

    final_state = _explainer_graph.invoke(initial_state)

    return {
        "explanation_summary": final_state.get("explanation_summary"),
        "explanation_detail": final_state.get("explanation_detail"),
        "recommended_actions": final_state.get("recommended_actions", []),
        "error": final_state.get("error"),
    }


# =========================================================
# 7. TEST NHANH ĐỘC LẬP
# =========================================================
if __name__ == "__main__":
    sample_raw_log = {
        "timestamp": "2026-08-25T10:05:00+00:00",
        "host": "WIN-SRV-01",
        "user": "admin",
        "event": "Process executed: powershell -enc SQBFAFgA...",
    }
    sample_triage = {"severity": "HIGH", "severity_score": 85.0}
    sample_investigation = {
        "matched_techniques": [
            {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
        ],
        "attack_chain": [
            {"timestamp": "2026-08-25T10:00:00+00:00", "event": "Multiple login attempts failed"},
            {"timestamp": "2026-08-25T10:05:00+00:00", "event": "powershell -enc ..."},
        ],
        "confidence": 78.0,
    }

    result = run_explainer_agent(sample_raw_log, sample_triage, sample_investigation)
    print(json.dumps(result, ensure_ascii=False, indent=2))
