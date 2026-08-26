"""
backend/main.py
----------------
Backend API chính của dự án, xây dựng bằng FastAPI.

PIPELINE ĐẦY ĐỦ (đã hoàn thiện):
    Log JSON đầu vào
        -> Agent 1: Triage       (ai_agents/agent_triage.py)
        -> Agent 2: Investigator (ai_agents/agent_investigator.py)
        -> Agent 3: Explainer    (ai_agents/agent_explainer.py)
        -> Lưu toàn bộ kết quả vào SQLite (backend/database.py)
        -> Trả kết quả có cấu trúc về cho client

Endpoints:
    POST /analyze_log   - Chạy full pipeline cho 1 log, trả kết quả + lưu lịch sử
    GET  /history        - Xem danh sách lịch sử đã phân tích (mới nhất trước)
    GET  /history/{id}   - Xem chi tiết 1 bản ghi lịch sử theo id
    GET  /health          - Kiểm tra server còn sống

Cách chạy dev server (từ thư mục gốc multi-agent-soc-project/):
    uvicorn backend.main:app --reload
"""

import json
import sys
import os
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, UploadFile, File, HTTPException, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Thêm thư mục gốc dự án vào sys.path để import được package ai_agents/
# (cần thiết vì backend/ và ai_agents/ là 2 package ngang hàng nhau)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agents.agent_triage import run_triage_agent
from ai_agents.agent_investigator import run_investigator_agent
from ai_agents.agent_explainer import run_explainer_agent

# Import backend.database theo 2 cách để tương thích cả 2 kiểu chạy:
#   - "uvicorn backend.main:app"  (main.py được import dưới dạng backend.main)
#   - "python backend/main.py"    (main.py chạy như 1 script độc lập)
try:
    from backend.database import init_db, save_incident, get_incident, list_incidents
except ImportError:
    from database import init_db, save_incident, get_incident, list_incidents


# =========================================================
# 1. KHỞI TẠO ỨNG DỤNG FASTAPI
# =========================================================
app = FastAPI(
    title="Multi-Agent SOC - XAI Security Incident Detection API",
    description=(
        "Backend API cho hệ thống phát hiện & giải thích sự cố an ninh mạng "
        "sử dụng kiến trúc Multi-Agent AI (Triage -> Investigator -> Explainer)."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # TODO: giới hạn domain cụ thể khi deploy thật
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    """Khởi tạo bảng SQLite (nếu chưa có) ngay khi backend khởi động."""
    init_db()


# =========================================================
# 2. ĐỊNH NGHĨA SCHEMA (Pydantic) CHO REQUEST/RESPONSE
# =========================================================
class LogInput(BaseModel):
    """Schema khi client gửi JSON log trực tiếp trong body (không upload file)."""
    log: Dict[str, Any] = Field(..., description="1 bản ghi log dạng JSON cần phân tích")
    context_logs: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description=(
            "Tuỳ chọn: danh sách các log liên quan khác (cùng host/user/IP) "
            "để Agent Investigator dựng lại chuỗi tấn công (attack chain). "
            "Nếu không cung cấp, attack chain sẽ chỉ gồm chính log này."
        ),
    )


class TriageResult(BaseModel):
    severity: Optional[str] = None
    severity_score: Optional[float] = None
    reasoning: Optional[str] = None
    matched_indicators: List[str] = []
    error: Optional[str] = None


class InvestigationResult(BaseModel):
    matched_techniques: List[Dict[str, Any]] = []
    attack_chain: List[Dict[str, Any]] = []
    reasoning: Optional[str] = None
    confidence: Optional[float] = None
    error: Optional[str] = None


class ExplanationResult(BaseModel):
    explanation_summary: Optional[str] = None
    explanation_detail: Optional[str] = None
    recommended_actions: List[str] = []
    error: Optional[str] = None


class AnalyzeLogResponse(BaseModel):
    """Response tổng thể trả về cho client sau khi chạy FULL pipeline."""
    status: str
    incident_id: Optional[int] = None   # id bản ghi vừa lưu trong SQLite
    source_log: Dict[str, Any]
    triage: TriageResult
    investigation: InvestigationResult
    explanation: ExplanationResult


# =========================================================
# 3. ENDPOINT KIỂM TRA SỨC KHOẺ (Health check)
# =========================================================
@app.get("/health")
def health_check():
    """Endpoint đơn giản để kiểm tra API có đang chạy hay không."""
    return {"status": "ok", "service": "multi-agent-soc-backend"}


# =========================================================
# 4. HÀM DÙNG CHUNG: CHẠY FULL PIPELINE CHO 1 LOG
# =========================================================
def _run_full_pipeline(
    log_data: Dict[str, Any],
    context_logs: Optional[List[Dict[str, Any]]] = None,
) -> AnalyzeLogResponse:
    """
    Chạy tuần tự cả 3 Agent (Triage -> Investigator -> Explainer), sau đó lưu
    kết quả vào SQLite. Dùng chung cho cả 2 endpoint bên dưới (JSON body và
    upload file) để tránh lặp code.
    """
    # --- Bước 1: Agent Triage ---
    try:
        triage_result = run_triage_agent(log_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi chạy Triage Agent: {str(e)}")

    # --- Bước 2: Agent Investigator ---
    try:
        investigation_result = run_investigator_agent(log_data, triage_result, context_logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi chạy Investigator Agent: {str(e)}")

    # --- Bước 3: Agent Explainer (XAI) ---
    try:
        explanation_result = run_explainer_agent(log_data, triage_result, investigation_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi chạy Explainer Agent: {str(e)}")

    # --- Bước 4: Lưu toàn bộ kết quả pipeline vào SQLite ---
    try:
        saved = save_incident(log_data, triage_result, investigation_result, explanation_result)
        incident_id = saved.get("id")
    except Exception:
        # Không chặn response nếu lưu DB lỗi - vẫn trả kết quả phân tích cho client,
        # nhưng incident_id = None để client biết chưa được lưu lịch sử.
        incident_id = None

    return AnalyzeLogResponse(
        status="analyzed",
        incident_id=incident_id,
        source_log=log_data,
        triage=TriageResult(**triage_result),
        investigation=InvestigationResult(**investigation_result),
        explanation=ExplanationResult(**explanation_result),
    )


# =========================================================
# 5. ENDPOINT CHÍNH: /analyze_log (nhận JSON body)
# =========================================================
# LƯU Ý KỸ THUẬT: FastAPI không cho phép trộn tham số `File(...)` và
# `Body(...)` ổn định trong CÙNG 1 endpoint (request sẽ luôn bị ép hiểu là
# multipart/form-data). Vì vậy pipeline được tách thành 2 endpoint riêng:
#   - POST /analyze_log       : nhận JSON body (hỗ trợ đầy đủ context_logs)
#   - POST /analyze_log/file  : nhận file .json upload
@app.post("/analyze_log", response_model=AnalyzeLogResponse)
async def analyze_log(log_body: LogInput):
    """
    Chạy FULL pipeline cho 1 bản ghi log gửi qua JSON body:
        Agent Triage -> Agent Investigator -> Agent Explainer -> lưu SQLite

    Ví dụ gọi API:
        curl -X POST "http://localhost:8000/analyze_log" \\
             -H "Content-Type: application/json" \\
             -d '{
                   "log": {"host": "WIN-SRV-01", "event": "powershell -enc ..."},
                   "context_logs": [
                     {"host": "WIN-SRV-01", "event": "Multiple login attempts failed"}
                   ]
                 }'
    """
    return _run_full_pipeline(log_body.log, log_body.context_logs)


# =========================================================
# 6. ENDPOINT PHỤ: /analyze_log/file (nhận file .json upload)
# =========================================================
@app.post("/analyze_log/file", response_model=AnalyzeLogResponse)
async def analyze_log_file(
    file: UploadFile = File(..., description="File log JSON (.json) upload trực tiếp"),
):
    """
    Chạy FULL pipeline cho 1 bản ghi log upload dưới dạng file .json.
    (Chưa hỗ trợ context_logs qua file - dùng POST /analyze_log nếu cần
    dựng attack chain với các sự kiện liên quan.)

    Ví dụ gọi API:
        curl -X POST "http://localhost:8000/analyze_log/file" \\
             -F "file=@sample_log.json"
    """
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="File phải có định dạng .json")

    try:
        content = await file.read()
        log_data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Nội dung file không phải JSON hợp lệ")

    return _run_full_pipeline(log_data, context_logs=None)


# =========================================================
# 7. ENDPOINT XEM LỊCH SỬ
# =========================================================
@app.get("/history")
def get_history(
    limit: int = Query(default=50, ge=1, le=500, description="Số lượng bản ghi tối đa trả về"),
    severity: Optional[str] = Query(default=None, description="Lọc theo mức độ: LOW/MEDIUM/HIGH/CRITICAL"),
):
    """Trả về danh sách các bản ghi đã phân tích, mới nhất trước."""
    return list_incidents(limit=limit, severity=severity)


@app.get("/history/{incident_id}")
def get_history_item(incident_id: int):
    """Trả về chi tiết 1 bản ghi lịch sử theo id."""
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy incident id={incident_id}")
    return incident


# =========================================================
# 8. CHẠY TRỰC TIẾP (dev mode: python backend/main.py)
# =========================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
