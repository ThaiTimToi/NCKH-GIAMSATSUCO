"""
backend/database.py
---------------------
Lưu lịch sử phân tích (toàn bộ pipeline: Triage + Investigation + Explanation)
vào SQLite bằng SQLAlchemy.

Thiết kế đơn giản, đủ dùng cho nghiên cứu/demo:
- 1 bảng duy nhất `incidents` lưu toàn bộ kết quả của 1 lần chạy pipeline
  cho 1 log (các trường JSON được serialize dưới dạng TEXT).
- Cung cấp các hàm tiện ích: init_db(), save_incident(), get_incident(),
  list_incidents() để backend/main.py gọi.

Đường dẫn file DB có thể tuỳ chỉnh qua biến môi trường DB_PATH,
mặc định là "soc_history.db" tại thư mục gốc dự án.
"""

from __future__ import annotations

import os
import json
import datetime as dt
from typing import Optional, List, Dict, Any

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================================================
# 1. CẤU HÌNH ENGINE / SESSION
# =========================================================
DB_PATH = os.getenv("DB_PATH", "soc_history.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# check_same_thread=False: cần thiết vì FastAPI có thể xử lý request trên
# thread khác với thread khởi tạo engine (SQLite mặc định chỉ cho phép
# truy cập từ 1 thread).
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


# =========================================================
# 2. ĐỊNH NGHĨA BẢNG `incidents`
# =========================================================
class Incident(Base):
    """
    Mỗi row = kết quả đầy đủ của 1 lần chạy pipeline (1 log đầu vào)
    qua cả 3 Agent: Triage -> Investigator -> Explainer.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)

    # --- Dữ liệu log gốc ---
    raw_log_json = Column(Text, nullable=False)          # JSON string của log gốc

    # --- Kết quả Agent 1: Triage ---
    severity = Column(String(20), nullable=True)
    severity_score = Column(Float, nullable=True)
    triage_reasoning = Column(Text, nullable=True)

    # --- Kết quả Agent 2: Investigator ---
    matched_techniques_json = Column(Text, nullable=True)  # JSON string list kỹ thuật MITRE
    attack_chain_json = Column(Text, nullable=True)        # JSON string chuỗi sự kiện liên quan
    investigation_reasoning = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)

    # --- Kết quả Agent 3: Explainer (XAI) ---
    explanation_summary = Column(Text, nullable=True)
    explanation_detail = Column(Text, nullable=True)
    recommended_actions_json = Column(Text, nullable=True)  # JSON string list hành động

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển 1 row thành dict (tự động parse lại các trường JSON string)."""
        def _safe_json_load(value: Optional[str], default):
            if not value:
                return default
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return default

        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "raw_log": _safe_json_load(self.raw_log_json, {}),
            "triage": {
                "severity": self.severity,
                "severity_score": self.severity_score,
                "reasoning": self.triage_reasoning,
            },
            "investigation": {
                "matched_techniques": _safe_json_load(self.matched_techniques_json, []),
                "attack_chain": _safe_json_load(self.attack_chain_json, []),
                "reasoning": self.investigation_reasoning,
                "confidence": self.confidence,
            },
            "explanation": {
                "summary": self.explanation_summary,
                "detail": self.explanation_detail,
                "recommended_actions": _safe_json_load(self.recommended_actions_json, []),
            },
        }


# =========================================================
# 3. KHỞI TẠO DATABASE
# =========================================================
def init_db() -> None:
    """
    Tạo bảng `incidents` nếu chưa tồn tại. Gọi hàm này 1 lần lúc khởi động
    ứng dụng FastAPI (ví dụ trong sự kiện "startup" của backend/main.py).
    """
    Base.metadata.create_all(bind=engine)


# =========================================================
# 4. HÀM LƯU 1 BẢN GHI PIPELINE ĐẦY ĐỦ
# =========================================================
def save_incident(
    raw_log: Dict[str, Any],
    triage_result: Dict[str, Any],
    investigation_result: Optional[Dict[str, Any]] = None,
    explanation_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Lưu kết quả đầy đủ của 1 lần chạy pipeline vào SQLite.

    Các tham số investigation_result / explanation_result có thể để None
    trong trường hợp pipeline dừng sớm (ví dụ: severity=LOW nên không chạy
    tiếp Investigator/Explainer để tiết kiệm chi phí LLM) - main.py tự quyết
    định khi nào gọi save_incident với đầy đủ 4 tham số.

    Trả về dict của bản ghi vừa lưu (bao gồm `id` được DB tự sinh).
    """
    investigation_result = investigation_result or {}
    explanation_result = explanation_result or {}

    db = SessionLocal()
    try:
        incident = Incident(
            raw_log_json=json.dumps(raw_log, ensure_ascii=False),

            severity=triage_result.get("severity"),
            severity_score=triage_result.get("severity_score"),
            triage_reasoning=triage_result.get("reasoning"),

            matched_techniques_json=json.dumps(
                investigation_result.get("matched_techniques", []), ensure_ascii=False
            ),
            attack_chain_json=json.dumps(
                investigation_result.get("attack_chain", []), ensure_ascii=False
            ),
            investigation_reasoning=investigation_result.get("reasoning"),
            confidence=investigation_result.get("confidence"),

            explanation_summary=explanation_result.get("explanation_summary"),
            explanation_detail=explanation_result.get("explanation_detail"),
            recommended_actions_json=json.dumps(
                explanation_result.get("recommended_actions", []), ensure_ascii=False
            ),
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident.to_dict()
    finally:
        db.close()


# =========================================================
# 5. HÀM TRUY VẤN LỊCH SỬ
# =========================================================
def get_incident(incident_id: int) -> Optional[Dict[str, Any]]:
    """Lấy 1 bản ghi theo id. Trả về None nếu không tìm thấy."""
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        return incident.to_dict() if incident else None
    finally:
        db.close()


def list_incidents(limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Lấy danh sách các bản ghi gần nhất (mới nhất trước), có thể lọc theo severity.
    Dùng cho endpoint kiểu GET /history (sẽ thêm vào main.py khi tích hợp).
    """
    db = SessionLocal()
    try:
        query = db.query(Incident).order_by(Incident.created_at.desc())
        if severity:
            query = query.filter(Incident.severity == severity)
        incidents = query.limit(limit).all()
        return [i.to_dict() for i in incidents]
    finally:
        db.close()


# =========================================================
# 6. TEST NHANH ĐỘC LẬP
# =========================================================
if __name__ == "__main__":
    init_db()

    saved = save_incident(
        raw_log={"host": "WIN-SRV-01", "event": "powershell -enc ..."},
        triage_result={"severity": "HIGH", "severity_score": 85.0, "reasoning": "Test"},
        investigation_result={
            "matched_techniques": [{"technique_id": "T1059.001", "technique_name": "PowerShell"}],
            "attack_chain": [{"event": "powershell -enc ..."}],
            "reasoning": "Test reasoning",
            "confidence": 80.0,
        },
        explanation_result={
            "explanation_summary": "Phát hiện thực thi PowerShell đáng ngờ.",
            "explanation_detail": "Chi tiết giải thích test...",
            "recommended_actions": ["Cách ly host", "Đổi mật khẩu"],
        },
    )
    print("Đã lưu bản ghi:", json.dumps(saved, ensure_ascii=False, indent=2))
    print("\nDanh sách lịch sử gần nhất:")
    print(json.dumps(list_incidents(limit=5), ensure_ascii=False, indent=2))
