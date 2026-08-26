"""
tests/simulate_pipeline.py
----------------------------
Script mô phỏng (simulate) luồng chạy FULL PIPELINE của hệ thống:

    Log JSON -> Agent Triage -> Agent Investigator -> Agent Explainer -> SQLite

Mục đích:
- Kiểm tra nhanh toàn bộ pipeline đã nối đúng chưa, KHÔNG cần bạn tự chạy
  `uvicorn` và gửi curl thủ công.
- Dùng `TestClient` của FastAPI để gọi thẳng vào `backend/main.py` (giống
  như gọi HTTP thật, nhưng không cần mở server/port).
- Kịch bản mô phỏng 1 chuỗi tấn công gồm 3 sự kiện xảy ra liên tiếp trên
  cùng 1 host/user (Brute force -> PowerShell encode -> Lateral movement
  qua PsExec), tương ứng với 1 kịch bản tấn công điển hình theo MITRE ATT&CK.

Cách chạy (từ thư mục gốc multi-agent-soc-project/):
    python tests/simulate_pipeline.py

LƯU Ý: Đây là dữ liệu MẪU tự tạo để demo pipeline. Khi bạn (Security) đã
chuẩn bị xong dữ liệu thật trong data/ và security_rules/, chỉ cần thay
SAMPLE_ATTACK_SCENARIO bên dưới bằng dữ liệu thật (đọc từ file JSON trong
data/) mà không cần sửa gì ở phần logic gọi pipeline.
"""

from __future__ import annotations

import sys
import os
import json

# --- Thiết lập môi trường TEST riêng biệt trước khi import backend/main.py ---
# Dùng 1 file SQLite riêng cho test (tránh ghi đè vào soc_history.db thật của dự án).
os.environ.setdefault("DB_PATH", "tests/test_soc_history.db")

# Thêm thư mục gốc dự án vào sys.path để import được package backend/ và ai_agents/
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from fastapi.testclient import TestClient  # noqa: E402
from backend.main import app  # noqa: E402


# =========================================================
# 1. DỮ LIỆU MẪU: kịch bản tấn công gồm 3 sự kiện liên tiếp
# =========================================================
# Kịch bản: kẻ tấn công brute-force tài khoản admin -> đăng nhập thành công
# -> thực thi PowerShell mã hoá (payload) -> di chuyển ngang (lateral movement)
# sang máy khác qua PsExec. Đây là chuỗi hành vi điển hình của 1 cuộc tấn công
# thực sự, không phải các sự kiện rời rạc ngẫu nhiên.
SAMPLE_ATTACK_SCENARIO = [
    {
        "timestamp": "2026-08-25T09:58:00+00:00",
        "host": "WIN-SRV-01",
        "user": "admin",
        "src_ip": "10.0.0.55",
        "event": "Multiple login attempts failed for user admin (brute force pattern)",
    },
    {
        "timestamp": "2026-08-25T10:05:00+00:00",
        "host": "WIN-SRV-01",
        "user": "admin",
        "src_ip": "10.0.0.55",
        "event": "Process executed: powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
    },
    {
        "timestamp": "2026-08-25T10:12:00+00:00",
        "host": "WIN-SRV-01",
        "user": "admin",
        "src_ip": "10.0.0.55",
        "event": "psexec used to connect to \\\\WIN-SRV-02\\admin$ and execute remote command",
    },
]


# =========================================================
# 2. HÀM TIỆN ÍCH IN KẾT QUẢ CHO DỄ ĐỌC
# =========================================================
def print_section(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_result(step_index: int, log_event: str, result: dict) -> None:
    triage = result.get("triage", {})
    investigation = result.get("investigation", {})
    explanation = result.get("explanation", {})

    print(f"\n--- Sự kiện #{step_index}: {log_event[:70]}... ---")
    print(f"  [Triage]         severity        = {triage.get('severity')} "
          f"(score={triage.get('severity_score')})")
    print(f"  [Triage]         reasoning       = {triage.get('reasoning')}")

    techniques = investigation.get("matched_techniques", [])
    technique_ids = [t.get("technique_id") for t in techniques]
    print(f"  [Investigator]   matched MITRE   = {technique_ids or 'Không có'}")
    print(f"  [Investigator]   attack_chain len= {len(investigation.get('attack_chain', []))}")
    print(f"  [Investigator]   confidence      = {investigation.get('confidence')}")

    print(f"  [Explainer]      summary         = {explanation.get('explanation_summary')}")
    actions = explanation.get("recommended_actions", [])
    print(f"  [Explainer]      actions         = {actions}")

    print(f"  [DB]             incident_id     = {result.get('incident_id')}")


# =========================================================
# 3. HÀM CHẠY MÔ PHỎNG CHÍNH
# =========================================================
def run_simulation() -> None:
    # QUAN TRỌNG: phải dùng TestClient trong khối "with" thì sự kiện
    # "startup" của FastAPI (nơi gọi init_db() để tạo bảng SQLite) mới
    # được kích hoạt. Nếu gọi TestClient(app) mà không có "with",
    # bảng `incidents` sẽ chưa được tạo và các thao tác DB sẽ lỗi.
    with TestClient(app) as client:
        # --- Kiểm tra server "sống" trước ---
        health = client.get("/health")
        assert health.status_code == 200, "Health check thất bại!"
        print_section("HEALTH CHECK")
        print(health.json())

        print_section(f"MÔ PHỎNG PIPELINE - {len(SAMPLE_ATTACK_SCENARIO)} sự kiện trong 1 chuỗi tấn công")

        incident_ids = []

        # Gửi lần lượt từng log trong kịch bản. Với mỗi log, các log TRƯỚC ĐÓ
        # trong kịch bản được truyền vào context_logs, mô phỏng việc SOC đã
        # ghi nhận các sự kiện trước đó và muốn Agent Investigator dựng lại
        # chuỗi tấn công.
        for i, log_event in enumerate(SAMPLE_ATTACK_SCENARIO, start=1):
            context_logs = SAMPLE_ATTACK_SCENARIO[: i - 1]  # các sự kiện xảy ra TRƯỚC log hiện tại

            payload = {"log": log_event, "context_logs": context_logs}
            response = client.post("/analyze_log", json=payload)

            assert response.status_code == 200, (
                f"Lỗi khi phân tích sự kiện #{i}: {response.status_code} - {response.text}"
            )

            result = response.json()
            print_result(i, log_event["event"], result)
            incident_ids.append(result.get("incident_id"))

        # --- Kiểm tra lại lịch sử đã lưu đầy đủ trong SQLite ---
        print_section("KIỂM TRA LỊCH SỬ (GET /history)")
        history_response = client.get("/history", params={"limit": 10})
        assert history_response.status_code == 200
        history = history_response.json()
        print(f"Tổng số bản ghi trong lịch sử (giới hạn 10 gần nhất): {len(history)}")
        for item in history:
            print(f"  - id={item['id']} | severity={item['triage']['severity']} "
                  f"| summary={item['explanation']['summary']}")

        # --- Kiểm tra lấy chi tiết 1 bản ghi cụ thể ---
        if incident_ids and incident_ids[-1] is not None:
            last_id = incident_ids[-1]
            print_section(f"CHI TIẾT 1 BẢN GHI (GET /history/{last_id})")
            detail_response = client.get(f"/history/{last_id}")
            assert detail_response.status_code == 200
            print(json.dumps(detail_response.json(), ensure_ascii=False, indent=2))

    print_section("✅ MÔ PHỎNG PIPELINE HOÀN TẤT - Tất cả bước chạy thành công")


if __name__ == "__main__":
    run_simulation()
