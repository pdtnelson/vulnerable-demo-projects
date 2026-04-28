from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.database import get_db_connection
from app.encryption import encrypt_phi, decrypt_phi
from app.schemas.treatment import TreatmentCreate, TreatmentUpdate, TreatmentResponse
from app.auth.rbac import require_permission
from app.auth.dependencies import get_current_user
from app.middleware.audit import log_audit

router = APIRouter(prefix="/treatments", tags=["treatments"])


@router.post("/", response_model=TreatmentResponse, status_code=status.HTTP_201_CREATED)
async def create_treatment(
    request: Request,
    treatment_data: TreatmentCreate,
    current_user: dict = Depends(require_permission("treatments:create")),
):
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        visit = conn.execute("SELECT id FROM visits WHERE id = ?", (treatment_data.visit_id,)).fetchone()
        if not visit:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Visit not found")

        cursor = conn.execute(
            """INSERT INTO treatments (visit_id, treatment_type, name, dosage, frequency, notes_enc, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                treatment_data.visit_id, treatment_data.treatment_type, treatment_data.name,
                treatment_data.dosage, treatment_data.frequency,
                encrypt_phi(treatment_data.notes) if treatment_data.notes else None,
                treatment_data.status or "active", now, now,
            ),
        )
        conn.commit()
        treatment_id = cursor.lastrowid

        log_audit(
            user_id=current_user["id"], user_role=current_user["role"],
            action="CREATE", resource_type="treatment", resource_id=treatment_id,
            details={"visit_id": treatment_data.visit_id, "name": treatment_data.name},
            ip_address=request.client.host if request.client else None, success=True,
        )

        row = conn.execute("SELECT * FROM treatments WHERE id = ?", (treatment_id,)).fetchone()
        return _row_to_response(row)
    finally:
        conn.close()


@router.get("/", response_model=list[TreatmentResponse])
async def list_treatments(
    request: Request,
    visit_id: int = None,
    status_filter: str = None,
    current_user: dict = Depends(require_permission("treatments:read")),
):
    conn = get_db_connection()
    try:
        query = "SELECT * FROM treatments WHERE 1=1"
        params = []
        if visit_id:
            query += " AND visit_id = ?"
            params.append(visit_id)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        query += " ORDER BY id DESC"

        rows = conn.execute(query, params).fetchall()

        log_audit(
            user_id=current_user["id"], user_role=current_user["role"],
            action="READ", resource_type="treatment",
            details={"action": "list", "count": len(rows), "filters": {"visit_id": visit_id}},
            ip_address=request.client.host if request.client else None, success=True,
        )

        return [_row_to_response(row) for row in rows]
    finally:
        conn.close()


@router.get("/{treatment_id}", response_model=TreatmentResponse)
async def get_treatment(
    treatment_id: int,
    request: Request,
    current_user: dict = Depends(require_permission("treatments:read")),
):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM treatments WHERE id = ?", (treatment_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Treatment not found")

        log_audit(
            user_id=current_user["id"], user_role=current_user["role"],
            action="READ", resource_type="treatment", resource_id=treatment_id,
            ip_address=request.client.host if request.client else None, success=True,
        )

        return _row_to_response(row)
    finally:
        conn.close()


@router.put("/{treatment_id}", response_model=TreatmentResponse)
async def update_treatment(
    treatment_id: int,
    request: Request,
    treatment_data: TreatmentUpdate,
    current_user: dict = Depends(get_current_user),
):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM treatments WHERE id = ?", (treatment_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Treatment not found")

        update_data = treatment_data.model_dump(exclude_unset=True)
        if not update_data:
            return _row_to_response(row)

        updates = {}
        for field, value in update_data.items():
            if field == "notes":
                updates["notes_enc"] = encrypt_phi(value) if value else None
            else:
                updates[field] = value
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [treatment_id]
        conn.execute(f"UPDATE treatments SET {set_clause} WHERE id = ?", values)
        conn.commit()

        log_audit(
            user_id=current_user["id"], user_role=current_user["role"],
            action="UPDATE", resource_type="treatment", resource_id=treatment_id,
            details={"updated_fields": list(update_data.keys())},
            ip_address=request.client.host if request.client else None, success=True,
        )

        row = conn.execute("SELECT * FROM treatments WHERE id = ?", (treatment_id,)).fetchone()
        return _row_to_response(row)
    finally:
        conn.close()


@router.delete("/{treatment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_treatment(
    treatment_id: int,
    request: Request,
    current_user: dict = Depends(require_permission("treatments:delete")),
):
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM treatments WHERE id = ?", (treatment_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Treatment not found")

        now = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE treatments SET status = 'discontinued', updated_at = ? WHERE id = ?", (now, treatment_id))
        conn.commit()

        log_audit(
            user_id=current_user["id"], user_role=current_user["role"],
            action="DELETE", resource_type="treatment", resource_id=treatment_id,
            ip_address=request.client.host if request.client else None, success=True,
        )
    finally:
        conn.close()


def _row_to_response(row) -> TreatmentResponse:
    return TreatmentResponse(
        id=row["id"], visit_id=row["visit_id"], treatment_type=row["treatment_type"],
        name=row["name"], dosage=row["dosage"], frequency=row["frequency"],
        notes=decrypt_phi(row["notes_enc"]) if row["notes_enc"] else None,
        status=row["status"], created_at=row["created_at"], updated_at=row["updated_at"],
    )
