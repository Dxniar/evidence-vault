"""Case lifecycle and explicit collaboration with serialized, audited changes."""
from flask import Blueprint, abort, flash, g, redirect, request, session, url_for
from sqlalchemy import select

from models import AuditLog, Case, CaseMember, Evidence, EvidenceTransfer, User, db, utc_now
from app import append_event, can_manage_case, can_view_case, login_required, session_matches_user

bp = Blueprint("casework", __name__)


def managed_case(case_id, extra_user_id=None):
    case = db.session.get(Case, case_id, with_for_update=True, populate_existing=True)
    if case is None:
        abort(404)
    ids = sorted({g.user.id, extra_user_id} - {None})
    users = db.session.scalars(select(User).where(User.id.in_(ids)).order_by(User.id)
        .with_for_update().execution_options(populate_existing=True)).all()
    actor = next((user for user in users if user.id == g.user.id), None)
    if not session_matches_user(actor):
        session.clear()
        abort(403)
    if not can_view_case(case, actor):
        abort(404)
    if not can_manage_case(case, actor):
        abort(403)
    return case, users


def change_reason():
    reason = request.form.get("reason", "").strip()
    if not 3 <= len(reason) <= 1000:
        abort(400, "Укажите основание изменения: от 3 до 1000 символов.")
    return reason


@bp.post("/cases/<int:case_id>/update")
@login_required
def update_case(case_id):
    case, _ = managed_case(case_id)
    if case.status != "active":
        abort(409, "Закрытое дело доступно для просмотра. Сначала возобновите его.")
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    reference = request.form.get("reference_number", "").strip()
    priority = request.form.get("priority", "normal")
    if not 3 <= len(title) <= 120 or len(description) > 5000 or len(reference) > 80 or priority not in {"low", "normal", "high"}:
        abort(400, "Проверьте название, описание, номер и приоритет.")
    reason = change_reason()
    before = {name: getattr(case, name) for name in ("title", "description", "reference_number", "priority")}
    after = {"title": title, "description": description, "reference_number": reference, "priority": priority}
    if before != after:
        for name, value in after.items():
            setattr(case, name, value)
        case.updated_at = utc_now()
        append_event("CASE_UPDATED", f"Обновлены сведения дела {case.case_number}. Основание: {reason}",
                     case_id=case.id, details={"before": before, "after": after, "reason": reason})
        db.session.commit()
        flash("Сведения обновлены. Предыдущее состояние сохранено в истории.", "success")
    else:
        flash("Сведения уже актуальны.", "info")
    return redirect(url_for("case_detail", case_id=case.id))


@bp.post("/cases/<int:case_id>/status")
@login_required
def change_status(case_id):
    case, _ = managed_case(case_id)
    target = request.form.get("status")
    if target not in {"active", "closed"}:
        abort(400, "Неизвестный статус дела.")
    reason = change_reason()
    if target == case.status:
        abort(409, "Дело уже имеет выбранный статус.")
    if target == "closed":
        pending = db.session.scalar(select(EvidenceTransfer.id).join(Evidence)
            .where(Evidence.case_id == case.id, EvidenceTransfer.status == "pending").limit(1))
        if pending is not None:
            abort(409, "Сначала завершите или отмените ожидающие передачи доказательств.")
        case.closed_at = utc_now()
        case.closed_by = g.user.id
        case.closure_reason = reason
    else:
        case.closed_at = None
        case.closed_by = None
        case.closure_reason = ""
    old = case.status
    case.status = target
    case.updated_at = utc_now()
    append_event("CASE_CLOSED" if target == "closed" else "CASE_REOPENED",
        f"Дело {case.case_number} {'закрыто' if target == 'closed' else 'возобновлено'}. Основание: {reason}",
        case_id=case.id, details={"before": old, "after": target, "reason": reason})
    db.session.commit()
    flash("Дело закрыто. Материалы доступны для просмотра." if target == "closed" else "Дело возобновлено.", "success")
    return redirect(url_for("case_detail", case_id=case.id))


@bp.post("/cases/<int:case_id>/members")
@login_required
def update_member(case_id):
    target_id = request.form.get("user_id", type=int)
    if target_id is None:
        abort(400, "Выберите сотрудника.")
    case, users = managed_case(case_id, target_id)
    if case.status != "active":
        abort(409, "Состав участников закрытого дела не изменяется.")
    target = next((user for user in users if user.id == target_id), None)
    permission = request.form.get("permission")
    reason = change_reason()
    if target_id == case.owner_id or not target:
        abort(400, "Выберите следователя, который не является владельцем дела.")
    if permission not in {"viewer", "editor", "remove"}:
        abort(400, "Неизвестное разрешение.")
    member = db.session.scalar(select(CaseMember).where(CaseMember.case_id == case.id,
        CaseMember.user_id == target_id).with_for_update())
    old = member.permission if member else None
    if permission == "remove":
        responsible = db.session.scalar(select(Evidence.id).where(
            Evidence.case_id == case.id, Evidence.custodian_id == target_id).limit(1))
        pending = db.session.scalar(select(EvidenceTransfer.id).join(Evidence).where(
            Evidence.case_id == case.id, EvidenceTransfer.status == "pending",
            (EvidenceTransfer.from_user_id == target_id) | (EvidenceTransfer.to_user_id == target_id)).limit(1))
        if responsible is not None or pending is not None:
            abort(409, "Сначала передайте ответственность и завершите ожидающие передачи этого сотрудника.")
        if not member:
            abort(409, "Сотрудник уже не входит в состав участников.")
        db.session.delete(member)
        new = None
    else:
        if target.role != "investigator" or not target.is_active:
            abort(400, "Доступ нельзя назначить отключённому сотруднику.")
        if old == permission:
            flash("Разрешение уже установлено.", "info")
            return redirect(url_for("case_detail", case_id=case.id))
        if member:
            member.permission = permission
        else:
            db.session.add(CaseMember(case_id=case.id, user_id=target_id, permission=permission))
        new = permission
    append_event("CASE_ACCESS_CHANGED", f"Изменён доступ {target.name} к делу {case.case_number}. Основание: {reason}",
        case_id=case.id, details={"target_id": target.id, "target_name": target.name,
                                "before": old, "after": new, "reason": reason})
    case.updated_at = utc_now()
    db.session.commit()
    flash("Состав участников обновлён.", "success")
    return redirect(url_for("case_detail", case_id=case.id))
