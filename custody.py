"""Explicit, acknowledged changes of the employee responsible for an evidence item."""

from functools import wraps

from flask import Blueprint, abort, flash, g, redirect, request, session, url_for
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from models import Case, Evidence, EvidenceTransfer, User, db, utc_now


bp = Blueprint("custody", __name__)


def authenticated(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from app import login_required

        return login_required(view)(*args, **kwargs)

    return wrapped


def lock_evidence(evidence_id):
    """All custody writes use the same order as case closure and member changes."""
    from app import can_view_case

    initial = db.session.get(Evidence, evidence_id)
    if initial is None:
        abort(404)
    case_id = initial.case_id
    case = db.session.scalar(select(Case).where(Case.id == case_id).with_for_update()
                             .execution_options(populate_existing=True))
    if case is None or not can_view_case(case):
        abort(404)
    evidence = db.session.scalar(select(Evidence).where(Evidence.id == evidence_id).with_for_update()
                                 .execution_options(populate_existing=True))
    if evidence is None or evidence.case_id != case_id:
        abort(409, description="Доказательство изменилось. Обновите страницу.")
    return case, evidence


def lock_transfer(transfer_id):
    initial = db.session.get(EvidenceTransfer, transfer_id)
    if initial is None:
        abort(404)
    case, evidence = lock_evidence(initial.evidence_id)
    transfer = db.session.scalar(select(EvidenceTransfer).where(EvidenceTransfer.id == transfer_id)
                                 .with_for_update().execution_options(populate_existing=True))
    if transfer is None or transfer.evidence_id != evidence.id:
        abort(409, description="Передача изменилась. Обновите страницу.")
    return case, evidence, transfer


def lock_users(*user_ids):
    """Hold account rows until commit so a concurrent revocation cannot be missed."""
    users = db.session.scalars(select(User).where(User.id.in_(set(user_ids))).order_by(User.id)
                               .with_for_update().execution_options(populate_existing=True)).all()
    by_id = {user.id: user for user in users}
    actor = by_id.get(g.user.id)
    if (actor is None or not actor.is_active
            or not actor.totp_enabled or actor.session_version != session.get("session_version")):
        abort(403)
    g.user = actor
    return by_id


def valid_custodian(user, case):
    from app import can_view_case

    return (user is not None and user.is_active and user.role in {"admin", "investigator"}
            and can_view_case(case, user))


def require_active_case(case):
    if case.status != "active":
        abort(409, description="В закрытом деле передача недоступна.")


@bp.post("/evidence/<int:evidence_id>/transfer")
@authenticated
def request_transfer(evidence_id):
    from app import append_event

    case, evidence = lock_evidence(evidence_id)
    pending = db.session.scalar(select(EvidenceTransfer).where(
        EvidenceTransfer.evidence_id == evidence.id, EvidenceTransfer.status == "pending")
        .with_for_update().execution_options(populate_existing=True))
    recipient_id = request.form.get("to_user_id", type=int)
    reason = request.form.get("reason", "").strip()
    if recipient_id is None or not 3 <= len(reason) <= 1000:
        abort(400, description="Выберите получателя и укажите основание передачи (3–1000 символов).")
    users = lock_users(g.user.id, recipient_id)
    require_active_case(case)
    if (evidence.custodian_id != g.user.id or not valid_custodian(g.user, case)):
        abort(403)
    if recipient_id == g.user.id or not valid_custodian(users.get(recipient_id), case):
        abort(400, description="Получатель должен быть активным сотрудником с доступом к этому делу.")
    if pending is not None:
        abort(409, description="Для этого доказательства уже ожидается подтверждение передачи.")
    transfer = EvidenceTransfer(evidence_id=evidence.id, from_user_id=g.user.id,
                                to_user_id=recipient_id, requested_by=g.user.id,
                                status="pending", reason=reason)
    try:
        db.session.add(transfer)
        db.session.flush()
        case.updated_at = utc_now()
        append_event("CUSTODY_TRANSFER_REQUESTED", f"Передача доказательства #{evidence.id} сотруднику "
                     f"#{recipient_id}; основание: {reason}", case_id=case.id, evidence_id=evidence.id,
                     details={"transfer_id": transfer.id, "from_user_id": g.user.id,
                              "from_name": g.user.name, "to_user_id": recipient_id,
                              "to_name": users[recipient_id].name, "reason": reason})
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        abort(409, description="Передача уже создана. Обновите страницу.")
    flash("Передача создана. Ответственный изменится после подтверждения получателем.", "success")
    return redirect(url_for("case_detail", case_id=case.id))


@bp.post("/transfers/<int:transfer_id>/accept")
@authenticated
def accept_transfer(transfer_id):
    from app import append_event

    case, evidence, transfer = lock_transfer(transfer_id)
    users = lock_users(g.user.id, transfer.from_user_id, transfer.to_user_id)
    require_active_case(case)
    if g.user.id != transfer.to_user_id or not valid_custodian(g.user, case):
        abort(403)
    if transfer.status != "pending" or evidence.custodian_id != transfer.from_user_id:
        abort(409, description="Эту передачу уже завершили либо изменился ответственный.")
    if not valid_custodian(users.get(transfer.from_user_id), case):
        abort(409, description="Отправитель больше не имеет полномочий по этому делу. Отмените передачу.")
    decided_at = utc_now()
    result = db.session.execute(update(EvidenceTransfer).where(
        EvidenceTransfer.id == transfer.id, EvidenceTransfer.status == "pending",
        EvidenceTransfer.from_user_id == evidence.custodian_id,
        EvidenceTransfer.to_user_id == g.user.id).values(status="accepted", decided_at=decided_at)
        .execution_options(synchronize_session="fetch"))
    evidence_result = db.session.execute(update(Evidence).where(
        Evidence.id == evidence.id, Evidence.custodian_id == transfer.from_user_id)
        .values(custodian_id=g.user.id).execution_options(synchronize_session="fetch"))
    if result.rowcount != 1 or evidence_result.rowcount != 1:
        db.session.rollback()
        abort(409, description="Другой сотрудник уже изменил состояние передачи.")
    case.updated_at = decided_at
    append_event("CUSTODY_TRANSFER_ACCEPTED", f"Подтверждена передача #{transfer.id} доказательства "
                 f"#{evidence.id}: от сотрудника #{transfer.from_user_id} сотруднику #{g.user.id}",
                 "success", case_id=case.id, evidence_id=evidence.id)
    db.session.commit()
    flash("Передача подтверждена. Вы назначены ответственным за доказательство.", "success")
    return redirect(url_for("case_detail", case_id=case.id))


@bp.post("/transfers/<int:transfer_id>/cancel")
@authenticated
def cancel_transfer(transfer_id):
    from app import append_event, can_manage_case, can_view_case

    case, evidence, transfer = lock_transfer(transfer_id)
    lock_users(g.user.id)
    if not can_view_case(case):
        abort(404)
    if g.user.id != transfer.from_user_id and not can_manage_case(case):
        abort(403)
    if transfer.status != "pending":
        abort(409, description="Эту передачу уже завершили.")
    decided_at = utc_now()
    result = db.session.execute(update(EvidenceTransfer).where(
        EvidenceTransfer.id == transfer.id, EvidenceTransfer.status == "pending")
        .values(status="cancelled", decided_at=decided_at).execution_options(synchronize_session="fetch"))
    if result.rowcount != 1:
        db.session.rollback()
        abort(409, description="Другой сотрудник уже изменил состояние передачи.")
    case.updated_at = decided_at
    append_event("CUSTODY_TRANSFER_CANCELLED", f"Отменена передача #{transfer.id} доказательства "
                 f"#{evidence.id}; ответственный сохранён", case_id=case.id, evidence_id=evidence.id)
    db.session.commit()
    flash("Передача отменена. Ответственный не изменён.", "success")
    return redirect(url_for("case_detail", case_id=case.id))
