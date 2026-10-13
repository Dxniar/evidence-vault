"""Case summaries and portable metadata manifests.

The manifest describes files; it neither retrieves their contents nor attests to
their legal origin or to a fresh integrity check.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from flask import Blueprint, g, render_template
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from models import AuditLog, Evidence, db, utc_now


def iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def export_filename(evidence_id: int, original_name: str) -> str:
    """Produce a portable single filename with an unambiguous evidence ID."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f\x7f-\x9f]', "_", original_name)
    name = name.strip().rstrip(". ") or "file"
    prefix = f"{evidence_id}_"
    # Unicode filenames must also fit common filesystems' 255-byte component
    # limit. Never truncate in the middle of a UTF-8 character.
    name = name.encode("utf-8")[:255 - len(prefix)].decode("utf-8", errors="ignore")
    name = name.rstrip(". ") or "file"
    return prefix + name


def transfer_metadata(transfer) -> dict:
    def person(user, user_id):
        return {"id": user_id, "name": user.name if user else None}

    return {
        "id": transfer.id,
        "status": transfer.status,
        "from": person(transfer.from_user, transfer.from_user_id),
        "to": person(transfer.to_user, transfer.to_user_id),
        "requested_by": person(transfer.requester, transfer.requested_by),
        "reason": transfer.reason,
        "requested_at": iso_utc(transfer.requested_at),
        "decided_at": iso_utc(transfer.decided_at),
    }


def evidence_metadata(evidence: Evidence, transfers: list) -> dict:
    return {
        "id": evidence.id,
        "original_name": evidence.original_name,
        "export_name": export_filename(evidence.id, evidence.original_name),
        "size_bytes": evidence.size_bytes,
        "sha256": evidence.sha256,
        "description": evidence.description,
        "uploaded_at": iso_utc(evidence.created_at),
        "source_details": {
            "source_label": evidence.source_label or None,
            "source_reference": evidence.source_reference or None,
            "acquisition_method": evidence.acquisition_method or None,
            "acquired_at": iso_utc(evidence.acquired_at),
            "source_sha256": evidence.source_sha256,
        },
        "custody": {
            "current_custodian": {
                "id": evidence.custodian_id,
                "name": evidence.custodian.name if evidence.custodian else None,
            },
            "transfers": [transfer_metadata(item) for item in transfers],
        },
        "integrity": {
            "status": evidence.current_integrity_status or "not_checked",
            "checked_at": iso_utc(evidence.integrity_checked_at),
            "checked_during_export": False,
        },
    }


def build_manifest(case, evidence_rows: list[Evidence], transfers: list, *, generated_at=None) -> dict:
    grouped: dict[int, list] = {}
    for transfer in transfers:
        grouped.setdefault(transfer.evidence_id, []).append(transfer)
    return {
        "format_version": 1,
        "case": {
            "id": case.id,
            "case_number": case.case_number,
            "title": case.title,
            "reference_number": case.reference_number or None,
            "status": case.status,
        },
        "generated_at": iso_utc(generated_at or utc_now()),
        "generated_by": {"id": g.user.id, "name": g.user.name},
        "evidence": [evidence_metadata(item, grouped.get(item.id, []))
                     for item in evidence_rows],
    }


def report_case_snapshot(case) -> dict:
    """Keep rendered fields independent of the session after the audit commit."""
    return {
        "id": case.id,
        "case_number": case.case_number,
        "reference_number": case.reference_number,
        "title": case.title,
        "status": case.status,
        "owner": {"name": case.owner.name},
        "created_at": case.created_at,
        "description": case.description,
    }


def report_event_snapshot(event: AuditLog) -> dict:
    return {
        "created_at": event.created_at,
        "name": event.name,
        "description": event.description,
        "event_type": event.event_type,
    }


def register_reports(app):
    # Import after the application module has finished loading; its factory and
    # the existing ACL helpers remain the single authority for access checks.
    from app import append_event, login_required, revalidate_case_access, visible_case
    from models import EvidenceTransfer

    blueprint = Blueprint("reports", __name__)

    def case_materials(case_id):
        evidence_rows = list(db.session.scalars(
            select(Evidence).options(joinedload(Evidence.custodian))
            .where(Evidence.case_id == case_id).order_by(Evidence.id)))
        transfers = list(db.session.scalars(
            select(EvidenceTransfer).join(Evidence)
            .options(joinedload(EvidenceTransfer.from_user),
                     joinedload(EvidenceTransfer.to_user),
                     joinedload(EvidenceTransfer.requester))
            .where(Evidence.case_id == case_id)
            .order_by(EvidenceTransfer.requested_at, EvidenceTransfer.id)))
        return evidence_rows, transfers

    @blueprint.get("/cases/<int:case_id>/report")
    @login_required
    def case_report(case_id):
        case = visible_case(case_id)
        evidence_rows, transfers = case_materials(case.id)
        generated_at = utc_now()
        manifest = build_manifest(case, evidence_rows, transfers, generated_at=generated_at)
        recent_events = list(db.session.scalars(
            select(AuditLog).options(joinedload(AuditLog.user)).where(AuditLog.case_id == case.id)
            .order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(501)))
        events_truncated = len(recent_events) > 500
        recent_events = recent_events[:500]
        revalidate_case_access(case)
        # The security event must be committed before sending the response.
        # Capture display values first: commit expires ORM instances, which
        # otherwise causes one database round trip for each history row.
        case_snapshot = report_case_snapshot(case)
        event_snapshots = [report_event_snapshot(event) for event in recent_events]
        append_event("CASE_REPORT_OPENED", f"Открыта служебная сводка {case.case_number}",
                     case_id=case.id)
        db.session.commit()
        return render_template("case_report.html", title="Служебная сводка", case=case_snapshot,
                               manifest=manifest, generated_at=generated_at,
                               recent_events=event_snapshots, events_truncated=events_truncated)

    @blueprint.get("/cases/<int:case_id>/manifest")
    @login_required
    def case_manifest(case_id):
        case = visible_case(case_id)
        evidence_rows, transfers = case_materials(case.id)
        manifest = build_manifest(case, evidence_rows, transfers)
        revalidate_case_access(case)
        append_event("MANIFEST_EXPORTED", f"Сформирован перечень материалов {case.case_number}",
                     case_id=case.id)
        db.session.commit()
        response = app.response_class(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                      mimetype="application/json")
        response.headers["Content-Disposition"] = f'attachment; filename="case-{case.id}-manifest.json"'
        return response

    app.register_blueprint(blueprint)
