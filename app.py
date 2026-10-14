from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import secrets
import uuid
from time import monotonic
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
import pyotp
import qrcode
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, current_app, flash, g, redirect, render_template,
                   request, send_file, session, url_for)
from flask_migrate import Migrate
from joserfc.errors import JoseError
from requests.exceptions import RequestException
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import contains_eager, joinedload
from werkzeug.exceptions import SecurityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from models import AuditLog, Case, CaseMember, Evidence, EvidenceTransfer, User, db, utc_now
from audit_logging import configure_application_logging
from storage import StorageError, StorageIntegrityError, StorageNotFound, SupabaseStorage, storage_deadline

ROLES = {"admin": "Администратор", "investigator": "Следователь", "auditor": "Аудитор"}
ALLOWED_EXTENSIONS = {"txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "json", "xml",
                      "jpg", "jpeg", "png", "gif", "webp", "zip", "7z", "log", "eml"}
MAX_EVIDENCE_FILE_SIZE = 16 * 1024 * 1024
MAX_UPLOAD_SIZE = 64 * 1024 * 1024
MAX_FILES_PER_UPLOAD = 20
AUTH_ATTEMPT_LIMIT = 5
LOCK_SECONDS = 300
GOOGLE_INVITE_LIFETIME = timedelta(days=7)
# These GET views only read the database. File delivery and reports also write
# audit events and must retain their normal transactional sessions.
READ_ONLY_PAGE_ENDPOINTS = frozenset({
    "index", "login", "dashboard", "cases", "case_detail", "audit", "account", "admin_users",
})
migrate = Migrate()


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("EVIDENCE_VAULT_SECRET"),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        APP_LOG_LEVEL=os.environ.get("APP_LOG_LEVEL", "INFO"),
        READ_PAGE_AUTOCOMMIT=True,
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True, "pool_size": 5, "max_overflow": 5,
                                   "pool_recycle": 1800, "pool_timeout": 3,
                                   "connect_args": {"sslmode": "require", "connect_timeout": 3}},
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_SIZE, MAX_FORM_MEMORY_SIZE=1024 * 1024,
        TRUSTED_HOSTS=[h.strip() for h in os.environ.get("APP_ALLOWED_HOSTS", "").split(",") if h.strip()],
        GOOGLE_OAUTH_CLIENT_ID=os.environ.get("GOOGLE_OAUTH_CLIENT_ID", ""),
        GOOGLE_OAUTH_CLIENT_SECRET=os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", ""),
        DISPLAY_TIMEZONE_OFFSET_HOURS=int(os.environ.get("DISPLAY_TIMEZONE_OFFSET_HOURS", "5")),
    )
    if test_config is not None:
        app.config.update(test_config)
    else:
        required = ("EVIDENCE_VAULT_SECRET", "DATABASE_URL", "SUPABASE_URL",
                    "SUPABASE_STORAGE_BUCKET", "APP_ALLOWED_HOSTS")
        missing = [name for name in required if not os.environ.get(name)]
        if not (os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")):
            missing.append("SUPABASE_SECRET_KEY")
        if missing:
            raise RuntimeError("Не заданы обязательные переменные: " + ", ".join(missing))
        if len(app.config["SECRET_KEY"]) < 32:
            raise RuntimeError("EVIDENCE_VAULT_SECRET должен содержать не менее 32 символов.")
        url = app.config["SQLALCHEMY_DATABASE_URI"]
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        if not url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise RuntimeError("DATABASE_URL должен указывать на PostgreSQL в Supabase.")
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://"):]
        app.config["SQLALCHEMY_DATABASE_URI"] = url
    if not -12 <= app.config["DISPLAY_TIMEZONE_OFFSET_HOURS"] <= 14:
        raise RuntimeError("DISPLAY_TIMEZONE_OFFSET_HOURS должен быть от -12 до 14.")
    if bool(app.config["GOOGLE_OAUTH_CLIENT_ID"]) != bool(app.config["GOOGLE_OAUTH_CLIENT_SECRET"]):
        raise RuntimeError("Для входа через Google задайте оба значения GOOGLE_OAUTH_CLIENT_ID и GOOGLE_OAUTH_CLIENT_SECRET.")
    configure_application_logging(app)
    db.init_app(app)
    migrate.init_app(app, db)
    app.extensions["evidence_google_oauth"] = None
    if app.config["GOOGLE_OAUTH_CLIENT_ID"]:
        oauth = OAuth(app)
        app.extensions["evidence_google_oauth"] = oauth.register(
            "google", client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
            client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email", "code_challenge_method": "S256"})
    app.extensions["evidence_storage"] = (
        app.config["STORAGE"] if "STORAGE" in app.config else SupabaseStorage(
            os.environ["SUPABASE_URL"],
            os.environ.get("SUPABASE_SECRET_KEY") or os.environ["SUPABASE_SERVICE_ROLE_KEY"],
            os.environ["SUPABASE_STORAGE_BUCKET"]))
    asset_versions = {
        filename: hashlib.sha256((Path(app.static_folder) / filename).read_bytes()).hexdigest()[:12]
        for filename in ("style.css", "theme.js", "app.js", "favicon.svg")
    }
    if test_config is None:
        count = int(os.environ.get("TRUST_PROXY_COUNT", "0"))
        if not 0 <= count <= 3:
            raise RuntimeError("TRUST_PROXY_COUNT должен быть от 0 до 3.")
        if count:
            app.wsgi_app = ProxyFix(app.wsgi_app, x_for=count, x_proto=count, x_host=count)

    @app.before_request
    def load_user_and_check_csrf():
        g.request_id = secrets.token_hex(8)
        g.user = None
        if request.endpoint == "static" and request.method in {"GET", "HEAD", "OPTIONS"}:
            return
        if request.endpoint in {"healthz", "operations.readyz"} and request.method == "GET":
            return
        user_id = session.get("user_id")
        if user_id:
            if (app.config["READ_PAGE_AUTOCOMMIT"] and request.method == "GET"
                    and request.endpoint in READ_ONLY_PAGE_ENDPOINTS
                    and db.engine.dialect.name == "postgresql"):
                # Keep authentication fresh without a BEGIN/ROLLBACK network
                # round trip for pages that perform no database writes.
                db.session.connection(execution_options={"isolation_level": "AUTOCOMMIT"})
            user = db.session.get(User, user_id)
            if session_matches_user(user):
                g.user = user
            else:
                session.clear()
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            expected, received = session.get("csrf_token", ""), request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected, received):
                abort(400, "Проверка формы не пройдена. Обновите страницу и повторите действие.")
        if g.user and g.user.must_change_password and request.endpoint not in {
                "account", "change_password", "setup_account_2fa", "logout", "static"}:
            return redirect(url_for("account"))

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = getattr(g, "request_id", secrets.token_hex(8))
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Chromium checks form-action against the redirect after an OAuth form POST.
        # Permit only Google's authorization origin on the two pages that start it.
        form_action = "form-action 'self'"
        if request.endpoint in {"login", "account"} and google_client() is not None:
            form_action += " https://accounts.google.com"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            f"object-src 'none'; base-uri 'none'; {form_action}; frame-ancestors 'none'")
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        else:
            version = asset_versions.get((request.view_args or {}).get("filename"))
            if version and request.args.get("v") == version and response.status_code in {200, 304}:
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response

    @app.context_processor
    def inject_helpers():
        return {"csrf_token": generate_csrf_token, "format_size": format_size,
                "format_datetime": format_datetime, "role_label": lambda role: ROLES.get(role, role),
                "plural": plural, "asset_url": lambda filename: url_for(
                    "static", filename=filename, v=asset_versions.get(filename)),
                "display_timezone": f"UTC{app.config['DISPLAY_TIMEZONE_OFFSET_HOURS']:+03d}:00"}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return redirect(url_for("account" if g.user and g.user.must_change_password
                                else "dashboard" if g.user else "login"))

    @app.route("/register", methods=("GET", "POST"))
    def register():
        abort(404)

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if g.user:
            return redirect(url_for("account" if g.user.must_change_password else "dashboard"))
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = db.session.scalar(select(User).where(User.email == email))
            if user and user.is_active and user.locked_until and as_utc(user.locked_until) > utc_now():
                flash("Аккаунт временно заблокирован. Попробуйте позже.", "danger")
            elif (not user or not user.is_active or not user.has_local_password
                  or not check_password_hash(user.password_hash, request.form.get("password", ""))):
                if user and user.is_active and user.has_local_password:
                    fail_auth(user, "LOGIN_FAILED", "Неудачная попытка входа по паролю")
                flash("Неверная почта или пароль.", "danger")
            else:
                session.clear()
                session["csrf_token"] = secrets.token_urlsafe(32)
                session["preauth_user_id"] = user.id
                session["preauth_version"] = user.session_version
                return redirect(url_for("verify_2fa" if user.totp_enabled else "setup_2fa"))
        return render_template("login.html", title="Вход", google_enabled=google_client() is not None)

    @app.post("/auth/google")
    def google_login():
        client = google_client()
        if client is None:
            abort(404)
        if g.user:
            return redirect(url_for("account" if g.user.must_change_password else "dashboard"))
        session.clear()
        session["google_flow"] = "login"
        try:
            return client.authorize_redirect(
                url_for("google_callback", _external=True), prompt="select_account")
        except (OAuthError, RequestException, ValueError) as exc:
            app.logger.warning("Google sign-in could not start: %s", type(exc).__name__)
            clear_google_flow()
            flash("Google сейчас недоступен. Попробуйте позже.", "danger")
            return redirect(url_for("login"))

    @app.get("/auth/google/callback")
    def google_callback():
        client = google_client()
        if client is None:
            abort(404)
        flow = session.get("google_flow")
        if flow not in {"login", "link"}:
            flash("Сеанс входа через Google истёк. Попробуйте ещё раз.", "danger")
            return redirect(url_for("login"))
        try:
            # Authlib checks OAuth state and validates the signed OIDC ID token,
            # including its issuer, audience, expiry and nonce.
            token = client.authorize_access_token()
        except (OAuthError, RequestException, JoseError, ValueError) as exc:
            app.logger.warning("Google sign-in failed: %s", type(exc).__name__)
            clear_google_flow()
            flash("Не удалось подтвердить вход через Google. Попробуйте ещё раз.", "danger")
            return redirect(url_for("account" if g.user else "login"))
        claims = token.get("userinfo")
        sub = claims.get("sub") if claims else None
        email = claims.get("email") if claims else None
        if (not isinstance(sub, str) or not 1 <= len(sub) <= 255 or not sub.isascii()
                or not isinstance(email, str) or not email.strip()
                or (claims.get("email_verified") is not True
                    and claims.get("email_verified") != "true")):
            clear_google_flow()
            flash("Google не подтвердил данные аккаунта. Вход отклонён.", "danger")
            return redirect(url_for("account" if g.user else "login"))

        flow = session.pop("google_flow")
        if flow == "link":
            user_id = session.pop("google_link_user_id", None)
            version = session.pop("google_link_version", None)
            if not g.user or g.user.id != user_id or g.user.session_version != version:
                flash("Сеанс привязки истёк. Войдите снова.", "danger")
                return redirect(url_for("login"))
            if email.strip().lower() != g.user.email:
                flash("Почта Google должна совпадать с почтой в профиле Evidence Vault.", "danger")
                return redirect(url_for("account"))
            bound = db.session.scalar(select(User).where(User.google_sub == sub))
            if bound and bound.id != g.user.id:
                flash("Этот Google-аккаунт уже привязан к другому пользователю.", "danger")
                return redirect(url_for("account"))
            if g.user.google_sub and g.user.google_sub != sub:
                flash("Сначала отключите прежний Google-аккаунт в профиле.", "danger")
                return redirect(url_for("account"))
            if g.user.google_sub == sub:
                flash("Этот Google-аккаунт уже подключён.", "success")
                return redirect(url_for("account"))
            g.user.google_sub = sub
            g.user.session_version += 1
            append_event("GOOGLE_LINKED", "Google-аккаунт подключён к профилю", "success")
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("Этот Google-аккаунт уже привязан к другому пользователю.", "danger")
                return redirect(url_for("account"))
            start_session(g.user)
            flash("Google-аккаунт подключён. Теперь вы можете входить через Google.", "success")
            return redirect(url_for("account"))

        clear_google_flow()
        user = db.session.scalar(select(User).where(User.google_sub == sub))
        if user is None:
            # The admin preapproves an exact email and role. A verified Google
            # identity can claim only an active, unexpired passwordless invite.
            invited = db.session.scalar(select(User).where(
                User.email == email.strip().lower(), User.google_sub.is_(None),
                User.has_local_password.is_(False), User.is_active.is_(True))
                .with_for_update())
            if invited and invited.google_invite_expires_at and as_utc(invited.google_invite_expires_at) > utc_now():
                if not invited.locked_until or as_utc(invited.locked_until) <= utc_now():
                    invited.google_sub = sub
                    invited.google_invite_expires_at = None
                    append_event("GOOGLE_INVITE_ACCEPTED", "Принято приглашение через Google", "success", invited.id)
                    try:
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
                    else:
                        user = invited
        if not user or not user.is_active or (user.locked_until and as_utc(user.locked_until) > utc_now()):
            append_event("GOOGLE_LOGIN_DENIED", "Вход через непривязанный или недоступный Google-аккаунт",
                         "warning", user.id if user else None)
            db.session.commit()
            session.clear()
            flash("Нет доступа. Попросите администратора выдать доступ или подключите Google в профиле.", "danger")
            return redirect(url_for("login"))
        if user.role == "investigator":
            user.last_login = utc_now()
            user.failed_attempts = 0
            user.locked_until = None
            append_event("GOOGLE_LOGIN_SUCCESS", "Успешный вход через Google", "success", user.id,
                         details={"auth_method": "google", "local_totp_required": False})
            db.session.commit()
            start_session(user, auth_method="google")
            return redirect(url_for("account" if user.must_change_password else "dashboard"))
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["preauth_user_id"] = user.id
        session["preauth_version"] = user.session_version
        session["preauth_method"] = "google"
        return redirect(url_for("verify_2fa" if user.totp_enabled else "setup_2fa"))

    @app.route("/setup-2fa", methods=("GET", "POST"))
    def setup_2fa():
        user = preauth_user()
        if not user or user.totp_enabled:
            return redirect(url_for("login"))
        if request.method == "POST":
            step = matching_totp_step(user.totp_secret, request.form.get("code", ""))
            if step is not None:
                result = db.session.execute(update(User).where(
                    User.id == user.id, User.is_active.is_(True), User.totp_enabled.is_(False),
                    User.session_version == session["preauth_version"])
                    .where((User.locked_until.is_(None)) | (User.locked_until <= utc_now()))
                    .where((User.last_totp_step.is_(None)) | (User.last_totp_step < step))
                    .values(totp_enabled=True, last_totp_step=step, failed_attempts=0,
                            locked_until=None, last_login=utc_now()))
            else:
                result = None
            if result is not None and result.rowcount == 1:
                append_event("2FA_ENABLED", "Подключена двухфакторная аутентификация", "success", user.id)
                if session.get("preauth_method") == "google":
                    append_event("GOOGLE_LOGIN_SUCCESS", "Успешный вход через Google и TOTP", "success", user.id)
                db.session.commit()
                start_session(user)
                flash("Двухфакторная защита подключена.", "success")
                return redirect(url_for("account" if user.must_change_password else "dashboard"))
            fail_auth(user, "2FA_FAILED", "Неверный код при подключении 2FA")
            if (user.totp_enabled or not user.is_active
                    or user.session_version != session.get("preauth_version")):
                session.clear()
                flash("Сеанс настройки 2FA завершён. Войдите снова.", "warning")
                return redirect(url_for("login"))
            if "preauth_user_id" not in session:
                flash("Слишком много попыток. Войдите снова через пять минут.", "danger")
                return redirect(url_for("login"))
            flash("Код не подошёл. Проверьте время на телефоне.", "danger")
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name="Evidence Vault")
        image_buffer = io.BytesIO()
        qrcode.make(uri).save(image_buffer, format="PNG")
        return render_template("setup_2fa.html", title="Подключение 2FA", user=user,
                               qr_data=base64.b64encode(image_buffer.getvalue()).decode("ascii"),
                               secret=user.totp_secret)

    @app.route("/verify-2fa", methods=("GET", "POST"))
    def verify_2fa():
        user = preauth_user()
        if not user or not user.totp_enabled:
            return redirect(url_for("login"))
        if request.method == "POST":
            step = matching_totp_step(user.totp_secret, request.form.get("code", ""))
            if step is not None:
                result = db.session.execute(update(User).where(User.id == user.id, User.is_active.is_(True),
                    User.session_version == session["preauth_version"])
                    .where((User.locked_until.is_(None)) | (User.locked_until <= utc_now()))
                    .where((User.last_totp_step.is_(None)) | (User.last_totp_step < step))
                    .values(last_totp_step=step, failed_attempts=0, locked_until=None, last_login=utc_now()))
                if result.rowcount == 1:
                    if session.get("preauth_method") == "google":
                        append_event("GOOGLE_LOGIN_SUCCESS", "Успешный вход через Google и TOTP", "success", user.id)
                    else:
                        append_event("LOGIN_SUCCESS", "Успешный вход с двухфакторной проверкой", "success", user.id)
                    db.session.commit()
                    start_session(user)
                    return redirect(url_for("account" if user.must_change_password else "dashboard"))
            fail_auth(user, "2FA_FAILED", "Неверный или повторно использованный код 2FA")
            if "preauth_user_id" not in session:
                flash("Слишком много попыток. Войдите снова через пять минут.", "danger")
                return redirect(url_for("login"))
            flash("Неверный или уже использованный код.", "danger")
        return render_template("verify_2fa.html", title="Проверка кода", user=user)

    @app.post("/logout")
    @login_required
    def logout():
        db.session.execute(update(User).where(User.id == g.user.id)
                           .values(session_version=User.session_version + 1))
        append_event("LOGOUT", "Пользователь завершил все свои сеансы", user_id=g.user.id)
        db.session.commit()
        session.clear()
        flash("Вы вышли из системы. Все ваши сеансы завершены.", "success")
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        visible = case_visibility_filter()
        case_count_query = select(func.count(Case.id)).where(visible).correlate(None).scalar_subquery()
        counts = db.session.execute(select(
            case_count_query.label("case_count"),
            func.count(Evidence.id).label("evidence_count"),
            func.count(Evidence.id).filter(
                func.coalesce(Evidence.observed_integrity_status, Evidence.integrity_status) == "verified",
                func.coalesce(Evidence.observed_integrity_at, Evidence.last_verified_at).is_not(None)
            ).label("verified_count")
        ).select_from(Evidence).join(Case).where(visible)).one()
        recent_cases = db.session.scalars(select(Case).where(visible).order_by(Case.created_at.desc()).limit(5)).all()
        logs = select(AuditLog).order_by(AuditLog.id.desc()).limit(6)
        logs = logs.where(audit_visibility_filter())
        return render_template("dashboard.html", title="Обзор", case_count=counts.case_count,
                               evidence_count=counts.evidence_count, verified_count=counts.verified_count,
                               recent_cases=recent_cases, recent_logs=db.session.scalars(logs).all())

    @app.route("/cases", methods=("GET", "POST"))
    @login_required
    def cases():
        if request.method == "POST":
            if g.user.role == "auditor":
                abort(403)
            source = parse_source_details()
            source_files = [item for item in request.files.getlist("files") if item and item.filename]
            if source["source_sha256"] and len(source_files) != 1:
                abort(400, "Исходную SHA-256 можно указать только для одного файла.")
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            priority = request.form.get("priority", "normal")
            reference = request.form.get("reference_number", "").strip()
            if not 3 <= len(title) <= 120 or len(description) > 5000 or len(reference) > 80 or priority not in {"low", "normal", "high"}:
                flash("Проверьте название (3–120 символов), описание и приоритет.", "danger")
            else:
                case = Case(case_number=f"EV-{utc_now().year}-{secrets.token_hex(6).upper()}",
                            title=title, description=description, reference_number=reference,
                            priority=priority, owner_id=g.user.id)
                db.session.add(case)
                db.session.flush()
                append_event("CASE_CREATED", f"Создано расследование {case.case_number}: {title}", "success", case_id=case.id)
                db.session.commit()
                store_uploaded_files(case, request.files.getlist("files"), "")
                flash(f"Расследование {case.case_number} создано.", "success")
                return redirect(url_for("case_detail", case_id=case.id))
        query = (select(Case, func.count(Evidence.id).label("evidence_count"))
                 .outerjoin(Evidence).group_by(Case.id).order_by(Case.created_at.desc()))
        query = query.where(case_visibility_filter())
        search = request.args.get("q", "").strip()[:200]
        selected_status = request.args.get("status", "all")
        if search:
            pattern = "%" + escape_search(search) + "%"
            query = query.where(or_(Case.title.ilike(pattern, escape="\\"),
                Case.case_number.ilike(pattern, escape="\\"), Case.reference_number.ilike(pattern, escape="\\")))
        if selected_status in {"active", "closed"}:
            query = query.where(Case.status == selected_status)
        page = max(1, request.args.get("page", 1, type=int))
        rows = db.session.execute(query.limit(51).offset((page - 1) * 50)).all()
        case_rows = []
        for case, count in rows[:50]:
            case.evidence_count = count
            case_rows.append(case)
        return render_template("cases.html", title="Расследования", cases=case_rows, page=page,
                               has_next=len(rows) > 50, q=search, selected_status=selected_status)

    @app.get("/cases/<int:case_id>")
    @login_required
    def case_detail(case_id: int):
        case = visible_case(case_id, options=(joinedload(Case.owner),))
        evidence_rows = db.session.scalars(select(Evidence).options(joinedload(Evidence.custodian))
                                           .where(Evidence.case_id == case_id)
                                           .order_by(Evidence.created_at.desc())).all()
        members = db.session.scalars(select(CaseMember).options(joinedload(CaseMember.user))
                                     .where(CaseMember.case_id == case_id)
                                     .order_by(CaseMember.created_at)).all()
        pending = db.session.scalars(select(EvidenceTransfer).join(Evidence)
            .options(joinedload(EvidenceTransfer.from_user), joinedload(EvidenceTransfer.to_user))
            .where(Evidence.case_id == case_id, EvidenceTransfer.status == "pending")).all()
        timeline = db.session.scalars(select(AuditLog).options(joinedload(AuditLog.user))
            .where(AuditLog.case_id == case_id)
            .order_by(AuditLog.id.desc()).limit(50)).all()
        can_manage = can_manage_case(case)
        can_edit = can_manage or (g.user.role == "investigator" and any(
            member.user_id == g.user.id and member.permission == "editor" for member in members))
        member_ids = {member.user_id for member in members}
        transfers_by_evidence = {transfer.evidence_id: transfer for transfer in pending}
        candidates = []
        can_transfer = g.user.role in {"admin", "investigator"} and any(
            item.custodian_id == g.user.id and item.id not in transfers_by_evidence for item in evidence_rows)
        if case.status == "active" and (can_manage or can_transfer):
            candidates_query = select(User).where(User.is_active.is_(True),
                User.role.in_(["investigator", "admin"]))
            if not can_manage:
                candidates_query = candidates_query.where(or_(
                    User.role == "admin", User.id == case.owner_id, User.id.in_(member_ids)))
            candidates = db.session.scalars(candidates_query.order_by(User.name)).all()
        return render_template("case_detail.html", title=case.case_number, case=case,
            evidence_rows=evidence_rows, members=members,
            can_manage=can_manage, can_edit=can_edit,
            eligible_members=[user for user in candidates if can_manage and user.role == "investigator" and user.id != case.owner_id],
            eligible_custodians=[user for user in candidates if
                user.role == "admin" or user.id == case.owner_id or user.id in member_ids],
            transfers_by_evidence=transfers_by_evidence,
            case_events=timeline)

    @app.post("/cases/<int:case_id>/upload")
    @login_required
    def upload_evidence(case_id: int):
        case = editable_case(case_id)
        uploaded_files = request.files.getlist("files")
        if not any(item and item.filename for item in uploaded_files):
            flash("Выберите один или несколько файлов для загрузки.", "danger")
        else:
            store_uploaded_files(case, uploaded_files, request.form.get("description", "").strip()[:5000])
        return redirect(url_for("case_detail", case_id=case_id))

    @app.post("/evidence/<int:evidence_id>/verify")
    @login_required
    def verify_evidence(evidence_id: int):
        evidence = visible_evidence(evidence_id)
        editable_case(evidence.case_id, allow_closed=True)
        status = check_integrity(evidence)
        revalidate_case_access(evidence.case, require_edit=True)
        record_integrity_observation(evidence, status, update_status=True)
        append_event("INTEGRITY_CHECK", f"Проверка файла {evidence.original_name}: {status}",
                     "success" if status == "verified" else "danger", case_id=evidence.case_id, evidence_id=evidence.id)
        db.session.commit()
        flash("Целостность подтверждена." if status == "verified" else "Нарушена целостность или файл отсутствует.",
              "success" if status == "verified" else "danger")
        return redirect(url_for("case_detail", case_id=evidence.case_id))

    @app.post("/evidence/<int:evidence_id>/check")
    @login_required
    def check_evidence(evidence_id: int):
        evidence = visible_evidence(evidence_id)
        status = check_integrity(evidence)
        revalidate_case_access(evidence.case)
        record_integrity_observation(evidence, status)
        append_event("AUDITOR_INTEGRITY_CHECK", f"Проверка файла {evidence.original_name}: {status}",
                     "success" if status == "verified" else "danger", case_id=evidence.case_id, evidence_id=evidence.id)
        db.session.commit()
        flash("SHA-256 совпадает с сохранённым значением." if status == "verified" else
              "SHA-256 не совпадает или файл отсутствует.", "success" if status == "verified" else "danger")
        return redirect(url_for("case_detail", case_id=evidence.case_id))

    @app.get("/evidence/<int:evidence_id>/download")
    @login_required
    def download_evidence(evidence_id: int):
        evidence = visible_evidence(evidence_id)
        try:
            with storage_deadline(monotonic() + 60):
                content = storage().download(evidence.stored_name, MAX_EVIDENCE_FILE_SIZE)
        except StorageNotFound:
            record_integrity_observation(evidence, "missing")
            append_event("DOWNLOAD_BLOCKED", f"Файл #{evidence.id} отсутствует: {evidence.original_name}", "danger",
                         case_id=evidence.case_id, evidence_id=evidence.id)
            db.session.commit()
            abort(404)
        except StorageIntegrityError:
            record_integrity_observation(evidence, "modified")
            append_event("DOWNLOAD_BLOCKED", f"Размер файла #{evidence.id} превышен: {evidence.original_name}", "danger",
                         case_id=evidence.case_id, evidence_id=evidence.id)
            db.session.commit()
            abort(409)
        if len(content) != evidence.size_bytes or not secrets.compare_digest(
                hashlib.sha256(content).hexdigest(), evidence.sha256):
            record_integrity_observation(evidence, "modified")
            append_event("DOWNLOAD_BLOCKED", f"Нарушена целостность файла {evidence.original_name}", "danger",
                         case_id=evidence.case_id, evidence_id=evidence.id)
            db.session.commit()
            abort(409)
        revalidate_case_access(evidence.case)
        record_integrity_observation(evidence, "verified")
        append_event("EVIDENCE_DOWNLOADED", f"Подготовлена выдача файла {evidence.original_name}",
                     case_id=evidence.case_id, evidence_id=evidence.id)
        db.session.commit()
        from reports import export_filename
        return send_file(io.BytesIO(content), mimetype="application/octet-stream", as_attachment=True,
                         download_name=export_filename(evidence.id, evidence.original_name), max_age=0)

    @app.get("/audit")
    @login_required
    def audit():
        selected = request.args.get("severity", "all")
        query = (select(AuditLog).outerjoin(User, AuditLog.user_id == User.id)
                 .options(contains_eager(AuditLog.user)).where(audit_visibility_filter()).order_by(AuditLog.id.desc()))
        search = request.args.get("q", "").strip()[:200]
        if search:
            pattern = "%" + escape_search(search) + "%"
            query = query.where(or_(AuditLog.description.ilike(pattern, escape="\\"),
                AuditLog.event_type.ilike(pattern, escape="\\"),
                func.coalesce(AuditLog.actor_name, User.name).ilike(pattern, escape="\\"),
                func.coalesce(AuditLog.actor_email, User.email).ilike(pattern, escape="\\")))
        if selected in {"info", "success", "warning", "danger"}:
            query = query.where(AuditLog.severity == selected)
        page = max(1, request.args.get("page", 1, type=int))
        rows = db.session.scalars(query.limit(51).offset((page - 1) * 50)).all()
        return render_template("audit.html", title="Журнал безопасности", logs=rows[:50],
                               selected_severity=selected, q=search, page=page, has_next=len(rows) > 50)

    @app.get("/account")
    @login_required
    def account():
        return render_template("account.html", title="Профиль", google_enabled=google_client() is not None)

    @app.post("/account/2fa/setup")
    @login_required
    def setup_account_2fa():
        if g.user.totp_enabled:
            return redirect(url_for("account"))
        user = g.user
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["preauth_user_id"] = user.id
        session["preauth_version"] = user.session_version
        session["preauth_method"] = "google"
        return redirect(url_for("setup_2fa"))

    @app.post("/account/password")
    @login_required
    def change_password():
        new_password = request.form.get("new_password", "")
        if not password_is_valid(new_password) or new_password != request.form.get("confirm_password", ""):
            flash("Новый пароль: минимум 12 символов, разные регистры, цифра и совпадающее подтверждение.", "danger")
            return redirect(url_for("account"))
        require_sensitive_confirmation()
        if g.user.has_local_password:
            if not check_password_hash(g.user.password_hash, request.form.get("current_password", "")):
                fail_auth(g.user, "PASSWORD_CHANGE_DENIED", "Неверный текущий пароль")
                flash("Неверный текущий пароль.", "danger")
                return redirect(url_for("account"))
            if check_password_hash(g.user.password_hash, new_password):
                flash("Новый пароль должен отличаться от текущего.", "danger")
                return redirect(url_for("account"))
        else:
            step = matching_totp_step(g.user.totp_secret, request.form.get("code", ""))
            if step is None or (g.user.last_totp_step is not None and step <= g.user.last_totp_step):
                fail_auth(g.user, "PASSWORD_CHANGE_DENIED", "Неверный или повторный код 2FA")
                flash("Введите новый код 2FA, который ещё не использовали для входа.", "danger")
                return redirect(url_for("account"))
            g.user.last_totp_step = step
        g.user.password_hash = generate_password_hash(new_password)
        g.user.has_local_password = True
        g.user.must_change_password = False
        g.user.failed_attempts = 0
        g.user.locked_until = None
        g.user.session_version += 1
        append_event("PASSWORD_CHANGED", "Пароль обновлён, прежние сеансы завершены", "success")
        db.session.commit()
        start_session(g.user, auth_method=session.get("auth_method", "totp"))
        flash("Пароль сохранён. Предыдущие сеансы завершены.", "success")
        return redirect(url_for("account"))

    @app.post("/account/google/connect")
    @login_required
    def connect_google():
        client = google_client()
        if client is None:
            abort(404)
        if g.user.google_sub:
            flash("Google-аккаунт уже подключён. Сначала отключите его.", "warning")
            return redirect(url_for("account"))
        require_sensitive_confirmation()
        if not check_password_hash(g.user.password_hash, request.form.get("password", "")):
            fail_auth(g.user, "GOOGLE_LINK_DENIED", "Неверный пароль при подключении Google")
            flash("Неверный пароль.", "danger")
            return redirect(url_for("account"))
        g.user.failed_attempts = 0
        db.session.commit()
        session["google_flow"] = "link"
        session["google_link_user_id"] = g.user.id
        session["google_link_version"] = g.user.session_version
        try:
            return client.authorize_redirect(
                url_for("google_callback", _external=True), prompt="select_account")
        except (OAuthError, RequestException, ValueError) as exc:
            app.logger.warning("Google account linking could not start: %s", type(exc).__name__)
            clear_google_flow()
            flash("Google сейчас недоступен. Попробуйте позже.", "danger")
            return redirect(url_for("account"))

    @app.post("/account/google/disconnect")
    @login_required
    def disconnect_google():
        if not g.user.google_sub:
            return redirect(url_for("account"))
        require_sensitive_confirmation()
        if not g.user.has_local_password:
            flash("Сначала создайте пароль в профиле, чтобы сохранить доступ после отключения Google.", "danger")
            return redirect(url_for("account"))
        if not check_password_hash(g.user.password_hash, request.form.get("password", "")):
            fail_auth(g.user, "GOOGLE_UNLINK_DENIED", "Неверный пароль при отключении Google")
            flash("Неверный пароль.", "danger")
            return redirect(url_for("account"))
        g.user.google_sub = None
        g.user.failed_attempts = 0
        g.user.session_version += 1
        append_event("GOOGLE_UNLINKED", "Google-аккаунт отключён от профиля", "warning")
        db.session.commit()
        if session.get("auth_method") == "google":
            session.clear()
            g.user = None
            flash("Google отключён. Войдите по паролю и подтвердите код TOTP.", "success")
            return redirect(url_for("login"))
        start_session(g.user)
        flash("Google-аккаунт отключён. Вход по паролю и TOTP доступен.", "success")
        return redirect(url_for("account"))

    @app.route("/admin/users", methods=("GET", "POST"))
    @role_required("admin")
    def admin_users():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            if not 2 <= len(name) <= 120 or not valid_email(email) or not password_is_valid(password) or role not in ROLES:
                flash("Проверьте имя, почту, роль и сложность пароля (не менее 12 символов).", "danger")
            else:
                db.session.add(User(name=name, email=email, password_hash=generate_password_hash(password),
                                    totp_secret=pyotp.random_base32(), role=role, must_change_password=True))
                try:
                    db.session.flush()
                    append_event("USER_CREATED", f"Создан пользователь {email} ({role})", "success")
                    db.session.commit()
                    flash("Пользователь создан. При первом входе он подключит 2FA.", "success")
                except IntegrityError:
                    db.session.rollback()
                    flash("Пользователь с таким адресом уже существует.", "danger")
        users = db.session.scalars(select(User).order_by(User.id)).all()
        now = utc_now()
        expired_invite_ids = {
            user.id for user in users
            if user.google_invite_expires_at and not user.google_sub
            and as_utc(user.google_invite_expires_at) <= now
        }
        return render_template("admin_users.html", title="Пользователи", users=users, roles=ROLES,
                               google_enabled=google_client() is not None,
                               expired_invite_ids=expired_invite_ids)

    @app.post("/admin/users/google")
    @role_required("admin")
    def admin_invite_google():
        if google_client() is None:
            abort(404)
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "")
        if not 2 <= len(name) <= 120 or not valid_email(email) or role not in ROLES:
            flash("Проверьте имя, почту и роль приглашённого сотрудника.", "danger")
            return redirect(url_for("admin_users"))
        user = User(name=name, email=email, role=role, totp_secret=pyotp.random_base32(),
                    password_hash=generate_password_hash(secrets.token_urlsafe(48)),
                    has_local_password=False, google_invite_expires_at=utc_now() + GOOGLE_INVITE_LIFETIME)
        db.session.add(user)
        try:
            db.session.flush()
            append_event("GOOGLE_INVITE_CREATED", f"Приглашён пользователь {email} ({role})", "success",
                         details={"target_id": user.id, "target_email": user.email, "target_role": role})
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Пользователь с таким адресом уже существует.", "danger")
            return redirect(url_for("admin_users"))
        flash("Приглашение создано на 7 дней. Сообщите сотруднику адрес приложения: он войдёт через Google и подключит 2FA.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/google-invite/renew")
    @role_required("admin")
    def admin_renew_google_invite(user_id: int):
        user = db.session.get(User, user_id, with_for_update=True)
        if (not user or not user.is_active or user.has_local_password or user.google_sub
                or user.google_invite_expires_at is None):
            abort(404)
        user.google_invite_expires_at = utc_now() + GOOGLE_INVITE_LIFETIME
        append_event("GOOGLE_INVITE_RENEWED", f"Продлено приглашение пользователя {user.email}", "warning")
        db.session.commit()
        flash("Приглашение продлено на 7 дней.", "success")
        return redirect(url_for("admin_users"))

    @app.post("/admin/users/<int:user_id>/update")
    @role_required("admin")
    def admin_update_user(user_id: int):
        user = db.session.get(User, user_id)
        if user is None:
            abort(404)
        if user.id == g.user.id:
            abort(403)
        role = request.form.get("role", "")
        active = request.form.get("is_active") == "1"
        if role not in ROLES:
            abort(400)
        if user.role == "admin" and (role != "admin" or not active):
            admins = db.session.scalars(select(User.id).where(User.role == "admin", User.is_active.is_(True))
                                        .order_by(User.id).with_for_update()).all()
            if len(admins) <= 1:
                abort(400, "Нельзя отключить последнего активного администратора.")
        if user.role != role or user.is_active != active:
            user.role = role
            user.is_active = active
            user.session_version += 1
            append_event("USER_UPDATED", f"Изменены роль или статус пользователя {user.email}", "warning")
            db.session.commit()
            flash("Изменения сохранены. Предыдущий сеанс пользователя завершён.", "success")
        return redirect(url_for("admin_users"))

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(413)
    @app.errorhandler(429)
    @app.errorhandler(503)
    def error_page(error):
        if isinstance(error, SecurityError):
            return app.response_class("Недоверенный адрес сервера.", status=400, mimetype="text/plain")
        messages = {400: "Некорректный запрос.", 403: "Недостаточно прав для действия.",
                    404: "Страница или запись не найдена.", 409: "Состояние записи изменилось. Обновите страницу.",
                    413: "Суммарный размер загрузки превышает 64 МБ.",
                    429: "Слишком много неудачных подтверждений. Повторите вход через пять минут.",
                    503: "Сервис временно недоступен. Попробуйте позже."}
        code = error.code
        description = getattr(error, "description", None)
        custom_description = description and description != getattr(type(error), "description", None)
        return render_template("error.html", title="Ошибка", code=code,
                               message=str(description) if code in {400, 409} and custom_description
                               else messages[code]), code

    @app.errorhandler(SQLAlchemyError)
    def database_failure(error):
        db.session.rollback()
        app.logger.error("Database operation failed: %s request_id=%s", type(error).__name__, g.request_id)
        g.user = None
        return error_page(type("ServiceUnavailable", (), {"code": 503})())

    @app.errorhandler(StorageError)
    def storage_failure(error):
        app.logger.error("Storage operation failed: %s", type(error).__name__)
        return error_page(type("ServiceUnavailable", (), {"code": 503})())

    @app.cli.command("bootstrap-admin")
    @click.option("--name", prompt=True)
    @click.option("--email", prompt=True)
    @click.password_option(confirmation_prompt=True)
    def bootstrap_admin(name: str, email: str, password: str):
        """Create the first administrator after flask db upgrade."""
        if db.session.scalar(select(func.count(User.id))) != 0:
            raise click.ClickException("Bootstrap возможен только в пустой базе. Далее используйте панель администратора.")
        if not valid_email(email.strip().lower()) or not password_is_valid(password):
            raise click.ClickException("Некорректная почта или слабый пароль (минимум 12 символов, регистр и цифра).")
        db.session.add(User(name=name.strip(), email=email.strip().lower(),
                            password_hash=generate_password_hash(password),
                            totp_secret=pyotp.random_base32(), role="admin"))
        db.session.commit()
        click.echo("Администратор создан. Подключите 2FA при первом входе.")

    @app.cli.command("check-setup")
    def check_setup():
        """Check database access and private Storage bucket before migration/startup."""
        try:
            db.session.execute(text("SELECT 1")).scalar_one()
            click.echo("PostgreSQL: соединение установлено.")
        except Exception as exc:
            raise click.ClickException("PostgreSQL недоступен. Проверьте DATABASE_URL и пароль.") from exc
        try:
            storage().check_bucket(MAX_EVIDENCE_FILE_SIZE)
            click.echo("Storage: bucket существует, закрыт и не ограничивает файлы меньше 16 МБ.")
        except StorageError as exc:
            raise click.ClickException(str(exc)) from exc

    from legacy_import import register_cli
    register_cli(app)
    from casework import bp as casework_bp
    app.register_blueprint(casework_bp)
    from custody import bp as custody_bp
    app.register_blueprint(custody_bp)
    from reports import register_reports
    register_reports(app)
    from operations import register_operations
    register_operations(app)

    return app


def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def valid_email(email: str) -> bool:
    return len(email) <= 254 and "@" in email and "." in email.rsplit("@", 1)[-1]


def password_is_valid(password: str) -> bool:
    return (len(password) >= 12 and any(c.islower() for c in password)
            and any(c.isupper() for c in password) and any(c.isdigit() for c in password))


def format_size(value: int | None) -> str:
    size = float(value or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if size < 1024 or unit == "ГБ":
            return f"{size:.0f} {unit}" if unit == "Б" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} ГБ"


def plural(value: int, one: str, few: str, many: str) -> str:
    number = abs(int(value))
    if 11 <= number % 100 <= 14:
        return many
    if number % 10 == 1:
        return one
    return few if 2 <= number % 10 <= 4 else many


def format_datetime(value: datetime | str | None) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    offset = current_app.config.get("DISPLAY_TIMEZONE_OFFSET_HOURS", 5)
    return as_utc(value).astimezone(timezone(timedelta(hours=offset))).strftime("%d.%m.%Y, %H:%M")


def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            flash("Войдите в систему, чтобы продолжить.", "warning")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(**kwargs):
            if g.user.role not in roles:
                abort(403)
            return view(**kwargs)
        return wrapped
    return decorator


def storage():
    return current_app.extensions["evidence_storage"]


def google_client():
    return current_app.extensions.get("evidence_google_oauth")


def clear_google_flow() -> None:
    session.pop("google_flow", None)
    session.pop("google_link_user_id", None)
    session.pop("google_link_version", None)


def append_event(event_type: str, description: str, severity: str = "info", user_id: int | None = None,
                 *, case_id: int | None = None, evidence_id: int | None = None, details: dict | None = None):
    actor_id = user_id if user_id is not None else (g.user.id if g.user else None)
    actor = db.session.get(User, actor_id) if actor_id is not None else None
    db.session.add(AuditLog(user_id=actor_id,
                            event_type=event_type, description=description, severity=severity,
                            actor_name=actor.name if actor else None, actor_email=actor.email if actor else None,
                            case_id=case_id, evidence_id=evidence_id,
                            details_json=json.dumps(details, ensure_ascii=False, sort_keys=True) if details else None,
                            ip_address=request.remote_addr or "—"))


def preauth_user() -> User | None:
    user_id = session.get("preauth_user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user or not user.is_active or user.session_version != session.get("preauth_version") or (
            user.locked_until and as_utc(user.locked_until) > utc_now()):
        session.clear()
        return None
    return user


def session_matches_user(user: User | None) -> bool:
    if (not user or not user.is_active or session.get("user_id") != user.id
            or session.get("session_version") != user.session_version):
        return False
    method = session.get("auth_method", "totp")
    if method == "google":
        return (user.role == "investigator" and bool(user.google_sub)
                and session.get("google_sub") == user.google_sub)
    return method == "totp" and user.totp_enabled


def start_session(user: User, *, auth_method: str = "totp") -> None:
    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["session_version"] = user.session_version
    session["auth_method"] = auth_method
    if auth_method == "google":
        session["google_sub"] = user.google_sub
    session["csrf_token"] = secrets.token_urlsafe(32)
    g.user = user


def fail_auth(user: User, event_type: str, description: str) -> None:
    db.session.refresh(user, with_for_update=True)
    if user.locked_until and as_utc(user.locked_until) > utc_now():
        session.clear()
        return
    user.failed_attempts += 1
    if user.failed_attempts >= AUTH_ATTEMPT_LIMIT:
        user.failed_attempts = 0
        user.locked_until = utc_now() + timedelta(seconds=LOCK_SECONDS)
        session.clear()
    append_event(event_type, description, "danger", user.id)
    db.session.commit()


def require_sensitive_confirmation() -> None:
    db.session.refresh(g.user, with_for_update=True)
    if not session_matches_user(g.user) or not g.user.totp_enabled:
        session.clear()
        abort(403)
    if g.user.locked_until and as_utc(g.user.locked_until) > utc_now():
        abort(429)


def matching_totp_step(secret: str, submitted: str) -> int | None:
    code = submitted.strip()
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current_step = int(utc_now().timestamp() // 30)
    totp = pyotp.TOTP(secret)
    for step in (current_step, current_step - 1, current_step + 1):
        if secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def case_visibility_filter(user: User | None = None):
    user = user or g.user
    if user.role in {"admin", "auditor"}:
        return True
    membership = select(CaseMember.id).where(CaseMember.case_id == Case.id, CaseMember.user_id == user.id).exists()
    return or_(Case.owner_id == user.id, membership)


def audit_visibility_filter():
    if g.user.role in {"admin", "auditor"}:
        return True
    case_ids = select(Case.id).where(case_visibility_filter())
    return or_(AuditLog.case_id.in_(case_ids),
               (AuditLog.case_id.is_(None)) & (AuditLog.user_id == g.user.id))


def can_view_case(case: Case, user: User | None = None) -> bool:
    user = user or g.user
    if not user or not user.is_active:
        return False
    if user.role in {"admin", "auditor"}:
        return True
    return user.role == "investigator" and (case.owner_id == user.id or db.session.scalar(
        select(CaseMember.id).where(CaseMember.case_id == case.id, CaseMember.user_id == user.id)) is not None)


def can_manage_case(case: Case, user: User | None = None) -> bool:
    user = user or g.user
    return bool(user and user.is_active and (
        user.role == "admin" or (user.role == "investigator" and case.owner_id == user.id)))


def can_edit_case(case: Case, user: User | None = None) -> bool:
    user = user or g.user
    if can_manage_case(case, user):
        return True
    if not user or not user.is_active or user.role != "investigator":
        return False
    return db.session.scalar(select(CaseMember.id).where(CaseMember.case_id == case.id,
        CaseMember.user_id == user.id, CaseMember.permission == "editor")) is not None


def revalidate_case_access(case: Case, *, require_edit: bool = False, allow_closed: bool = True):
    """Serialize publication with case closure/access changes after external I/O."""
    db.session.refresh(case, with_for_update=True)
    db.session.refresh(g.user, with_for_update=True)
    if not session_matches_user(g.user):
        session.clear()
        g.user = None
        abort(403, "Сеанс завершён. Войдите повторно.")
    if not can_view_case(case):
        abort(404)
    if require_edit and not can_edit_case(case):
        abort(403)
    if not allow_closed and case.status != "active":
        abort(409, "Дело закрыто. Новые материалы не принимаются.")


def escape_search(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def visible_case(case_id: int, *, options=()) -> Case:
    case = db.session.scalar(select(Case).options(*options).where(
        Case.id == case_id, case_visibility_filter()))
    if case is None:
        abort(404)
    return case


def editable_case(case_id: int, allow_closed: bool = False) -> Case:
    case = visible_case(case_id)
    if not can_edit_case(case):
        abort(403)
    if not allow_closed and case.status != "active":
        abort(409, "Дело закрыто. Новые материалы не принимаются.")
    return case


def visible_evidence(evidence_id: int) -> Evidence:
    evidence = db.session.get(Evidence, evidence_id)
    if evidence is None:
        abort(404)
    visible_case(evidence.case_id)
    return evidence


def store_uploaded_files(case: Case, files: list, description: str) -> None:
    uploaded_count = 0
    failed_names = []
    pending_names = []
    selected = [item for item in files if item is not None and item.filename]
    if len(selected) > MAX_FILES_PER_UPLOAD:
        flash(f"Выберите не более {MAX_FILES_PER_UPLOAD} файлов за одну загрузку.", "warning")
        return
    source = parse_source_details()
    if source["source_sha256"] and len(selected) != 1:
        abort(400, "Исходную SHA-256 можно указать только для одного файла.")
    case_id, case_number, user_id = case.id, case.case_number, g.user.id
    deadline = monotonic() + 90
    for index, uploaded in enumerate(selected):
        if monotonic() >= deadline:
            failed_names.extend(Path(item.filename.replace("\\", "/")).name[:255] for item in selected[index:])
            break
        original_name = "".join(c for c in Path(uploaded.filename.replace("\\", "/")).name
                                if ord(c) >= 32 and ord(c) != 127)[:255]
        if not original_name:
            flash("Имя файла не должно быть пустым.", "warning")
            continue
        extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        if extension not in ALLOWED_EXTENSIONS:
            flash(f"Файл «{original_name}» имеет неподдерживаемый тип.", "warning")
            continue
        content = uploaded.stream.read(MAX_EVIDENCE_FILE_SIZE + 1)
        if len(content) > MAX_EVIDENCE_FILE_SIZE:
            flash(f"Файл «{original_name}» превышает 16 МБ.", "warning")
            continue
        key = f"{case_id}/{uuid.uuid4().hex}.{extension}"
        digest = hashlib.sha256(content).hexdigest()
        if source["source_sha256"] and not secrets.compare_digest(source["source_sha256"], digest):
            failed_names.append(original_name)
            append_event("SOURCE_HASH_MISMATCH", f"Исходная SHA-256 не совпала для файла {original_name}", "danger", case_id=case_id)
            db.session.commit()
            continue
        try:
            with storage_deadline(deadline):
                storage().upload(key, content, "application/octet-stream")
                stored_content = storage().download(key, MAX_EVIDENCE_FILE_SIZE)
            if len(stored_content) != len(content) or not secrets.compare_digest(
                    hashlib.sha256(stored_content).hexdigest(), digest):
                raise StorageIntegrityError("Хранилище не подтвердило содержимое загруженного файла.")
            checked_at = utc_now()
            try:
                revalidate_case_access(case, require_edit=True, allow_closed=False)
            except Exception:
                # The remote object has not been published as evidence yet.
                db.session.rollback()
                storage().delete(key)
                raise
            evidence = Evidence(case_id=case_id, uploaded_by=user_id, original_name=original_name,
                                    stored_name=key, mime_type=uploaded.mimetype or "application/octet-stream",
                                    size_bytes=len(content), sha256=digest, description=description,
                                    last_verified_at=checked_at, observed_integrity_status="verified",
                                    observed_integrity_at=checked_at, custodian_id=user_id, **source)
            db.session.add(evidence)
            db.session.flush()
            case.updated_at = checked_at
            append_event("EVIDENCE_UPLOADED", f"В дело {case_number} загружен файл {original_name}", "success", user_id,
                         case_id=case_id, evidence_id=evidence.id,
                         details={"sha256": digest, "size_bytes": len(content),
                                  "source_label": source["source_label"],
                                  "source_reference": source["source_reference"],
                                  "acquisition_method": source["acquisition_method"],
                                  "acquired_at": as_utc(source["acquired_at"]).isoformat() if source["acquired_at"] else None})
            db.session.commit()
            uploaded_count += 1
        except (StorageError, SQLAlchemyError) as exc:
            db.session.rollback()
            if isinstance(exc, SQLAlchemyError):
                # A lost commit response does not prove rollback. Never delete
                # an object until a fresh query establishes it has no metadata.
                try:
                    persisted = db.session.scalar(select(Evidence.id).where(Evidence.stored_name == key))
                except SQLAlchemyError:
                    db.session.rollback()
                    pending_names.append(original_name)
                    current_app.logger.error("Upload outcome needs reconciliation at key %s", key)
                    continue
                if persisted is not None:
                    uploaded_count += 1
                    continue
            try:
                storage().delete(key)
            except StorageError:
                current_app.logger.warning("Check for orphaned storage object at key %s", key)
            failed_names.append(original_name)
            current_app.logger.warning("File upload failed: %s", type(exc).__name__)
            try:
                append_event("EVIDENCE_UPLOAD_FAILED", f"Не сохранён файл {original_name} в дело {case_number}",
                             "warning", user_id, case_id=case_id)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
    if uploaded_count:
        flash(f"Загружено файлов: {uploaded_count}. Содержимое хранилища и SHA-256 проверены.", "success")
    if failed_names:
        names = ", ".join(f"«{name}»" for name in failed_names[:3])
        flash(f"Не сохранено файлов: {len(failed_names)} — {names}. Повторите загрузку только несохранённых файлов.", "danger")
    if pending_names:
        names = ", ".join(f"«{name}»" for name in pending_names[:3])
        flash(f"Не удалось подтвердить сохранение: {names}. Проверьте список файлов перед повторной загрузкой.", "warning")


def parse_source_details() -> dict:
    fields = {}
    for name, maximum in (("source_label", 500), ("source_reference", 200), ("acquisition_method", 300)):
        value = request.form.get(name, "").strip()
        if len(value) > maximum:
            abort(400, "Сведения об источнике превышают допустимую длину.")
        fields[name] = value
    acquired = request.form.get("acquired_at", "").strip()
    fields["acquired_at"] = None
    if acquired:
        try:
            date = datetime.fromisoformat(acquired)
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone(timedelta(hours=current_app.config["DISPLAY_TIMEZONE_OFFSET_HOURS"])))
            date = date.astimezone(timezone.utc)
            if date > utc_now() + timedelta(minutes=5):
                raise ValueError("future acquisition")
            fields["acquired_at"] = date
        except (ValueError, OverflowError):
            abort(400, "Укажите корректную дату получения материала.")
    digest = request.form.get("source_sha256", "").strip().lower()
    if digest and (len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)):
        abort(400, "Исходная SHA-256 должна содержать 64 шестнадцатеричных символа.")
    fields["source_sha256"] = digest or None
    return fields


def record_integrity_observation(evidence: Evidence, status: str, update_status: bool = False) -> None:
    checked_at = utc_now()
    values = {"observed_integrity_status": status, "observed_integrity_at": checked_at}
    if update_status:
        values.update(integrity_status=status, last_verified_at=checked_at)
    db.session.execute(update(Evidence).where(Evidence.id == evidence.id)
        .where((Evidence.observed_integrity_at.is_(None)) | (Evidence.observed_integrity_at <= checked_at))
        .values(**values).execution_options(synchronize_session="fetch"))


def check_integrity(evidence: Evidence) -> str:
    try:
        with storage_deadline(monotonic() + 60):
            content = storage().download(evidence.stored_name, MAX_EVIDENCE_FILE_SIZE)
    except StorageNotFound:
        return "missing"
    except StorageIntegrityError:
        return "modified"
    return "verified" if len(content) == evidence.size_bytes and secrets.compare_digest(
        hashlib.sha256(content).hexdigest(), evidence.sha256) else "modified"


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
