FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/app
RUN useradd --create-home --uid 10001 appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py models.py storage.py legacy_import.py casework.py custody.py reports.py operations.py audit_logging.py ./
COPY migrations ./migrations
COPY templates ./templates
COPY static ./static
USER appuser
EXPOSE 8080
CMD ["sh", "-c", "if [ -z \"${APP_ALLOWED_HOSTS:-}\" ] && [ -n \"${RENDER_EXTERNAL_HOSTNAME:-}\" ]; then export APP_ALLOWED_HOSTS=\"$RENDER_EXTERNAL_HOSTNAME\"; fi; exec gunicorn --workers 2 --timeout 180 --bind 0.0.0.0:${PORT:-8080} --access-logfile - --access-logformat '%(t)s method=%(m)s path=%(U)s status=%(s)s seconds=%(L)s request_id=%({x-request-id}o)s' --error-logfile - 'app:create_app()'"]
