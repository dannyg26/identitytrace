FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
COPY detections ./detections
COPY correlations ./correlations
COPY dashboard ./dashboard
COPY scripts ./scripts
RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 identitytrace \
    && mkdir /data && chown identitytrace /data
USER 10001
EXPOSE 8000
ENV DATABASE_URL=sqlite:////data/identitytrace.db
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
