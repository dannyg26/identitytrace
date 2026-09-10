# Reproducible local deployment (blueprint §5.1, §14.1). Not verified with
# an actual `docker build` in this dev environment (no Docker installed
# here - see docs/architecture.md) - CI (.github/workflows/ci.yml) builds
# this image on every push, which is where it's actually exercised.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (cached across builds that only change
# application code), then the rest of the source.
COPY pyproject.toml ./
COPY app ./app
COPY detections ./detections
COPY correlations ./correlations
COPY dashboard ./dashboard
COPY scripts ./scripts

# Editable install, deliberately - not `pip install .`. Detection/
# correlation rule YAML and dashboard templates are read from disk at
# runtime relative to the installed `app` package's own location
# (app/detections/loader.py etc.) - a real, non-editable install copies
# `app` into site-packages away from this directory and silently breaks
# that (see IDENTITYTRACE_DETECTIONS_DIR/_CORRELATIONS_DIR/_DASHBOARD_DIR
# env var overrides in those modules for the fallback if this ever needs
# to change). An editable install keeps `app` resolving relative paths
# from right here, matching how this project runs in dev.
RUN pip install --no-cache-dir -e .

EXPOSE 8000
ENV DATABASE_URL=sqlite:///./identitytrace.db

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
