# STRATUM API + console. Build: docker build -t stratum .   Run: docker run -p 8000:8000 stratum
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY stratum ./stratum
COPY policies ./policies
RUN pip install --no-cache-dir ".[api]" \
 && useradd --uid 10001 --no-create-home stratum
USER 10001
EXPOSE 8000
# STRATUM_SOURCE=synthetic | real (mount the corpus at /data) | /path/to/dataset.json
ENV STRATUM_SOURCE=synthetic STRATUM_DATA=/data
CMD ["uvicorn", "stratum.api:app", "--host", "0.0.0.0", "--port", "8000"]
