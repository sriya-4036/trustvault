FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd --create-home --uid 10001 trustvault && mkdir /data && chown trustvault /data
USER trustvault
ENV TRUSTVAULT_DATA_DIR=/data
VOLUME /data
EXPOSE 8000
# Single worker: the audit hash chain is serialised in-process (see README).
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
