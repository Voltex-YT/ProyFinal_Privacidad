FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -g 1000 siemgroup && \
    useradd -u 1000 -g siemgroup -m siemuser

WORKDIR /siem

COPY collector.py .

RUN mkdir -p /siem/logs && chown -R siemuser:siemgroup /siem

USER siemuser

EXPOSE 5514/udp

CMD ["python3", "collector.py"]
