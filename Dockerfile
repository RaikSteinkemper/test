FROM python:3.13-slim

# ClamAV + Signaturen beim Build laden. Signaturen veralten mit dem Image → Image regelmäßig neu bauen.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clamav \
 && rm -rf /var/lib/apt/lists/* \
 && freshclam --stdout \
 && chmod -R a+r /var/lib/clamav

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY scan_models.py /app/scan_models.py

ENV PROMPTFOO_DISABLE_TELEMETRY=1
USER 10001
ENTRYPOINT ["python", "/app/scan_models.py"]
# Aufruf: docker run --rm -v /pfad/zu/modellen:/model:ro <image> /model