FROM python:3.15-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --no-deps -r requirements.lock \
    && pip check \
    && useradd --system --uid 10001 --no-create-home bridge
COPY bridge ./bridge
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "bridge", "serve"]
