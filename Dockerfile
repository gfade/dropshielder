FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY storefront ./storefront

ENV PORT=8080
ENV DROPSHIELDER_HOST=0.0.0.0
ENV DROPSHIELDER_PACKAGE_JSON=/app/storefront/package.json
ENV DROPSHIELDER_STOREFRONT_DIR=/app/storefront

EXPOSE 8080

CMD ["python", "-m", "backend.server"]
