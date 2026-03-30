# ============================================================
# Cerberus — Unified Dockerfile (Frontend + Backend)
# ============================================================
# Multi-stage build that combines the React SPA and FastAPI
# backend into a single container:
#
#   Stage 1 (frontend-deps): Install Node.js dependencies
#   Stage 2 (frontend-build): Build the Vite production bundle
#   Stage 3 (runtime): Python + nginx + uvicorn in one container
#
# nginx serves the static frontend on port 80 and proxies
# /api/* requests to uvicorn on localhost:8000. This eliminates
# CORS entirely since everything is same-origin.
#
# Build:  docker build -t cerberus .
# Run:    docker run -p 10000:80 --env-file .env cerberus
# ============================================================

# ── Stage 1: Install frontend dependencies ──────────────────
FROM node:20-alpine AS frontend-deps
WORKDIR /app
# Copy only package files first for better Docker layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# ── Stage 2: Build frontend production bundle ───────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY --from=frontend-deps /app/node_modules ./node_modules
COPY frontend/ .
# Set API base to empty string so all API calls are relative
# (same origin — nginx proxies /api/* to uvicorn)
ENV VITE_API_URL=""
RUN npm run build

# ── Stage 3: Runtime — Python + nginx ───────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Install nginx and clean up apt cache to keep image small
RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY backend/ .

# Copy the built frontend into nginx's serve directory
COPY --from=frontend-build /app/dist /usr/share/nginx/html

# Copy the unified nginx config (proxies /api to localhost:8000)
COPY deploy/nginx-unified.conf /etc/nginx/conf.d/default.conf
# Remove the default nginx site config to avoid conflicts
RUN rm -f /etc/nginx/sites-enabled/default

# Copy the startup script that runs both nginx and uvicorn
COPY deploy/start.sh /app/start.sh
RUN chmod +x /app/start.sh

# Render uses port 10000 by default; nginx listens on 80,
# but we'll configure it to also listen on $PORT if set
EXPOSE 80

# Start both services via the startup script
CMD ["/app/start.sh"]
