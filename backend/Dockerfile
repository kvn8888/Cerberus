# ============================================================
# Cerberus Backend — FastAPI-only container (standalone)
# ============================================================
# Used by the cerberus-backend Render service.
# Build context should be the project root so requirements.txt
# is accessible (it lives at repo root, not inside backend/).
#
# The unified root Dockerfile (nginx + uvicorn) handles the full
# production deployment. This file is the backend-only variant.
# ============================================================

FROM python:3.12-slim

WORKDIR /app

# Install system deps (wget for health checks, curl for diagnostics)
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the backend source code into the container
COPY backend/ .

# Expose the uvicorn port
EXPOSE 8000

# Start FastAPI via uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
