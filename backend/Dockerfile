# ============================================================
# Cerberus Backend — FastAPI application container
# ============================================================
# Build context should be the project root so we can access
# requirements.txt (which lives at repo root, not in backend/).
#
# docker-compose sets:
#   context: .           (project root)
#   dockerfile: backend/Dockerfile
# ============================================================

FROM python:3.12-slim

WORKDIR /app

# Install system deps needed by some Python packages (e.g. neo4j, httpx)
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the backend source code into the image
COPY backend/ .

# Expose the FastAPI port
EXPOSE 8000

# Run uvicorn — reload is off in the container (use volume mount for dev)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
