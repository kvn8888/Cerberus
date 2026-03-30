#!/bin/bash
# ============================================================
# start.sh — Launches both nginx and uvicorn in one container
# ============================================================
# Render requires a single process listening on $PORT (default
# 10000). We configure nginx to listen on $PORT and proxy API
# requests to uvicorn on localhost:8000.
#
# If the uvicorn process dies, the container exits so Render
# can restart it automatically.
# ============================================================

set -e

# Render injects PORT=10000; default to 80 for local Docker
PORT="${PORT:-80}"

# Rewrite nginx to listen on the correct port
# (replaces "listen 80;" with "listen $PORT;" in the config)
sed -i "s/listen 80;/listen ${PORT};/" /etc/nginx/conf.d/default.conf

echo "Starting uvicorn on :8000 ..."
# Start uvicorn in the background
uvicorn main:app --host 127.0.0.1 --port 8000 &
UVICORN_PID=$!

# Give uvicorn a moment to bind before nginx starts proxying
sleep 2

echo "Starting nginx on :${PORT} ..."
# Start nginx in the foreground
nginx -g "daemon off;" &
NGINX_PID=$!

# Wait for either process to exit — if one dies, kill the other
# and exit so the container restarts
wait -n $UVICORN_PID $NGINX_PID
EXIT_CODE=$?

echo "Process exited with code $EXIT_CODE — shutting down"
kill $UVICORN_PID $NGINX_PID 2>/dev/null || true
exit $EXIT_CODE
