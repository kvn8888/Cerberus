# Retro 003: Making Docker Actually Work — When Your Dockerfiles Are Lies

The Cerberus Docker setup looked fine on paper. Three services in a `docker-compose.yml`, Dockerfiles for each. But none of it could actually run. This session was about systematically finding and fixing every broken assumption — from macOS binaries mounted into Linux containers to CLI flags that changed between versions.

## The Starting Point

Cerberus is a cross-domain threat intelligence platform with three Docker services:

1. **neo4j-mcp** — A bridge server connecting FastAPI to Neo4j Aura (the graph database). It's a pre-built Go binary, not something we compile.
2. **backend** — A FastAPI Python app serving the API.
3. **frontend** — A React + Vite + Tailwind app.

The `docker-compose.yml` existed, the Dockerfiles existed, but `docker compose up` had never actually succeeded. Here's what was wrong.

## Step 1: The Binary That Can't Run

The neo4j-mcp service was defined like this:

```yaml
neo4j-mcp:
  image: alpine:latest
  volumes:
    - ./neo4j-mcp_Darwin_arm64/neo4j-mcp:/usr/local/bin/neo4j-mcp
  command: >
    /usr/local/bin/neo4j-mcp --transport http --port 8787 --host 0.0.0.0
```

Two problems here, both fundamental:

**Problem 1:** The `neo4j-mcp_Darwin_arm64` binary is a macOS (Darwin) executable. Docker containers run Linux. You can't execute a macOS binary inside an Alpine Linux container — it's a different OS with a different binary format (Mach-O vs ELF). This is like trying to run a `.exe` on a Mac.

**Problem 2:** The `--transport`, `--port`, and `--host` flags don't exist in neo4j-mcp v1.5.0. Running `--help` revealed the actual flags:

```
--neo4j-transport-mode <MODE>   MCP Transport mode (e.g., 'stdio', 'http')
--neo4j-http-port <PORT>        HTTP server port
--neo4j-http-host <HOST>        HTTP server host
```

**The fix:** Download the Linux ARM64 binary (since we're on Apple Silicon, Docker Desktop runs ARM64 Linux VMs), create a proper Dockerfile that copies it in:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache wget
COPY neo4j-mcp /usr/local/bin/neo4j-mcp
RUN chmod +x /usr/local/bin/neo4j-mcp
EXPOSE 8787
ENTRYPOINT [ \
  "neo4j-mcp", \
  "--neo4j-transport-mode", "http", \
  "--neo4j-http-port", "8787", \
  "--neo4j-http-host", "0.0.0.0", \
  "--neo4j-http-allow-unauthenticated-ping", "true" \
]
```

This was a reminder: **always check binary compatibility when containerizing pre-built executables.** And always run `--help` on the actual version you have — documentation and changelogs can be stale.

## Step 2: The Dockerfile That Can't Find Its Files

The backend Dockerfile had this line:

```dockerfile
COPY ../requirements.txt .
```

This doesn't work. Docker build contexts are sandboxed — you **cannot** `COPY` files from outside the build context directory. The docker-compose set the context to `./backend`, but `requirements.txt` lives at the project root.

There are two common solutions:
1. Move `requirements.txt` into `backend/` (duplicating it, which creates drift risk)
2. Change the build context to the project root and point to the Dockerfile

I chose option 2 because it keeps `requirements.txt` as a single source of truth:

```yaml
backend:
  build:
    context: .                    # project root — can see requirements.txt
    dockerfile: backend/Dockerfile  # Dockerfile path relative to context
```

The Dockerfile then uses:

```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .    # only copy backend source, not the whole repo
```

**Key insight:** When the build context changes, the `.dockerignore` at the context root becomes critical. Without it, Docker sends the entire project (including the 12MB neo4j-mcp binary, node_modules, .git, etc.) as build context. I added a `.dockerignore` at the project root to exclude everything the backend doesn't need.

## Step 3: The Healthcheck That Gets a 405

After fixing the binary and flags, the neo4j-mcp container started successfully — but Docker still reported it as "unhealthy." The healthcheck was:

```yaml
healthcheck:
  test: ["CMD", "wget", "--spider", "-q", "http://localhost:8787"]
```

`wget --spider` expects a 200 OK. But neo4j-mcp's HTTP mode only exposes a POST endpoint at `/mcp` — there's no GET health route. Testing from inside the container:

```
GET /            → 404 Not Found
GET /ping        → 404 Not Found
GET /health      → 404 Not Found
GET /mcp         → 405 Method Not Allowed (Allow: POST, OPTIONS)
```

A 405 on `/mcp` actually **proves the server is alive** — it's telling us the endpoint exists but we're using the wrong HTTP method. So the healthcheck became:

```yaml
healthcheck:
  test: ["CMD-SHELL", "wget -q --spider http://localhost:8787/mcp 2>&1 || wget -S -O /dev/null http://localhost:8787/mcp 2>&1 | grep -q '405'"]
```

This tries the normal wget first (which will fail), then falls back to checking if the response contains `405`. If it does, the server is up.

## The Gotcha: HTTP Mode Rejects Credentials

Even after fixing the binary and flags, the container kept crashing with:

```
Failed to load configuration: Neo4j username and password should not
be set for HTTP transport mode; credentials are provided per-request
via Basic Auth headers
```

The docker-compose was passing `NEO4J_USERNAME` and `NEO4J_PASSWORD` as environment variables to the neo4j-mcp container. In HTTP mode, neo4j-mcp v1.5.0 treats these as an error — the design is that each HTTP request carries its own Neo4j credentials via Basic Auth headers. This is a security improvement (no credentials sitting in container env vars), but it breaks the naive "pass all env vars to everything" pattern.

**The fix:** Remove `NEO4J_USERNAME` and `NEO4J_PASSWORD` from the neo4j-mcp service. Only `NEO4J_URI` stays (so the server knows *where* to connect). The backend sends credentials per-request when calling the MCP server.

## Step 4: Multi-Stage Frontend for Dev and Prod

The original frontend Dockerfile was dev-only:

```dockerfile
FROM node:20-alpine
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
```

This works, but for deployment you want a production build served by nginx, not a Vite dev server. A multi-stage build handles both:

```dockerfile
# Stage 1: Install deps (cached layer)
FROM node:20-alpine AS deps
COPY package.json package-lock.json ./
RUN npm ci

# Stage 2: Dev (docker-compose default)
FROM node:20-alpine AS dev
COPY --from=deps /app/node_modules ./node_modules
COPY . .
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# Stage 3: Production build
FROM node:20-alpine AS build
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG VITE_API_URL=http://localhost:8000
RUN npm run build

# Stage 4: Serve via nginx
FROM nginx:alpine AS prod
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
```

docker-compose targets `dev` with `target: dev`. Deployment builds target `prod` with `docker build --target prod`.

The nginx config handles three things: static asset caching, API reverse proxying (so the frontend doesn't need CORS in production), and SPA fallback routing (`try_files $uri /index.html`). The SSE endpoint gets special proxy settings — `proxy_buffering off` is critical or nginx will buffer the stream and the frontend won't get real-time updates.

## What's Next

- **End-to-end integration test** — Run `docker compose up`, submit a query, and verify the full pipeline: frontend → backend → neo4j-mcp → Neo4j Aura → LLM narrative → SSE stream back to frontend.
- **Production deployment** — The GMI Cloud deploy scripts in `deploy/` need updating to use the new Dockerfiles.
- **Backend hot-reload** — The backend container doesn't volume-mount source code for dev. Adding a volume mount + `--reload` flag to uvicorn would speed up backend iteration in Docker.
- **CORS lockdown** — The backend currently has `allow_origins=["*"]`. In a production nginx setup, the frontend proxies API requests, so CORS isn't needed at all.

---

The lesson: a Dockerfile is a theory about how your app should run. `docker compose up` is the experiment. They disagreed on every point, but fixing each failure was a five-minute job once I understood the actual error. The hard part was never the fix — it was reading the error message carefully enough to know *which* assumption was wrong.
