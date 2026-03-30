# ============================================================
# Cerberus Frontend — React + Vite + Tailwind + shadcn/ui
# ============================================================
# Multi-stage build:
#   - "deps"  stage: installs node_modules (cached layer)
#   - "dev"   stage: for local development with hot reload
#   - "build" stage: creates optimized production bundle
#   - "prod"  stage: serves static files via nginx
#
# docker-compose targets "dev" by default.
# For deployment: docker build --target prod -t cerberus-frontend .
# ============================================================

# ── Stage 1: Install dependencies ───────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ── Stage 2: Development (default for docker-compose) ───────
FROM node:20-alpine AS dev
WORKDIR /app
# Copy installed node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules
COPY . .
EXPOSE 5173
# Vite dev server bound to all interfaces for Docker networking
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

# ── Stage 3: Production build ───────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# VITE_API_URL is baked into the JS bundle at build time
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# ── Stage 4: Production serve via nginx ─────────────────────
FROM nginx:alpine AS prod
# Copy built assets into nginx's default serve directory
COPY --from=build /app/dist /usr/share/nginx/html
# Custom nginx config for SPA routing (all paths → index.html)
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
