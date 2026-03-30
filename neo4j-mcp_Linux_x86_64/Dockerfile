# ============================================================
# neo4j-mcp — Lightweight container for the Neo4j MCP server
# ============================================================
# Uses the pre-downloaded Linux x86_64 binary from the repo.
# Runs in HTTP mode so backend can reach it over the network.
#
# Build context: ./neo4j-mcp_Linux_x86_64/
# ============================================================

FROM alpine:3.20

# Install wget so the healthcheck can verify the server is alive
RUN apk add --no-cache wget

# Copy the pre-built binary into the image
COPY neo4j-mcp /usr/local/bin/neo4j-mcp

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/neo4j-mcp

# HTTP mode listens on this port
EXPOSE 8787

# Start in HTTP mode, bound to all interfaces so Docker networking works.
# In HTTP mode, Neo4j credentials come via per-request Basic Auth headers,
# but we also set env vars so the healthcheck ping can work unauthenticated.
ENTRYPOINT [ \
  "neo4j-mcp", \
  "--neo4j-transport-mode", "http", \
  "--neo4j-http-port", "8787", \
  "--neo4j-http-host", "0.0.0.0", \
  "--neo4j-http-allow-unauthenticated-ping", "true" \
]
