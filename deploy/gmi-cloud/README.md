# GMI Cloud Deployment

This folder turns the Cerberus backend into a concrete deployable artifact for
GMI Cloud-hosted container infrastructure.

What this gives the project right now:
- a clearly packaged backend service for remote hosting
- a truthful way to say GMI Cloud is used for serving the live API
- a small deployment surface that does not depend on the missing frontend

## What to deploy

Deploy the FastAPI backend container built from [`backend/Dockerfile`](/Users/emanschool/Cerberus/backend/Dockerfile).

Expose:
- `8000/tcp`

Set environment variables:
- `NEO4J_URI`
- `NEO4J_USERNAME`
- `NEO4J_PASSWORD`
- `ANTHROPIC_API_KEY`
- `NEO4J_MCP_URL` if you are also hosting the Neo4j MCP bridge remotely

## Container health check

Use:

```bash
curl -sf http://<service-host>:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Suggested demo usage

Host only the backend on GMI Cloud first. That is enough to make the sponsor
usage concrete without waiting on the missing frontend.

Judge-safe phrasing:

`We deploy the live Cerberus backend on GMI Cloud and use it to serve the query, confirmation, schema, and Juspay-ingestion APIs.`
