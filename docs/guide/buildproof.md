---
description: "Understand the pages, APIs, WebSockets, and business domains in an agent-built application."
---

# BuildProof Console

BuildProof turns an agent-built repository into a system report. It is the
product-facing layer above Code-Graph-RAG: users see pages, backend routes,
business domains, and source evidence instead of a graph database console.

## Run locally

```bash
uv run buildproof --repo /path/to/repository
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765).

The first release recognizes Next.js application routes and traces their local
imports to find indirect HTTP and WebSocket calls. It also extracts FastAPI app
and router endpoints, mount prefixes, authentication boundaries, handlers, and
source locations. A client request is only mapped when its normalized route
template matches a backend route; unresolved dynamic requests stay visible as
unresolved evidence.

## Run with Docker

```bash
BUILDPROOF_REPO_PATH=/absolute/path/to/repository \
docker compose -f docker-compose.buildproof.yaml up --build
```

The target repository is mounted read-only. The console binds to loopback by
default. Set `BUILDPROOF_BIND_HOST=0.0.0.0` only when you deliberately want to
expose it to another machine and have added an authenticating reverse proxy.

## Report API

```bash
curl "http://127.0.0.1:8765/api/analyze?repo=/path/to/repository"
```

The report contains:

- technology and entrypoint inventory;
- Next.js pages and source evidence;
- HTTP and WebSocket endpoints;
- page-to-endpoint mappings;
- public, authenticated, and administrator boundaries;
- business-domain summaries;
- unresolved requests and analysis warnings.

The API is intentionally deterministic and does not require an LLM. Natural
language explanations and graph-backed impact analysis can be layered on the
same report without changing its evidence model.

