<div align="center">
  <h1>BuildProof</h1>
  <p><strong>Static architecture intelligence connected to a real, auditable runtime.</strong></p>
  <p>
    <a href="https://www.chuhaijian.com"><img src="https://img.shields.io/badge/Live-Console-1677ff" alt="BuildProof live console"></a>
    <a href="https://github.com/tajleonbennis-maker/buildproof/blob/main/LICENSE"><img src="https://img.shields.io/github/license/tajleonbennis-maker/buildproof" alt="License"></a>
    <a href="https://github.com/tajleonbennis-maker/buildproof/commits/main"><img src="https://img.shields.io/github/last-commit/tajleonbennis-maker/buildproof" alt="Last commit"></a>
  </p>
</div>

BuildProof turns a source repository into a versioned system model, deploys the
same commit into an isolated inspection environment, and connects static
evidence with observed runtime behaviour. It is designed for AI-generated and
fast-moving Web applications where a file-level scan alone cannot prove what
was actually shipped or exposed.

BuildProof is built on the open-source
[Code-Graph-RAG](https://github.com/vitali87/code-graph-rag) engine. This fork
retains its multi-language parsing, graph, RAG, MCP, and code intelligence
capabilities while adding the BuildProof analysis and runtime verification
product described below.

**Live console:** [www.chuhaijian.com](https://www.chuhaijian.com)

## BuildProof Capabilities

- **Versioned repository analysis.** Every saved report records the exact Git
  commit used for analysis and deployment.
- **Full-stack route mapping.** Pages, React and Next.js components, browser
  calls, Next.js handlers, FastAPI routes, WebSockets, SDK calls, and external
  services are connected into evidence-backed call chains.
- **Frontend component inventory.** Components are discovered independently of
  route files, including reusable and indirectly routed UI components.
- **Attack intelligence manifests.** Machine-readable attack surfaces can be
  consumed by white-box scanners and security agents without reparsing the
  repository.
- **Supply-chain and security evidence.** Dependency versions, source
  locations, scan status, known vulnerabilities, and affected components are
  shown together.
- **Automated monitoring.** Saved repositories can be rescanned on a schedule so
  the console does not silently retain an obsolete snapshot.
- **Ephemeral runtime verification.** The analyzed commit can be built in an
  isolated Docker environment, exposed for inspection, health-probed, and
  automatically expired.
- **Runtime evidence ingestion.** Process, file, network, HTTP, deployment, and
  audit events are normalized and attached to the corresponding static report.
- **Evidence-first reporting.** Findings link back to files and line numbers;
  unresolved dynamic behaviour is marked for review instead of guessed.

## Verification Flow

```text
Git repository
    -> static analysis + source evidence
    -> attack manifest + component/API inventory
    -> build the exact commit in an isolated environment
    -> health and public reachability probes
    -> runtime audit events
    -> one report keyed by repository and commit SHA
```

The deployment service applies memory and process limits, labels containers
with the source commit, verifies application health, and reports the public test
URL back to the console. Runtime environments are intended for authorized,
temporary inspection, not production hosting.

## Run Locally

```bash
uv run buildproof --repo /path/to/agent-built-app
```

Then open `http://127.0.0.1:8765`. See the
[BuildProof guide](docs/guide/buildproof.md) for Docker deployment and API use.

Useful integration endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` | Analyze and save a repository |
| `GET /api/projects` | List saved reports |
| `GET /api/projects/{id}` | Read the complete static report |
| `GET /api/projects/{id}/attack-manifest` | Read scanner-oriented attack intelligence |
| `GET /api/projects/{id}/deployment` | Read deployment and commit-verification state |
| `POST /api/runtime/ingest/{id}` | Ingest authenticated runtime evidence |
| `GET /api/projects/{id}/runtime` | Read normalized runtime observations |

Public mode accepts public GitHub repositories. Private repositories should be
checked out by an authorized worker and analyzed without exposing repository
credentials to the runtime node.

<p align="center">
  <img src="./assets/demo.gif" alt="BuildProof demo">
</p>

## BuildProof Development

- Automated exact-commit deployment and public health verification.
- Runtime audit collection and evidence relay from the isolated inspection node.
- Scheduled rescanning for monitored repositories.
- Scanner-oriented attack manifests, security evidence views, and Shannon
  surface deduplication.
- Expanded Next.js, FastAPI, Supabase, frontend component, monorepo dependency,
  and full-stack call-chain analysis.

See the [commit history](https://github.com/tajleonbennis-maker/buildproof/commits/main)
for implementation details. Upstream Code-Graph-RAG release notes remain in
[NEWS.md](NEWS.md).

## Code-Graph-RAG Engine

The underlying Code-Graph-RAG engine parses multi-language codebases with
Tree-sitter, builds a knowledge graph in Memgraph, and supports natural-language
querying, editing, and optimization across mixed-language monorepos.

## What It Does

Point Code-Graph-RAG at a repository and it reads every source file, extracts functions, classes, methods, modules, and the relationships between them, and stores the result as an interconnected graph. Once the graph exists you can:

- Ask questions about the codebase in natural language and get answers grounded in the real structure.
- Retrieve the actual source of any function, class, or method by name or by intent.
- Edit code through the agent with AST-based surgical patching and a diff preview before anything changes.
- Optimise code against language best practices or your own coding standards.
- Find dead code by walking call and reference edges from entry points.
- Search and rewrite structurally by AST pattern with ast-grep.
- Overlay runtime behaviour: trace a test run (or pull production eBPF profiles) with `cgr trace` and merge the calls that actually happened into the graph, exposing dispatch that static analysis cannot see.

## How It Works

The system has two components:

1. **Multi-language parser.** A Tree-sitter based parser reads the codebase and ingests functions, classes, methods, modules, and their relationships into Memgraph under a single language-agnostic schema.
2. **RAG system** (`codebase_rag/`). An interactive CLI that turns natural language into Cypher queries, retrieves matching code, and drives AI-powered editing and optimisation.

```
Source Code -> Tree-sitter Parser -> AST Analysis -> Memgraph Knowledge Graph
                                                             |
User Query -> AI Model (Cypher Gen) -> Cypher Query -> Graph Results -> Response
```

See the [Architecture Overview](docs/architecture/overview.md) and [Graph Schema](docs/architecture/graph-schema.md) for the full picture.

## Supported Languages

Python, TypeScript, TSX, JavaScript, Rust, Go, Java, C, C++, C#, PHP, Lua, and Dart are fully supported. Scala is in development, and Ruby, Kotlin, Swift, Elixir, Haskell, Solidity, Bash, and Nix have structural support (modules, functions, classes where the language has them, and imports) through the pluggable ast-grep tier. See the [Language Support](docs/architecture/language-support.md) matrix for per-language capabilities.

## Installation

`cgr` is published to PyPI. Install it system-wide with the `treesitter-full` (all languages) and `semantic` (vector search) extras:

```bash
# with uv (recommended)
uv tool install "code-graph-rag[treesitter-full,semantic]"

# or with pipx
pipx install "code-graph-rag[treesitter-full,semantic]"
```

### Which version am I getting?

Three version lines exist and they intentionally differ:

| where | what it tracks |
|---|---|
| git tags | every version, one per merge |
| GitHub Releases (binaries, signatures) | every 50th version, plus any security fix |
| PyPI | every 50th version, plus any security fix |

So the newest tag on `main` usually runs ahead of the newest release, often by
tens of patch versions; they coincide only just after a release. Nothing is
stuck, the cadences differ by design. A security fix does NOT wait for the
cadence: it ships a release and a PyPI upload immediately.

`uv tool install` and `pipx install` give you the newest PyPI version, which is the
newest RELEASE, not the newest tag. Interim tags exist so every merge is
addressable; binaries and PyPI uploads follow the cadence above.

To run code newer than the latest release, install from git:

```bash
uv tool install "code-graph-rag[treesitter-full,semantic] @ git+https://github.com/vitali87/code-graph-rag@main"
```

You also need Docker (for Memgraph), `cmake`, and `ripgrep`. Full prerequisites, source installs, and environment setup are in the [Installation](docs/getting-started/installation.md) guide.

## Quick Start

```bash
# Start the packaged Memgraph + Qdrant stack (no compose file needed)
cgr daemon up

# Parse a repository into the graph, then query it
cgr start --repo-path /path/to/repo --update-graph
cgr start --repo-path /path/to/repo
```

Repeat the first command for each repository you want indexed; the graph is
shared, and syncing one project leaves the others alone. To start over from an
empty graph, add `--clean` — it deletes **every** project in the shared graph,
not just this one, and asks for confirmation first when other
projects would be destroyed.

The [Quick Start](docs/getting-started/quickstart.md) guide walks through parsing, querying, and exporting in five minutes.

## MCP Server

Code-Graph-RAG runs as an [MCP](https://modelcontextprotocol.io) server so Claude Code and other MCP clients can query and edit your codebase directly. See the [MCP Server](docs/guide/mcp-server.md) guide for setup.

## Documentation

**Getting Started**
- [Installation](docs/getting-started/installation.md)
- [Quick Start](docs/getting-started/quickstart.md)
- [Configuration](docs/getting-started/configuration.md)

**User Guide**
- [CLI Reference](docs/guide/cli-reference.md)
- [Interactive Querying](docs/guide/interactive-querying.md)
- [Code Optimisation](docs/guide/code-optimization.md)
- [Dead Code Detection](docs/guide/dead-code.md)
- [Dynamic Call Tracing](docs/guide/dynamic-tracing.md)
- [Graph Export](docs/guide/graph-export.md)
- [Real-Time Updates](docs/guide/realtime-updates.md)
- [C/C++ Semantic Mode](docs/guide/cpp-semantic-mode.md)
- [MCP Server](docs/guide/mcp-server.md)

**Architecture**
- [Overview](docs/architecture/overview.md)
- [Graph Schema](docs/architecture/graph-schema.md)
- [Language Support](docs/architecture/language-support.md)
- [Data-Flow Edges](docs/architecture/data-flow-edges.md)

**Python SDK**
- [Overview](docs/sdk/overview.md)
- [Graph Loader](docs/sdk/graph-loader.md)
- [Cypher Generator](docs/sdk/cypher-generator.md)
- [Semantic Search](docs/sdk/semantic-search.md)

**Advanced**
- [Adding Languages](docs/advanced/adding-languages.md)
- [Ignore Patterns](docs/advanced/ignore-patterns.md)
- [Building Binaries](docs/advanced/building-binaries.md)
- [Troubleshooting](docs/advanced/troubleshooting.md)

## Enterprise Services

Code-Graph-RAG is open source and free to use. For organisations that need more, we offer **fully managed cloud-hosted solutions** and **on-premise deployments**:

- **Cloud-Hosted Deployment**: Managed cloud infrastructure for both the graph database and the AI agent connection. Zero infrastructure overhead, so we handle scaling, updates, and availability while your team focuses on building.
- **On-Premise & Air-Gapped Deployment**: Deploy Code-Graph-RAG entirely within your own environment, including air-gapped networks. Full data sovereignty for regulated industries and security-sensitive organisations.

We also offer custom development, integration consulting, technical support contracts, and team training.

**[View plans & pricing at code-graph-rag.com](https://code-graph-rag.com/enterprise)**

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines. Good first PRs come from the TODO issues.

## Support

For issues or questions, check the [Troubleshooting](docs/advanced/troubleshooting.md) guide first, then open an issue.

## License

MIT. See [LICENSE](LICENSE).
