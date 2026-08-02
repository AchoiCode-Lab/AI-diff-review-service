# Submission notes

## Architecture

The dependency-free Python server owns a thread-safe in-memory job store, fixed four-worker executor, idempotency index, content cache, and recorded SSE event history. POST enqueues work, workers transition queued → running → done/failed. The parser retains added hunk lines and their new-file locations. File-aware chunk accounting never splits a file. Findings are deduplicated and ordered globally. A completed byte-identical request creates a completed cache-hit job without provider work. Recorded events make new SSE connections replay the lifecycle identically.

## Providers

`mock` deterministically implements every published rule. `llm` is an OpenAI-compatible adapter configured by `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`; missing credentials or a network failure makes that job fail gracefully. Production follow-up: normalize and validate structured LLM output into findings.

## Verification

I locally verified health/spec, auth, invalid inputs, mock findings and ordering, idempotency, caching, SSE replay, file-aware chunks, rate limits, and concurrent jobs. The mock provider makes this deterministic.

## AI assistance and judgment

I used Codex for implementation and edge-case review. I rejected scanning raw diff text with regex alone that would match removed/context/header lines and lose the required new-file line numbers, so the service parses unified hunks first.

## More time

I would add durable storage, a distributed queue, schema-validated LLM output, SSE event IDs, observability, secret management, HTTPS, and deployment automation.
