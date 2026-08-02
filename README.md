# AI Diff Review Service

Dependency-free Python implementation of the assessment API.

```sh
export REVIEW_TOKEN='xsolla-review-T9mK7vQ2pL8xN4wR6cJ1hF5aZ3yD0sU
python3 server.py
python3 -m unittest -v
```

It listens on port 8080 (override with `PORT`). The optional OpenAI-compatible
LLM provider needs `LLM_BASE_URL`, `LLM_API_KEY`, and optionally `LLM_MODEL`.
