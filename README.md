# scan-assess

A local framework that runs security collection modules, passes their JSON outputs to a local OpenAI-compatible LLM endpoint, and writes a Markdown security report.

## Run The LLM Server

Optionally, with llama.cpp, in one terminal:

```bash
./launch_llama.sh
```

The scanner expects an OpenAI-compatible endpoint at:

```text
http://localhost:8033/v1
```

## Run scan-assess

Install dependencies:

```bash
uv sync
```

```bash
uv run main.py
uv run main.py --demo # bundled demo data
```

Reports are written to `reports/`. Module outputs are written to `outputs/`.
