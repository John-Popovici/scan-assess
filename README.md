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

## Modules

Reports are written to `reports/`. Module outputs are written to `outputs/`.

Configuation files are located in `mondules/module_name/config/scan_assess_runtime.json` and can be used to set default arguments for each module manually as well. Arguments passed with `--set` will override these config values.
Arguments can be set with `--set key=value` where `key` is the module name and `value` is a JSON string of the module's arguments. General arguments such as `--demo` are sent to all modules.

```bash
uv run main.py --verbose --set threatsucker.example_arg=example_value
```
