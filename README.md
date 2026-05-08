A framework that launches multiple modules to gather data and send them to a central LLM server for analysis.

Optionally, with llama.cpp, in one terminal:
```bash
./launch_llama.sh
```

In another terminal, prepare and run the main script:
```bash
uv sync
uv run main.py
```

Modules are expected to write JSON files to the `output` directory. The main script will read those files, send their contents to the LLM server, and generate a markdown report in the `reports` directory.
