# Setup on Linux, macOS, and Windows

Run commands from the repository root. The scanner needs Python 3.10 or newer;
Ollama and Node.js are optional. Node.js is used only for frontend tests.
The instructions below are documented for all three systems; this project's
recorded execution checks are on Linux. Windows and macOS walkthroughs remain pending.

## Linux

Install Python and its venv support using your distribution's package manager.
On Ubuntu, if `python3 -m venv` reports missing venv support:

```bash
sudo apt install python3-venv
```

Create the environment and install the application:

```bash
cd /path/to/VULN_AI_SCANNER
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp -n .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload --env-file .env
```

`cp -n` preserves an existing `.env`. Open <http://127.0.0.1:8001>.
Keep this terminal running. Stop the scanner with Ctrl+C.

For optional AI, install Ollama using the [official Linux instructions](https://docs.ollama.com/linux):

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl start ollama
ollama pull qwen2.5-coder:3b
```

If your Linux setup does not use systemd, run `ollama serve` in a separate terminal
instead of the systemctl command. Do not start a second server if one is already running.

## macOS

Install Python 3.10+ from [Python.org](https://www.python.org/downloads/macos/).
In Terminal:

```bash
cd /path/to/VULN_AI_SCANNER
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp -n .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload --env-file .env
```

For optional AI, install and launch Ollama following the
[official macOS instructions](https://docs.ollama.com/macos). In another terminal:

```bash
ollama pull qwen2.5-coder:3b
```

Keep the Ollama app running. Open <http://127.0.0.1:8001>.

## Windows PowerShell

Install Python 3.10+ from [Python.org](https://www.python.org/downloads/windows/).
Open PowerShell in your checkout:

```powershell
cd C:\path\to\VULN_AI_SCANNER
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload --env-file .env
```

If the Python launcher `py` is unavailable, use `python -m venv .venv` instead.
These commands use the environment's Python directly, so activation is unnecessary.
You can optionally activate with `.\.venv\Scripts\Activate.ps1` if your PowerShell
configuration permits it. See Python's [venv documentation](https://docs.python.org/3/library/venv.html).

For optional AI, install and launch Ollama following the
[official Windows instructions](https://docs.ollama.com/windows). Open a new terminal:

```powershell
ollama pull qwen2.5-coder:3b
```

Open <http://127.0.0.1:8001>. Stop the scanner with Ctrl+C.

## Daily use and checks

On Linux/macOS, enter your project directory, run `source .venv/bin/activate`,
and repeat the uvicorn command. On Windows, use the environment's `python.exe`
command above. Edit `OLLAMA_MODEL` in `.env` to select another downloaded local
model, then restart the scanner. An NVD key is optional; AI needs no API key.
Never replace an existing `.env` with the example when it contains your settings.

Use **Check local AI** in the scanner to check runtime/model availability without
sending source or starting generation. Then enable **Explain findings with Ollama**
and upload one of the examples. Model installation is checked separately from
actual generation: an installed model can still fail to load or time out.

If the port is occupied, choose a different port (for example 8002) in the uvicorn
command and open that same port in your browser. If UI changes do not appear,
refresh the page. If AI is unavailable, verify Ollama is running and use `ollama list`
to check the configured model is installed. Keep the scanner bound to loopback.

Run backend tests with your environment's Python:

```bash
python -m unittest discover -s tests
```

On Windows, replace `python` with `.\.venv\Scripts\python.exe` if you did not activate.
With Node.js installed, run the two frontend test files on any platform:

```bash
node tests/frontend/ui-utils.test.mjs
node tests/frontend/ai-ui.test.mjs
```

See [AI evaluation and review](AI_EVALUATION.md) for the optional development
workflow. No training is performed by scans or evaluations.
