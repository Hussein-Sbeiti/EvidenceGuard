# Local Vulnerability Scanner (school-project MVP)

A local web app for uploading source files or folders and checking a small, editable catalog of common risky coding patterns. Findings include a file path, line number, severity, CWE category, explanation, and suggested mitigation.

See [TODO.md](TODO.md) for the project backlog.
See [examples/README.md](examples/README.md) for educational fixtures and website test steps,
and [examples/TEST_RESULTS.md](examples/TEST_RESULTS.md) for observed endpoint results.

## What this version does

- Runs locally with a FastAPI backend and a browser UI.
- Uses a slate sidebar with separate source scan, results, and CVE database views; navigation moves above the content on smaller screens.
- Accepts source files, folders, requirements.txt, and package-lock.json; scans supported text files in memory.
- Parses exact dependency pins locally and optionally queries OSV, with separate inventory, unresolved-entry, advisory-evidence, and fixed-version reporting.
- Shows upload limits and reasons for skipped files, supports severity filtering, and downloads the latest completed scan as JSON or a readable text report.
- Uses local heuristic rules for examples such as dynamic code execution, unsafe Python deserialization, shell command construction, risky HTML insertion, hard-coded credentials, and dynamically constructed SQL queries.
- Does not save uploaded source files or send them to an external service.
- Optionally looks up CVE IDs mentioned in uploaded source using CVE.org and NVD; displays exact CVE-linked Exploit-DB metadata from a local CSV index.
- Includes a manual CVE lookup, persistent SQLite cache, provider throttling, and graceful partial results.

This includes CVE/exploit reference lookups, but is **not yet an AI model or a complete vulnerability scanner**. The rule catalog detects patterns associated with vulnerability classes; it cannot tell whether an application is exploitable, and it can miss issues or report false positives. Suggested fixes are examples, not automatic patches. Do not treat a clean scan as proof of security.


#We will use:
#Model: VulnLLM-R-7B
#Runtime: llama.cpp
#Backend: Python + FastAPI
#Frontend: HTML, CSS and Javascript

#Requires Python 3.10 or newer.

#Mac OS:
brew install llama.cpp

#Windows Powershell:
winget install llama.cpp

#Start the model:
#Works on Both Windows and Mac:

llama-server -hf Mungert/VulnLLM-R-7B-GGUF:Q4_K_M --host 127.0.0.1 --port 8080 -c 8192

#This downloads the quantized model and starts an inference server

#Create the python backend and web interface


#bash
mkdir VULN_AI_SCANNER
cd VULN_AI_SCANNER
python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python3 -m pip3 install -r requirements.txt OR pip3 install fastapi uvicorn requests
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

#Open <http://127.0.0.1:8000>. Stop the development server with `Ctrl+C`.

#input code below into the web interface to test functionality:

void process(char *input) {
    char buffer[10];
    strcpy(buffer, input);
}

The upload endpoint limits a scan to 50 files, 512 KB per file, and 5 MB total file data (including skipped files). Streaming multipart limits reject oversized data before file buffers can roll to disk, and a separate raw-body cap allows 256 KB for multipart overhead. Only supported UTF-8 text source files are scanned. The server requires loopback connections and local Host headers; API requests from other origins are rejected. Keep the server bound to `127.0.0.1`. See [upload review](docs/UPLOAD_REVIEW.md) for tested boundaries and limitations.

## Free vulnerability intelligence setup

No key is required to start. CVE.org uses `POST https://search.cve.org/search` with a JSON `cveIds` filter. NVD uses `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`. An optional NVD key is sent only in the `apiKey` header.

