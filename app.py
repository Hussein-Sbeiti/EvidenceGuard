from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests

app = FastAPI()

MODEL_API = "http://127.0.0.1:8080/v1/chat/completions"

class AnalysisRequest(BaseModel):
    code: str
    language: str

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Analyzer</title>
        <style>
            body {
                font-family: Arial;
                max-width: 900px;
                margin: 40px auto;
                padding: 20px;
                background: #101827;
                color: white;
            }
            textarea {
                width: 100%;
                height: 300px;
                background: #1e293b;
                color: white;
                padding: 12px;
                box-sizing: border-box;
                border: 1px solid #475569;
                border-radius: 8px;
            }
            select, button {
                padding: 12px;
                margin: 12px 0;
                border-radius: 6px;
            }
            button {
                background: #2563eb;
                color: white;
                border: none;
                cursor: pointer;
            }
            pre {
                white-space: pre-wrap;
                overflow-wrap: anywhere;
                background: #1e293b;
                padding: 20px;
                border-radius: 8px;
            }
        </style>
    </head>
    <body>
        <h1>VulnLLM Security Analyzer</h1>
        <p>Submit source code for vulnerability analysis.</p>

        <label>Programming language</label><br>
        <select id="language">
            <option>C</option>
            <option>C++</option>
            <option>Python</option>
            <option>Java</option>
        </select>

        <h3>Source code</h3>
        <textarea id="code"
          placeholder="Paste your source code here..."></textarea>

        <br>
        <button onclick="analyze()">Analyze Code</button>

        <h2>Analysis Results</h2>
        <pre id="output">Results will appear here...</pre>

        <script>
        async function analyze() {
            const code = document.getElementById("code").value;
            const language = document.getElementById("language").value;
            const output = document.getElementById("output");

            if (!code.trim()) {
                output.textContent = "Please enter source code.";
                return;
            }

            output.textContent = "Analyzing code...";

            try {
                const response = await fetch("/analyze", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({code, language})
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.detail || "Analysis failed");
                }

                output.textContent = result.analysis;

            } catch (error) {
                output.textContent = "Error: " + error.message;
            }
        }
        </script>
    </body>
    </html>
    """

@app.post("/analyze")
def analyze(request: AnalysisRequest):

    prompt = f"""
You are a software vulnerability analysis specialist.

Analyze the following {request.language} source code.

Identify:
1. Whether vulnerabilities exist.
2. Vulnerability type and CWE identifier, if applicable.
3. Vulnerable code locations.
4. Technical explanation and root cause.
5. Exploitability conditions.
6. Recommended remediation.

Distinguish confirmed vulnerabilities from potential issues.
Do not invent vulnerabilities.

SOURCE CODE:

{request.code}
"""

    payload = {
        "model": "VulnLLM-R-7B",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "max_tokens": 4096
    }

    response = requests.post(
        MODEL_API,
        json=payload,
        timeout=600
    )

    response.raise_for_status()

    result = response.json()

    return {
        "analysis": result["choices"][0]["message"]["content"]
    }
