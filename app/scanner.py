import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath


SUPPORTED_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".php",
    ".py",
    ".rb",
    ".ts",
    ".tsx",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: str
    description: str
    recommendation: str
    fix_example: str
    languages: frozenset[str]
    pattern: re.Pattern[str]


RULES = (
    Rule(
        id="PY-EVAL",
        title="Dynamic code execution with eval",
        severity="high",
        cwe="CWE-95",
        description="eval() executes a string as code and can run attacker-controlled input.",
        recommendation="Avoid evaluating input as code. Parse the expected data format or use an explicit allowlist.",
        fix_example="value = json.loads(input_text)",
        languages=frozenset({".py"}),
        pattern=re.compile(r"\beval\s*\("),
    ),
    Rule(
        id="PY-EXEC",
        title="Dynamic code execution with exec",
        severity="high",
        cwe="CWE-95",
        description="exec() executes dynamically constructed Python code.",
        recommendation="Replace dynamic execution with explicit operations or a restricted parser.",
        fix_example="# Parse input as data; do not pass it to exec().",
        languages=frozenset({".py"}),
        pattern=re.compile(r"\bexec\s*\("),
    ),
    Rule(
        id="PY-PICKLE",
        title="Unsafe pickle deserialization",
        severity="high",
        cwe="CWE-502",
        description="Loading pickle data from an untrusted source can execute arbitrary code.",
        recommendation="Do not unpickle untrusted data. Use a data-only format such as JSON.",
        fix_example="value = json.loads(serialized_text)",
        languages=frozenset({".py"}),
        pattern=re.compile(r"\bpickle\s*\.\s*loads?\s*\("),
    ),
    Rule(
        id="PY-YAML",
        title="Potentially unsafe YAML deserialization",
        severity="medium",
        cwe="CWE-502",
        description="yaml.load() may construct Python objects when used without a safe loader.",
        recommendation="Use yaml.safe_load() for untrusted YAML input.",
        fix_example="value = yaml.safe_load(document)",
        languages=frozenset({".py"}),
        pattern=re.compile(r"\byaml\s*\.\s*load\s*\("),
    ),
    Rule(
        id="PY-SHELL",
        title="Shell command built with shell=True",
        severity="high",
        cwe="CWE-78",
        description="Passing a command through a shell can make untrusted input executable as shell syntax.",
        recommendation="Pass an argument list to subprocess and leave shell=False (the default).",
        fix_example='subprocess.run(["tool", user_value], check=True)',
        languages=frozenset({".py"}),
        pattern=re.compile(r"\bshell\s*=\s*True\b"),
    ),
    Rule(
        id="JS-EVAL",
        title="Dynamic code execution with eval",
        severity="high",
        cwe="CWE-95",
        description="eval() interprets a string as JavaScript and can execute attacker-controlled input.",
        recommendation="Avoid eval(). Parse structured data or dispatch through an explicit allowlist.",
        fix_example="const value = JSON.parse(inputText);",
        languages=frozenset({".js", ".jsx", ".ts", ".tsx"}),
        pattern=re.compile(r"\beval\s*\("),
    ),
    Rule(
        id="JS-INNERHTML",
        title="HTML inserted through innerHTML",
        severity="medium",
        cwe="CWE-79",
        description="Assigning untrusted text to innerHTML can enable cross-site scripting.",
        recommendation="Use textContent for plain text, or sanitize HTML with a maintained allowlist sanitizer.",
        fix_example="element.textContent = userProvidedText;",
        languages=frozenset({".js", ".jsx", ".ts", ".tsx"}),
        pattern=re.compile(r"\.innerHTML\s*="),
    ),
    Rule(
        id="JS-DOCUMENT-WRITE",
        title="HTML written with document.write",
        severity="medium",
        cwe="CWE-79",
        description="document.write() can interpret attacker-controlled strings as HTML.",
        recommendation="Create DOM nodes and assign untrusted strings with textContent.",
        fix_example="document.body.textContent = userProvidedText;",
        languages=frozenset({".js", ".jsx", ".ts", ".tsx"}),
        pattern=re.compile(r"\bdocument\s*\.\s*write\s*\("),
    ),
    Rule(
        id="HARDCODED-SECRET",
        title="Possible hard-coded credential",
        severity="medium",
        cwe="CWE-798",
        description="A credential-like value appears to be assigned directly in source code.",
        recommendation="Load secrets from a local environment or secret manager, and rotate any exposed credential.",
        fix_example='api_key = os.environ["API_KEY"]',
        languages=frozenset(SUPPORTED_EXTENSIONS),
        pattern=re.compile(
            r"""(?ix)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b"""
            r"""\s*[:=]\s*(['"])[^'"\s]{4,}\1"""
        ),
    ),
)


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str
    title: str
    severity: str
    cwe: str
    description: str
    recommendation: str
    fix_example: str
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def display_filename(filename: str) -> str:
    """Keep browser-supplied folder paths for display without using them on disk."""
    normalized = filename.replace("\\", "/")
    parts = [part for part in PurePosixPath(normalized).parts if part not in {"", ".", "..", "/"}]
    return "/".join(parts) or "uploaded-file"


def scan_source(filename: str, source: str) -> list[Finding]:
    extension = PurePosixPath(filename.replace("\\", "/")).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        return []

    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        for rule in RULES:
            if extension not in rule.languages or not rule.pattern.search(line):
                continue
            if rule.id == "PY-YAML" and re.search(
                r"\b(?:yaml\s*\.\s*safe_load|Loader\s*=\s*(?:yaml\s*\.\s*)?SafeLoader)\b",
                line,
            ):
                continue
            findings.append(
                Finding(
                    file=display_filename(filename),
                    line=line_number,
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    description=rule.description,
                    recommendation=rule.recommendation,
                    fix_example=rule.fix_example,
                    evidence=line.strip()[:300],
                )
            )
    return findings
