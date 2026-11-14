import re
from bisect import bisect_left, bisect_right
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath

from app.javascript_parser import analyze_javascript
from app.python_analysis import analyze_python, mask_python


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

CWE_NAMES = {
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-95": "Eval Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-798": "Use of Hard-coded Credentials",
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
        id="PY-SQL-INJECTION",
        title="SQL query constructed with dynamic values",
        severity="high",
        cwe="CWE-89",
        description="A SQL execution call receives a query built with interpolation, formatting, or concatenation. Untrusted values could change the SQL structure; review the data source.",
        recommendation="Bind data values with database parameters instead of inserting them into SQL text. Use an allowlist for SQL identifiers that cannot be parameterized.",
        fix_example='cursor.execute("SELECT username FROM users WHERE username = ?", (username,))',
        languages=frozenset({".py"}),
        pattern=re.compile(r"(?!)"),  # Requires AST and local value-flow analysis.
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
        pattern=re.compile(r"\.\s*innerHTML\s*=(?!=|>)"),
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
        result = asdict(self)
        result["cwe_name"] = CWE_NAMES.get(self.cwe, "Software weakness")
        return result


def display_filename(filename: str) -> str:
    """Keep browser-supplied folder paths for display without using them on disk."""
    normalized = filename.replace("\\", "/")
    parts = [part for part in PurePosixPath(normalized).parts if part not in {"", ".", "..", "/"}]
    return "/".join(parts) or "uploaded-file"


def analyze_source(filename: str, source: str) -> tuple[list[Finding], list[str]]:
    extension = PurePosixPath(filename.replace("\\", "/")).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        return [], []
    lines = source.splitlines()
    matches = []
    warnings = []
    if extension == ".py":
        matches, warnings = analyze_python(source)
        if matches is None:
            code, literals = mask_python(source)
            matches = lexical_matches(code, literals, extension)
    elif extension in {".js", ".jsx", ".ts", ".tsx"}:
        matches, warnings = analyze_javascript(source, extension)
    else:
        # The remaining languages still use the original credential heuristic.
        for line_number, line in enumerate(lines, 1):
            if RULES[-1].pattern.search(line):
                matches.append(("HARDCODED-SECRET", line_number, line_number))

    by_id = {rule.id: rule for rule in RULES}
    findings = []
    seen = set()
    rule_order = {rule.id: index for index, rule in enumerate(RULES)}
    for rule_id, start, end in sorted(matches, key=lambda match: (match[1], rule_order[match[0]])):
        if (rule_id, start) in seen:
            continue
        seen.add((rule_id, start))
        rule = by_id[rule_id]
        findings.append(Finding(
            file=display_filename(filename), line=start, rule_id=rule.id,
            title=rule.title, severity=rule.severity, cwe=rule.cwe,
            description=rule.description, recommendation=rule.recommendation,
            fix_example=rule.fix_example, evidence="\n".join(lines[start - 1:end]).strip()[:300],
        ))
    return findings, warnings


def lexical_matches(code: str, literals: list[tuple[int, int, str]], extension: str) -> list[tuple[str, int, int]]:
    """Find patterns across lines while preserving original source locations."""
    offsets = [index for index, char in enumerate(code) if char == "\n"]
    matches = []
    for rule in RULES:
        if extension not in rule.languages or rule.id == "HARDCODED-SECRET":
            continue
        for match in rule.pattern.finditer(code):
            # Function declarations and explicit member access aren't a direct
            # call to JavaScript's global eval function.
            if rule.id == "JS-EVAL":
                cursor = match.start() - 1
                while cursor >= 0 and code[cursor].isspace():
                    cursor -= 1
                if cursor >= 0 and code[cursor] in ".$":
                    continue
                end_word = cursor + 1
                while cursor >= 0 and (code[cursor].isalnum() or code[cursor] in "_$"):
                    cursor -= 1
                if code[cursor + 1:end_word] == "function":
                    continue
            start = bisect_right(offsets, match.start()) + 1
            end = bisect_right(offsets, match.end() - 1) + 1
            matches.append((rule.id, start, end))
    credential_prefix = re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=](?!=|>)"
    )
    literals = sorted(literals)
    literal_starts = [literal[0] for literal in literals]
    for assignment in credential_prefix.finditer(code):
        index = bisect_left(literal_starts, assignment.end())
        if index == len(literals):
            continue
        start, end, value = literals[index]
        if code[assignment.end():start].strip():
            continue
        if len(value) < 4 or any(char.isspace() for char in value):
            continue
        matches.append(("HARDCODED-SECRET", bisect_right(offsets, start) + 1, bisect_right(offsets, end - 1) + 1))
    return matches


def scan_source(filename: str, source: str) -> list[Finding]:
    """Compatibility entry point for callers that only need findings."""
    return analyze_source(filename, source)[0]
