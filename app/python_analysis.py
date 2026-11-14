"""Inspect Python syntax without importing or executing uploaded modules."""

import ast
import io
import re
import tokenize

from app.sql_analysis import analyze_sql


CREDENTIAL_NAME = re.compile(r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)", re.IGNORECASE)
CONVENTIONAL_NAMES = {
    "eval": "builtins.eval", "exec": "builtins.exec", "builtins": "builtins",
    "pickle": "pickle", "yaml": "yaml", "subprocess": "subprocess",
    "SafeLoader": "yaml.SafeLoader", "CSafeLoader": "yaml.CSafeLoader",
}
SHELL_APIS = {f"subprocess.{name}" for name in ("run", "Popen", "call", "check_call", "check_output")}
SAFE_LOADERS = {"yaml.SafeLoader", "yaml.CSafeLoader"}


def literal_credential(value):
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return len(value.value) >= 4 and not any(char.isspace() for char in value.value)
    return False


class Bindings(ast.NodeVisitor):
    """Collect lexical bindings, stopping at nested scopes. Rebindings stay unknown."""

    def __init__(self):
        self.names: dict[str, str | None] = {}
        self.outside: set[str] = set()
        self.globals: set[str] = set()

    def bind(self, name, target=None):
        if name not in self.names:
            self.names[name] = target
        elif self.names[name] != target:
            self.names[name] = None

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id)

    def visit_Import(self, node):
        for alias in node.names:
            self.bind(alias.asname or alias.name.split(".")[0], alias.name if alias.asname else alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                target = f"{node.module}.{alias.name}" if node.level == 0 and node.module else None
                self.bind(alias.asname or alias.name, target)

    def visit_FunctionDef(self, node):
        self.bind(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        pass

    def visit_ListComp(self, node):
        pass

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Global(self, node):
        self.outside.update(node.names)
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        self.outside.update(node.names)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node):
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)

    visit_MatchStar = visit_MatchAs

    def visit_MatchMapping(self, node):
        if node.rest:
            self.bind(node.rest)
        self.generic_visit(node)


class PythonAnalysis(ast.NodeVisitor):
    def __init__(self, tree):
        self.scopes = []
        self.matches = []
        self.module_live = {}
        self.push_scope(tree.body, "module")

    def push_scope(self, body, kind, arguments=None):
        bindings = Bindings()
        for statement in body:
            bindings.visit(statement)
        if arguments:
            for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
                bindings.bind(argument.arg)
            for argument in (arguments.vararg, arguments.kwarg):
                if argument:
                    bindings.bind(argument.arg)
        names = {name: value for name, value in bindings.names.items() if kind == "module" or name not in bindings.outside}
        self.scopes.append((kind, names, bindings.globals))

    def resolve(self, node):
        if isinstance(node, ast.Name):
            for index in range(len(self.scopes) - 1, -1, -1):
                kind, names, globals_ = self.scopes[index]
                if node.id in globals_ and kind != "module":
                    return self.scopes[0][1].get(node.id, CONVENTIONAL_NAMES.get(node.id))
                # Methods do not close over the namespace of their class.
                if kind == "class" and index != len(self.scopes) - 1:
                    continue
                if kind == "module" and not any(scope[0] in {"function", "comprehension"} for scope in self.scopes):
                    return self.module_live.get(node.id, CONVENTIONAL_NAMES.get(node.id))
                if node.id in names:
                    return names[node.id]
            return CONVENTIONAL_NAMES.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def flag(self, rule, node):
        self.matches.append((rule, node.lineno, node.end_lineno or node.lineno))

    def module_binding(self, node):
        if len(self.scopes) == 1:
            bindings = Bindings()
            bindings.visit(node)
            self.module_live.update(bindings.names)

    def visit_Import(self, node):
        self.module_binding(node)

    visit_ImportFrom = visit_Import

    def visit_Call(self, node):
        function = self.resolve(node.func)
        if function in {"builtins.eval", "builtins.exec"}:
            self.flag("PY-EVAL" if function.endswith(".eval") else "PY-EXEC", node)
        elif function in {"pickle.load", "pickle.loads"}:
            self.flag("PY-PICKLE", node)
        elif function == "yaml.load":
            loader = next((keyword.value for keyword in node.keywords if keyword.arg == "Loader"), None)
            if loader is None and len(node.args) >= 2:
                loader = node.args[1]
            if self.resolve(loader) not in SAFE_LOADERS:
                self.flag("PY-YAML", node)
        elif function in SHELL_APIS:
            if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                self.flag("PY-SHELL", node)
        self.generic_visit(node)

    def credential(self, target, value, span):
        name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else None
        if name and CREDENTIAL_NAME.fullmatch(name) and literal_credential(value):
            self.flag("HARDCODED-SECRET", span)

    def visit_Assign(self, node):
        for target in node.targets:
            self.credential(target, node.value, node)
        self.generic_visit(node)
        self.module_binding(node)

    def visit_AnnAssign(self, node):
        self.credential(node.target, node.value, node)
        self.generic_visit(node)
        self.module_binding(node)

    visit_NamedExpr = visit_AnnAssign

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str) and CREDENTIAL_NAME.fullmatch(key.value) and literal_credential(value):
                self.matches.append(("HARDCODED-SECRET", key.lineno, value.end_lineno or value.lineno))
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for expression in [*node.decorator_list, *node.args.defaults, *filter(None, node.args.kw_defaults)]:
            self.visit(expression)
        self.module_binding(node)
        self.push_scope(node.body, "function", node.args)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for expression in [*node.args.defaults, *filter(None, node.args.kw_defaults)]:
            self.visit(expression)
        self.push_scope([], "function", node.args)
        self.visit(node.body)
        self.scopes.pop()

    def visit_ClassDef(self, node):
        for expression in [*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords)]:
            self.visit(expression)
        self.push_scope(node.body, "class")
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.module_binding(node)

    def visit_ListComp(self, node):
        # The outermost iterable executes in the enclosing scope.
        first, *rest = node.generators
        self.visit(first.iter)
        bindings = Bindings()
        for generator in node.generators:
            bindings.visit(generator.target)
        self.scopes.append(("comprehension", bindings.names, set()))
        for condition in first.ifs:
            self.visit(condition)
        for generator in rest:
            self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.scopes.pop()

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


def analyze_python(source):
    try:
        tree = ast.parse(source)
        analysis = PythonAnalysis(tree)
        analysis.visit(tree)
        return analysis.matches + analyze_sql(tree), []
    except (SyntaxError, ValueError, RecursionError):
        return None, ["Python syntax could not be fully analyzed; token-based fallback used. Findings may be incomplete, and import aliases are not resolved in fallback mode."]


def mask_python(source):
    """Best-effort masking for invalid/incomplete files, preserving source offsets."""
    chars = list(source)
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    literals = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type not in {tokenize.COMMENT, tokenize.STRING}:
                continue
            start = offsets[token.start[0] - 1] + token.start[1]
            end = offsets[token.end[0] - 1] + token.end[1]
            if token.type == tokenize.STRING:
                try:
                    value = ast.literal_eval(token.string)
                    if isinstance(value, str):
                        literals.append((start, end, value))
                except (SyntaxError, ValueError, RecursionError):
                    pass
            for index in range(start, min(end, len(chars))):
                if chars[index] not in "\r\n":
                    chars[index] = " "
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return "".join(chars), literals
