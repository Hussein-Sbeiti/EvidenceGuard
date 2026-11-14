"""Bounded, intra-procedural SQL construction analysis. Never executes SQL."""

import ast
import re
from dataclasses import dataclass


SQL = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|WITH)\b", re.I)
SINKS = {"execute", "executemany", "executescript"}


@dataclass(frozen=True)
class Value:
    text: str | None = None
    dynamic: bool = True
    sql: bool = False


def string(text, dynamic=False, sql=False):
    return Value(text[:4096], dynamic, sql or bool(SQL.search(text)))


def value(node, env):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return string(node.value)
        return Value(str(node.value), False)
    if isinstance(node, ast.Name):
        return env.get(node.id, Value())
    if isinstance(node, ast.JoinedStr):
        parts = [value(part.value, env) if isinstance(part, ast.FormattedValue) else value(part, env) for part in node.values]
        return string("".join(part.text or "" for part in parts), any(part.dynamic for part in parts), any(part.sql for part in parts))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left, right = value(node.left, env), value(node.right, env)
        return string((left.text or "") + (right.text or ""), left.dynamic or right.dynamic, left.sql or right.sql)
    if isinstance(node, (ast.Tuple, ast.List, ast.Dict)):
        children = node.values if isinstance(node, ast.Dict) else node.elts
        parts = [value(child, env) for child in children]
        return Value(None, any(part.dynamic for part in parts), any(part.sql for part in parts))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        base = value(node.func.value, env)
        args = [value(arg, env) for arg in node.args] + [value(arg.value, env) for arg in node.keywords]
        return string(base.text or "", base.dynamic or any(arg.dynamic for arg in args), base.sql)
    if isinstance(node, ast.IfExp):
        return merge_value(value(node.body, env), value(node.orelse, env))
    return Value()


def merge_value(left, right):
    return Value(left.text if left.text == right.text else None, left.dynamic or right.dynamic, left.sql or right.sql)


def merge_env(left, right):
    return {name: merge_value(left.get(name, Value()), right.get(name, Value())) for name in left.keys() | right.keys()}


class SqlAnalysis:
    def __init__(self):
        self.matches = []

    def inspect(self, expression, env):
        if expression is None:
            return
        stack = [expression]
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in SINKS:
                query = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg in {"sql", "query", "operation"}), None)
                query_value = value(query, env)
                if query_value.sql and query_value.dynamic:
                    self.matches.append(("PY-SQL-INJECTION", node.lineno, node.end_lineno or node.lineno))
            stack.extend(ast.iter_child_nodes(node))

    def block(self, statements, env):
        env = env.copy()
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in [*node.args.defaults, *filter(None, node.args.kw_defaults)]:
                    self.inspect(default, env)
                local = env.copy()
                for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, *filter(None, [node.args.vararg, node.args.kwarg])]:
                    local[argument.arg] = Value()
                self.block(node.body, local)
            elif isinstance(node, ast.ClassDef):
                self.block(node.body, env)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                self.inspect(node.value, env)
                resolved = value(node.value, env)
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Name):
                        env[target.id] = resolved
            elif isinstance(node, ast.AugAssign):
                self.inspect(node.value, env)
                if isinstance(node.target, ast.Name):
                    left, right = env.get(node.target.id, Value()), value(node.value, env)
                    env[node.target.id] = string((left.text or "") + (right.text or ""), left.dynamic or right.dynamic, left.sql or right.sql)
            elif isinstance(node, ast.If):
                self.inspect(node.test, env)
                env = merge_env(self.block(node.body, env), self.block(node.orelse, env))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self.inspect(node.test if isinstance(node, ast.While) else node.iter, env)
                loop = env.copy()
                if not isinstance(node, ast.While) and isinstance(node.target, ast.Name):
                    loop[node.target.id] = Value()
                env = merge_env(env, self.block(node.body, loop))
                env = self.block(node.orelse, env)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self.inspect(item.context_expr, env)
                    if isinstance(item.optional_vars, ast.Name):
                        env[item.optional_vars.id] = Value()
                env = self.block(node.body, env)
            elif isinstance(node, ast.Try):
                paths = [self.block(node.orelse, self.block(node.body, env))]
                paths += [self.block(handler.body, env) for handler in node.handlers]
                env = paths[0]
                for path in paths[1:]:
                    env = merge_env(env, path)
                env = self.block(node.finalbody, env)
            else:
                self.inspect(node, env)
        return env


def analyze_sql(tree):
    analysis = SqlAnalysis()
    analysis.block(tree.body, {})
    return analysis.matches
