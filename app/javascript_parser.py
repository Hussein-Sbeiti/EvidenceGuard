"""Tree-sitter syntax analysis for JavaScript, JSX, TypeScript, and TSX."""

import re
from functools import lru_cache

from tree_sitter import Language, Parser
import tree_sitter_javascript
import tree_sitter_typescript


FUNCTIONS = {"function_declaration", "function_expression", "generator_function", "generator_function_declaration", "arrow_function", "method_definition"}
SCOPES = FUNCTIONS | {"program", "statement_block", "catch_clause", "for_statement", "for_in_statement", "switch_body", "class"}
CREDENTIAL = re.compile(r"(?:password|passwd|secret|api[_-]?key|access[_-]?token)", re.I)


@lru_cache(maxsize=3)
def language(extension):
    if extension == ".tsx":
        return Language(tree_sitter_typescript.language_tsx())
    if extension == ".ts":
        return Language(tree_sitter_typescript.language_typescript())
    return Language(tree_sitter_javascript.language())


def field(node, name):
    return node.child_by_field_name(name) if node else None


def text(node):
    return node.text.decode("utf-8") if node else ""


def pattern_names(node):
    if not node:
        return set()
    if node.type in {"identifier", "shorthand_property_identifier_pattern"}:
        return {text(node)}
    if node.type in {"required_parameter", "optional_parameter", "pair_pattern", "assignment_pattern"}:
        return pattern_names(field(node, "pattern") or field(node, "value") or field(node, "left"))
    if node.type in {"object_pattern", "array_pattern", "formal_parameters", "rest_pattern"}:
        return set().union(*(pattern_names(child) for child in node.named_children))
    return set()


def property_name(node):
    if not node:
        return ""
    if node.type in {"property_identifier", "identifier"}:
        return text(node)
    if node.type == "string":
        return text(node)[1:-1]
    return ""


def member(node):
    if node and node.type in {"member_expression", "subscript_expression"}:
        return field(node, "object"), property_name(field(node, "property") or field(node, "index"))
    return None, ""


def unwrap(node):
    while node and node.type in {"parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression", "type_assertion", "sequence_expression"}:
        expressions = [child for child in node.named_children if child.type not in {"type_arguments", "type_identifier", "type_annotation", "predefined_type"}]
        if not expressions:
            break
        node = expressions[-1] if node.type == "sequence_expression" else expressions[0]
    return node


def literal(node):
    if node and node.type in {"string", "template_string"}:
        if any(child.type == "template_substitution" for child in node.named_children):
            return None
        return text(node)[1:-1]
    return None


def analyze_javascript(source, extension):
    tree = Parser(language(extension)).parse(source.encode("utf-8"))
    root = tree.root_node
    scopes = {}
    node_scopes = {}
    all_nodes = []
    stack = [(root, [])]
    while stack:
        node, ancestors = stack.pop()
        if node.type == "ERROR":
            continue
        if node.type in {"function_declaration", "generator_function_declaration", "class_declaration"} and ancestors:
            scopes[ancestors[-1].id].update(pattern_names(field(node, "name")))
        if node.type in SCOPES:
            ancestors = [*ancestors, node]
            scopes[node.id] = set()
            if node.type in FUNCTIONS:
                scopes[node.id].update(pattern_names(field(node, "parameters") or field(node, "parameter")))
                if node.type in {"function_expression", "generator_function"}:
                    scopes[node.id].update(pattern_names(field(node, "name")))
            if node.type == "catch_clause":
                scopes[node.id].update(pattern_names(field(node, "parameter")))
            if node.type == "for_in_statement":
                scope = next((parent for parent in reversed(ancestors) if parent.type in FUNCTIONS | {"program"}), node) if any(child.type == "var" for child in node.children) else node
                scopes[scope.id].update(pattern_names(field(node, "left")))
            if node.type == "class":
                scopes[node.id].update(pattern_names(field(node, "name")))
        node_scopes[node.id] = ancestors
        all_nodes.append(node)
        if node.type == "variable_declarator":
            scope = ancestors[-1]
            if node.parent.type == "variable_declaration":
                scope = next((parent for parent in reversed(ancestors) if parent.type in FUNCTIONS | {"program"}), scope)
            scopes[scope.id].update(pattern_names(field(node, "name")))
        elif node.type == "import_clause":
            for child in node.named_children:
                if child.type == "identifier":
                    scopes[ancestors[-1].id].add(text(child))
        elif node.type == "import_specifier":
            scopes[ancestors[-1].id].update(pattern_names(field(node, "alias") or field(node, "name")))
        elif node.type == "namespace_import":
            for child in node.named_children:
                scopes[ancestors[-1].id].update(pattern_names(child))
        stack.extend((child, ancestors) for child in reversed(node.named_children))

    def unbound(name, node):
        return not any(name in scopes[parent.id] for parent in node_scopes[node.id])

    matches = []
    def flag(rule, node):
        matches.append((rule, node.start_point.row + 1, node.end_point.row + 1))

    for node in all_nodes:
        if node.type == "call_expression":
            function = unwrap(field(node, "function"))
            obj, name = member(function)
            if function and function.type == "identifier" and text(function) == "eval" and unbound("eval", node):
                flag("JS-EVAL", node)
            elif name == "eval" and text(obj) in {"window", "globalThis"} and unbound(text(obj), node):
                flag("JS-EVAL", node)
            elif name == "write" and text(obj) == "document" and unbound("document", node):
                flag("JS-DOCUMENT-WRITE", node)
        if node.type in {"assignment_expression", "augmented_assignment_expression"}:
            target = field(node, "left")
            if member(target)[1] == "innerHTML":
                flag("JS-INNERHTML", node)
        if node.type in {"variable_declarator", "assignment_expression", "pair", "public_field_definition"}:
            target = field(node, "name") or field(node, "left") or field(node, "key")
            name = member(target)[1] or property_name(target)
            value = literal(field(node, "value") or field(node, "right"))
            if CREDENTIAL.fullmatch(name) and value and len(value) >= 4 and not any(char.isspace() for char in value):
                flag("HARDCODED-SECRET", node)
    warnings = ["JavaScript/TypeScript syntax contains errors; parser recovery was used. Findings may be incomplete."] if root.has_error else []
    return matches, warnings
