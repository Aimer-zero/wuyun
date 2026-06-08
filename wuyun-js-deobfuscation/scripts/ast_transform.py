#!/usr/bin/env python3
"""Conservative local JavaScript deobfuscation transforms for Wuyun.

The script does not execute target JavaScript. It performs deterministic local
rewrites for common string-array and simple dispatcher patterns, then writes the
result to a separate output file when --apply is used.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


STRING_ARRAY_RE = re.compile(
    r"\b(?:var|let|const)\s+([_$A-Za-z][\w$]*)\s*=\s*(\[(?:\s*['\"][^'\"]*['\"]\s*,?){2,}\])\s*;",
    re.S,
)
PICKER_RE_TEMPLATE = r"function\s+{name}\s*\(\s*([_$A-Za-z][\w$]*)\s*\)\s*\{{\s*return\s+{array}\s*\[\s*\1\s*\]\s*;?\s*\}}"
CALL_RE_TEMPLATE = r"\b{name}\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)"
INDEX_RE_TEMPLATE = r"\b{name}\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]"
SPLIT_DISPATCH_RE = re.compile(
    r"(?:var|let|const)\s+([_$A-Za-z][\w$]*)\s*=\s*['\"]([0-9A-Za-z_|-]+)['\"]\.split\(['\"]\|['\"]\)\s*,\s*([_$A-Za-z][\w$]*)\s*=\s*0\s*;",
    re.S,
)
SWITCH_RE_TEMPLATE = (
    r"while\s*\(\s*!!\[\]\s*\|?\|?\s*true\s*\)\s*\{{\s*"
    r"switch\s*\(\s*{order}\s*\[\s*{index}\+\+\s*\]\s*\)\s*\{{(?P<body>.*?)\}}\s*break\s*;?\s*\}}"
)

BABEL_TRANSFORM_JS = r"""
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const t = require("@babel/types");

const payload = JSON.parse(fs.readFileSync(0, "utf8"));
const ast = parser.parse(payload.code, {
  sourceType: "unambiguous",
  plugins: ["jsx", "typescript", "classProperties", "dynamicImport"],
  errorRecovery: true
});
const arrays = new Map();
const pickers = new Map();
const stats = {
  string_arrays_found: 0,
  picker_functions_found: 0,
  literal_replacements: 0,
  unicode_decodes: 0,
  simple_control_flow_recoveries: 0
};

traverse(ast, {
  VariableDeclarator(path) {
    const id = path.node.id;
    const init = path.node.init;
    if (!t.isIdentifier(id) || !t.isArrayExpression(init)) return;
    const values = [];
    for (const item of init.elements) {
      if (!t.isStringLiteral(item)) return;
      values.push(item.value);
    }
    if (values.length >= 2) {
      arrays.set(id.name, values);
      stats.string_arrays_found += 1;
    }
  }
});

traverse(ast, {
  FunctionDeclaration(path) {
    const node = path.node;
    if (!node.id || node.params.length !== 1 || !t.isIdentifier(node.params[0])) return;
    const param = node.params[0].name;
    if (node.body.body.length !== 1 || !t.isReturnStatement(node.body.body[0])) return;
    const ret = node.body.body[0].argument;
    if (!t.isMemberExpression(ret) || !t.isIdentifier(ret.object) || !t.isIdentifier(ret.property, { name: param })) return;
    if (!arrays.has(ret.object.name)) return;
    pickers.set(node.id.name, ret.object.name);
    stats.picker_functions_found += 1;
  }
});

traverse(ast, {
  MemberExpression(path) {
    const node = path.node;
    if (!t.isIdentifier(node.object) || !t.isNumericLiteral(node.property)) return;
    const values = arrays.get(node.object.name);
    if (!values) return;
    const idx = node.property.value;
    if (idx >= 0 && idx < values.length) {
      path.replaceWith(t.stringLiteral(values[idx]));
      stats.literal_replacements += 1;
    }
  },
  CallExpression(path) {
    const node = path.node;
    if (!t.isIdentifier(node.callee) || node.arguments.length !== 1 || !t.isNumericLiteral(node.arguments[0])) return;
    const arrayName = pickers.get(node.callee.name);
    if (!arrayName) return;
    const values = arrays.get(arrayName);
    const idx = node.arguments[0].value;
    if (values && idx >= 0 && idx < values.length) {
      path.replaceWith(t.stringLiteral(values[idx]));
      stats.literal_replacements += 1;
    }
  },
  StringLiteral(path) {
    if (/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/.test(path.node.extra && path.node.extra.raw || "")) {
      stats.unicode_decodes += 1;
    }
  }
});

const output = generate(ast, { comments: true, compact: false, jsescOption: { minimal: true } }, payload.code).code + "\n";
process.stdout.write(JSON.stringify({ code: output, stats, engine: "babel" }));
"""


@dataclass
class TransformStats:
    string_arrays_found: int = 0
    picker_functions_found: int = 0
    literal_replacements: int = 0
    unicode_decodes: int = 0
    simple_control_flow_recoveries: int = 0


def js_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def parse_js_string_array(raw: str) -> list[str] | None:
    try:
        # JS single/double-quoted string arrays are close enough to Python
        # literals for conservative local samples; reject anything dynamic.
        parsed = ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return None
    if isinstance(parsed, list) and all(isinstance(item, str) for item in parsed):
        return parsed
    return None


def decode_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def replace_array_references(text: str, array_name: str, values: list[str], stats: TransformStats) -> str:
    pattern = re.compile(INDEX_RE_TEMPLATE.format(name=re.escape(array_name)))

    def repl(match: re.Match[str]) -> str:
        idx = decode_int(match.group(1))
        if 0 <= idx < len(values):
            stats.literal_replacements += 1
            return js_string(values[idx])
        return match.group(0)

    return pattern.sub(repl, text)


def replace_picker_calls(text: str, picker_name: str, values: list[str], stats: TransformStats) -> str:
    pattern = re.compile(CALL_RE_TEMPLATE.format(name=re.escape(picker_name)))

    def repl(match: re.Match[str]) -> str:
        idx = decode_int(match.group(1))
        if 0 <= idx < len(values):
            stats.literal_replacements += 1
            return js_string(values[idx])
        return match.group(0)

    return pattern.sub(repl, text)


def decode_escaped_literals(text: str, stats: TransformStats) -> str:
    string_re = re.compile(r"(['\"])((?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\.|(?!\1).)*)(\1)")

    def repl(match: re.Match[str]) -> str:
        content = match.group(2)
        if "\\x" not in content and "\\u" not in content:
            return match.group(0)
        try:
            decoded = bytes(content, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return match.group(0)
        stats.unicode_decodes += 1
        return js_string(decoded)

    return string_re.sub(repl, text)


def find_picker_functions(text: str, array_name: str) -> list[str]:
    names: list[str] = []
    for match in re.finditer(r"\bfunction\s+([_$A-Za-z][\w$]*)\s*\(", text):
        name = match.group(1)
        pattern = re.compile(PICKER_RE_TEMPLATE.format(name=re.escape(name), array=re.escape(array_name)), re.S)
        if pattern.search(text):
            names.append(name)
    return names


def recover_simple_control_flow(text: str, stats: TransformStats) -> str:
    dispatch = SPLIT_DISPATCH_RE.search(text)
    if not dispatch:
        return text
    order_name, order_raw, index_name = dispatch.groups()
    order = order_raw.split("|")
    switch_pattern = re.compile(
        SWITCH_RE_TEMPLATE.format(order=re.escape(order_name), index=re.escape(index_name)),
        re.S,
    )
    switch = switch_pattern.search(text)
    if not switch:
        return text
    body = switch.group("body")
    cases: dict[str, str] = {}
    for case_match in re.finditer(r"case\s+['\"]([^'\"]+)['\"]\s*:\s*(.*?)(?:continue\s*;|break\s*;)", body, re.S):
        cases[case_match.group(1)] = case_match.group(2).strip()
    if not cases or any(item not in cases for item in order):
        return text
    recovered = "\n".join(cases[item] for item in order)
    stats.simple_control_flow_recoveries += 1
    return text[: dispatch.start()] + "/* Wuyun recovered simple dispatcher */\n" + recovered + text[switch.end():]


def transform(text: str) -> tuple[str, TransformStats]:
    stats = TransformStats()
    out = decode_escaped_literals(text, stats)
    arrays: dict[str, list[str]] = {}
    for match in STRING_ARRAY_RE.finditer(out):
        values = parse_js_string_array(match.group(2))
        if values is None:
            continue
        arrays[match.group(1)] = values
        stats.string_arrays_found += 1
    for array_name, values in arrays.items():
        out = replace_array_references(out, array_name, values, stats)
        picker_names = find_picker_functions(out, array_name)
        stats.picker_functions_found += len(picker_names)
        for picker_name in picker_names:
            out = replace_picker_calls(out, picker_name, values, stats)
    out = recover_simple_control_flow(out, stats)
    return out, stats


def transform_with_babel(text: str) -> tuple[str, TransformStats] | None:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as script:
        script.write(BABEL_TRANSFORM_JS)
        script_path = script.name
    try:
        proc = subprocess.run(
            ["node", script_path],
            input=json.dumps({"code": text}),
            text=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        Path(script_path).unlink(missing_ok=True)
    if proc.returncode != 0:
        return None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    stats = TransformStats(**payload.get("stats", {}))
    # Babel backend currently handles AST-safe literals/pickers; keep the
    # conservative simple dispatcher recovery as a second pass.
    out = recover_simple_control_flow(str(payload["code"]), stats)
    return out, stats


def unified_diff(original: str, transformed: str, fromfile: str, tofile: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            transformed.splitlines(keepends=True),
            fromfile=fromfile,
            tofile=tofile,
            n=3,
        )
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run conservative local JS deobfuscation transforms.")
    parser.add_argument("input", help="input JS file")
    parser.add_argument("--output", help="output JS file; required with --apply")
    parser.add_argument("--apply", action="store_true", help="write transformed output")
    parser.add_argument("--diff", action="store_true", help="print unified diff")
    parser.add_argument("--engine", choices=["auto", "babel", "python"], default="auto", help="transform backend")
    parser.add_argument("--json", action="store_true", help="emit JSON summary")
    args = parser.parse_args(argv)

    input_path = Path(args.input).resolve()
    if input_path.suffix.lower() not in {".js", ".mjs", ".cjs"}:
        print("error: ast_transform currently accepts .js/.mjs/.cjs files only", file=sys.stderr)
        return 2
    if args.apply and not args.output:
        print("error: --output is required with --apply", file=sys.stderr)
        return 2
    if args.output and Path(args.output).resolve() == input_path:
        print("error: output must not overwrite input", file=sys.stderr)
        return 2

    original = input_path.read_text(encoding="utf-8", errors="replace")
    engine_used = "python"
    transformed_stats = None
    if args.engine in {"auto", "babel"}:
        transformed_stats = transform_with_babel(original)
        if transformed_stats:
            engine_used = "babel"
        elif args.engine == "babel":
            print("error: Babel backend unavailable; install @babel/parser @babel/traverse @babel/generator @babel/types or use --engine python", file=sys.stderr)
            return 2
    if transformed_stats:
        transformed, stats = transformed_stats
    else:
        transformed, stats = transform(original)
    changed = original != transformed
    payload = {
        "input": str(input_path),
        "output": str(Path(args.output).resolve()) if args.output else None,
        "changed": changed,
        "engine": engine_used,
        "stats": stats.__dict__,
        "limits": [
            "does not execute JavaScript",
            "auto mode prefers Babel AST when local dependencies exist, then falls back to conservative Python transforms",
            "handles string-array/picker rewrites and simple dispatcher recovery only",
            "review transformed output before using it as evidence",
        ],
    }
    if args.apply:
        Path(args.output).write_text(transformed, encoding="utf-8")
        payload["status"] = "written"
    else:
        payload["status"] = "dry-run"

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("# Wuyun JS AST Transform")
        print()
        print(f"- Status: `{payload['status']}`")
        print(f"- Engine: `{engine_used}`")
        print(f"- Changed: `{changed}`")
        for key, value in payload["stats"].items():
            print(f"- {key}: `{value}`")
        print()
        if args.diff:
            print("## Diff")
            print("```diff")
            print(unified_diff(original, transformed, str(input_path), args.output or "<transformed>")[:12000])
            print("```")
        print("## Limits")
        for item in payload["limits"]:
            print(f"- {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
