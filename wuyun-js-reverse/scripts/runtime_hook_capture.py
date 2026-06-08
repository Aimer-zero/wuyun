#!/usr/bin/env python3
"""Generate or run browser runtime observation hooks for Wuyun JS reverse.

The hook records request/crypto metadata only. It does not bypass controls,
patch stealth fingerprints, steal credentials, or persist raw request bodies.
Running against a URL requires --authorize-runtime-observation and --scope-host.

`generate` emits concrete code artifacts, not just a plan:

- browser-js: an init-script hook for DevTools/Playwright/Puppeteer injection
- playwright-python: a standalone Playwright runner
- puppeteer: a standalone Puppeteer runner
- frida-android-webview: a Frida script template for authorized Android WebView labs
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


HOOK_JS = r"""
(() => {
  if (globalThis.__wuyunHookInstalled) return;
  globalThis.__wuyunHookInstalled = true;
  const PREFIX = "__WUYUN_HOOK__";
  const now = () => new Date().toISOString();
  const redactUrl = (value) => {
    try {
      const url = new URL(String(value), location.href);
      if (url.search) url.search = "?<query-redacted>";
      if (url.hash) url.hash = "#<fragment-redacted>";
      return url.toString();
    } catch (_) {
      return String(value).slice(0, 240);
    }
  };
  const bodyShape = (value) => {
    if (value == null) return { type: "none", length: 0 };
    if (typeof value === "string") return { type: "string", length: value.length };
    if (value instanceof ArrayBuffer) return { type: "ArrayBuffer", length: value.byteLength };
    if (ArrayBuffer.isView(value)) return { type: value.constructor.name, length: value.byteLength };
    if (typeof Blob !== "undefined" && value instanceof Blob) return { type: "Blob", length: value.size };
    if (typeof FormData !== "undefined" && value instanceof FormData) return { type: "FormData", length: Array.from(value.keys()).length };
    if (typeof URLSearchParams !== "undefined" && value instanceof URLSearchParams) return { type: "URLSearchParams", length: Array.from(value.keys()).length };
    return { type: value.constructor ? value.constructor.name : typeof value, length: null };
  };
  const headerShape = (headers) => {
    const out = [];
    const add = (name) => {
      const lower = String(name).toLowerCase();
      const sensitive = /authorization|cookie|token|secret|password|key/.test(lower);
      out.push({ name: lower, value: sensitive ? "<redacted>" : "<present>" });
    };
    try {
      if (!headers) return out;
      if (headers instanceof Headers) headers.forEach((_, key) => add(key));
      else if (Array.isArray(headers)) headers.forEach((item) => add(item[0]));
      else if (typeof headers === "object") Object.keys(headers).forEach(add);
    } catch (_) {}
    return out;
  };
  const emit = (event) => {
    try {
      console.log(PREFIX + JSON.stringify({ ts: now(), ...event }));
    } catch (_) {}
  };

  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === "function") {
    globalThis.fetch = function(input, init = {}) {
      const url = typeof input === "string" || input instanceof URL ? input : input && input.url;
      const method = (init && init.method) || (input && input.method) || "GET";
      emit({
        type: "fetch",
        method,
        url: redactUrl(url || ""),
        headers: headerShape(init.headers || (input && input.headers)),
        body: bodyShape(init.body),
      });
      return originalFetch.apply(this, arguments);
    };
  }

  const OriginalXHR = globalThis.XMLHttpRequest;
  if (OriginalXHR && OriginalXHR.prototype) {
    const open = OriginalXHR.prototype.open;
    const send = OriginalXHR.prototype.send;
    const setRequestHeader = OriginalXHR.prototype.setRequestHeader;
    OriginalXHR.prototype.open = function(method, url) {
      this.__wuyun = { method, url: redactUrl(url), headers: [] };
      return open.apply(this, arguments);
    };
    OriginalXHR.prototype.setRequestHeader = function(name, value) {
      if (this.__wuyun) this.__wuyun.headers.push({ name: String(name).toLowerCase(), value: /authorization|cookie|token|secret|password|key/i.test(name) ? "<redacted>" : "<present>" });
      return setRequestHeader.apply(this, arguments);
    };
    OriginalXHR.prototype.send = function(body) {
      emit({ type: "xhr", ...(this.__wuyun || {}), body: bodyShape(body) });
      return send.apply(this, arguments);
    };
  }

  const OriginalWebSocket = globalThis.WebSocket;
  if (typeof OriginalWebSocket === "function") {
    globalThis.WebSocket = function(url, protocols) {
      emit({ type: "websocket-connect", url: redactUrl(url), protocols: Array.isArray(protocols) ? protocols : (protocols ? [String(protocols)] : []) });
      const ws = protocols ? new OriginalWebSocket(url, protocols) : new OriginalWebSocket(url);
      const originalSend = ws.send;
      ws.send = function(data) {
        emit({ type: "websocket-send", url: redactUrl(url), body: bodyShape(data) });
        return originalSend.apply(this, arguments);
      };
      return ws;
    };
    Object.setPrototypeOf(globalThis.WebSocket, OriginalWebSocket);
    globalThis.WebSocket.prototype = OriginalWebSocket.prototype;
  }

  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) {
    ["digest", "sign", "verify", "importKey", "deriveKey", "encrypt", "decrypt"].forEach((name) => {
      const original = subtle[name];
      if (typeof original !== "function") return;
      subtle[name] = function(...args) {
        const algorithm = args[0] && (typeof args[0] === "string" ? args[0] : args[0].name);
        emit({ type: "crypto.subtle." + name, algorithm: algorithm || "<unknown>", arg_shapes: args.map(bodyShape) });
        return original.apply(this, args);
      };
    });
  }

  const wrapCryptoJS = () => {
    const c = globalThis.CryptoJS;
    if (!c || c.__wuyunWrapped) return;
    c.__wuyunWrapped = true;
    ["HmacSHA256", "HmacSHA1", "SHA256", "SHA1", "MD5", "AES"].forEach((name) => {
      const target = c[name];
      if (typeof target === "function") {
        c[name] = function(...args) {
          emit({ type: "CryptoJS." + name, arg_shapes: args.map(bodyShape) });
          return target.apply(this, args);
        };
      } else if (target && typeof target.encrypt === "function") {
        ["encrypt", "decrypt"].forEach((op) => {
          const original = target[op];
          target[op] = function(...args) {
            emit({ type: "CryptoJS." + name + "." + op, arg_shapes: args.map(bodyShape) });
            return original.apply(this, args);
          };
        });
      }
    });
  };
  wrapCryptoJS();
  setInterval(wrapCryptoJS, 1000);
  emit({ type: "hook-installed", url: redactUrl(location.href) });
})();
"""


def common_limits() -> list[str]:
    return [
        "metadata-only runtime observation",
        "query strings, sensitive headers, and request bodies are redacted or summarized",
        "no stealth fingerprint patching or protection bypass performed",
    ]


def standalone_playwright_python() -> str:
    return (
        """#!/usr/bin/env python3
\"\"\"Standalone Wuyun Playwright runtime hook capture.

Generated by wuyun-js-reverse/scripts/runtime_hook_capture.py.
Execution requires --authorize-runtime-observation and --scope-host.
\"\"\"
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


HOOK_JS = __HOOK_JSON__


def enforce_scope(url: str, scope_hosts: list[str]) -> None:
    host = urlparse(url).hostname or ""
    if host.lower() not in {item.lower() for item in scope_hosts}:
        raise ValueError(f"target host `{host}` is not in --scope-host allowlist")


async def run(args: argparse.Namespace) -> int:
    try:
        from playwright.async_api import async_playwright
    except Exception as exc:  # noqa: BLE001
        print(f"error: playwright is not installed or unavailable: {exc}", file=sys.stderr)
        return 2

    enforce_scope(args.url, args.scope_host)
    events: list[dict] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=args.headless)
        context = await browser.new_context(ignore_https_errors=False)
        await context.add_init_script(HOOK_JS)
        page = await context.new_page()

        def on_console(message):
            text = message.text
            if text.startswith("__WUYUN_HOOK__"):
                try:
                    events.append(json.loads(text.removeprefix("__WUYUN_HOOK__")))
                except json.JSONDecodeError:
                    pass

        page.on("console", on_console)
        await page.goto(args.url, wait_until=args.wait_until, timeout=int(args.timeout * 1000))
        await page.wait_for_timeout(int(args.duration * 1000))
        await browser.close()

    payload = {
        "status": "captured",
        "runner": "playwright-python",
        "url": args.url,
        "events": events,
        "limits": __LIMITS_JSON__,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Wrote runtime capture to {args.output}")
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Standalone Wuyun Playwright runtime hook capture.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--scope-host", action="append", default=[], help="authorized host allowlist")
    parser.add_argument("--authorize-runtime-observation", action="store_true")
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--wait-until", choices=["load", "domcontentloaded", "networkidle", "commit"], default="domcontentloaded")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if not args.authorize_runtime_observation:
        print("error: --authorize-runtime-observation is required", file=sys.stderr)
        return 2
    if not args.scope_host:
        print("error: --scope-host is required", file=sys.stderr)
        return 2
    try:
        return asyncio.run(run(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
"""
        .replace("__HOOK_JSON__", json.dumps(HOOK_JS))
        .replace("__LIMITS_JSON__", json.dumps(common_limits(), ensure_ascii=False))
    )


def standalone_puppeteer() -> str:
    return (
        """#!/usr/bin/env node
// Standalone Wuyun Puppeteer runtime hook capture.
// Generated by wuyun-js-reverse/scripts/runtime_hook_capture.py.
// Execution requires --authorize-runtime-observation and --scope-host.

const fs = require("fs");
const puppeteer = require("puppeteer");

const HOOK_JS = __HOOK_JSON__;
const LIMITS = __LIMITS_JSON__;

function parseArgs(argv) {
  const out = { scopeHost: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === "--authorize-runtime-observation") out.authorized = true;
    else if (item === "--headless") out.headless = true;
    else if (item === "--url") out.url = argv[++i];
    else if (item === "--scope-host") out.scopeHost.push(argv[++i]);
    else if (item === "--duration") out.duration = Number(argv[++i]);
    else if (item === "--timeout") out.timeout = Number(argv[++i]);
    else if (item === "--wait-until") out.waitUntil = argv[++i];
    else if (item === "--output") out.output = argv[++i];
    else throw new Error(`unknown argument: ${item}`);
  }
  out.duration = Number.isFinite(out.duration) ? out.duration : 5;
  out.timeout = Number.isFinite(out.timeout) ? out.timeout : 30;
  out.waitUntil = out.waitUntil || "domcontentloaded";
  return out;
}

function enforceScope(rawUrl, scopeHosts) {
  const host = new URL(rawUrl).hostname.toLowerCase();
  const allowed = new Set(scopeHosts.map((item) => String(item).toLowerCase()));
  if (!allowed.has(host)) throw new Error(`target host \`${host}\` is not in --scope-host allowlist`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.authorized) throw new Error("--authorize-runtime-observation is required");
  if (!args.url) throw new Error("--url is required");
  if (!args.scopeHost.length) throw new Error("--scope-host is required");
  enforceScope(args.url, args.scopeHost);

  const events = [];
  const browser = await puppeteer.launch({ headless: Boolean(args.headless) });
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(HOOK_JS);
  page.on("console", (message) => {
    const text = message.text();
    if (!text.startsWith("__WUYUN_HOOK__")) return;
    try {
      events.push(JSON.parse(text.slice("__WUYUN_HOOK__".length)));
    } catch (_) {}
  });
  await page.goto(args.url, { waitUntil: args.waitUntil, timeout: Math.trunc(args.timeout * 1000) });
  await new Promise((resolve) => setTimeout(resolve, Math.trunc(args.duration * 1000)));
  await browser.close();

  const payload = {
    status: "captured",
    runner: "puppeteer",
    url: args.url,
    events,
    limits: LIMITS,
  };
  const text = JSON.stringify(payload, null, 2);
  if (args.output) fs.writeFileSync(args.output, text + "\\n", "utf8");
  else console.log(text);
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exitCode = 2;
});
"""
        .replace("__HOOK_JSON__", json.dumps(HOOK_JS))
        .replace("__LIMITS_JSON__", json.dumps(common_limits(), ensure_ascii=False))
    )


def frida_android_webview(scope_hosts: list[str]) -> str:
    return (
        """// Wuyun Frida Android WebView runtime hook template.
// Generated by wuyun-js-reverse/scripts/runtime_hook_capture.py.
// Attach only to an authorized app/lab. Regenerate with --scope-host for each allowed host.

"use strict";

const HOOK_JS = __HOOK_JSON__;
const ALLOWED_HOSTS = new Set(__SCOPE_HOSTS_JSON__.map((item) => String(item).toLowerCase()));

function emit(event) {
  try {
    send(Object.assign({ source: "wuyun-frida-android-webview", ts: new Date().toISOString() }, event));
  } catch (_) {}
}

function hostAllowed(rawUrl) {
  if (ALLOWED_HOSTS.size === 0) return false;
  try {
    const Uri = Java.use("android.net.Uri");
    const uri = Uri.parse(String(rawUrl));
    const host = String(uri.getHost() || "").toLowerCase();
    return ALLOWED_HOSTS.has(host);
  } catch (_) {
    return false;
  }
}

Java.perform(() => {
  if (ALLOWED_HOSTS.size === 0) {
    emit({ type: "scope-empty", message: "regenerate with --scope-host before use" });
  }

  const WebView = Java.use("android.webkit.WebView");

  function install(view, reason) {
    Java.scheduleOnMainThread(() => {
      try {
        view.evaluateJavascript(HOOK_JS, null);
        emit({ type: "hook-installed", reason: String(reason) });
      } catch (error) {
        emit({ type: "hook-error", reason: String(reason), error: String(error) });
      }
    });
  }

  const loadUrlString = WebView.loadUrl.overload("java.lang.String");
  loadUrlString.implementation = function(url) {
    const result = loadUrlString.call(this, url);
    if (hostAllowed(url)) install(this, url);
    return result;
  };

  try {
    const loadUrlMap = WebView.loadUrl.overload("java.lang.String", "java.util.Map");
    loadUrlMap.implementation = function(url, headers) {
      const result = loadUrlMap.call(this, url, headers);
      if (hostAllowed(url)) install(this, url);
      return result;
    };
  } catch (_) {}

  try {
    const evaluateJavascript = WebView.evaluateJavascript.overload("java.lang.String", "android.webkit.ValueCallback");
    evaluateJavascript.implementation = function(script, callback) {
      emit({ type: "evaluateJavascript", script_length: script ? String(script).length : 0 });
      return evaluateJavascript.call(this, script, callback);
    };
  } catch (_) {}

  emit({
    type: "frida-template-installed",
    limits: __LIMITS_JSON__,
  });
});
"""
        .replace("__HOOK_JSON__", json.dumps(HOOK_JS))
        .replace("__SCOPE_HOSTS_JSON__", json.dumps(scope_hosts, ensure_ascii=False))
        .replace("__LIMITS_JSON__", json.dumps(common_limits(), ensure_ascii=False))
    )


def enforce_scope(url: str, scope_hosts: list[str]) -> None:
    host = urlparse(url).hostname or ""
    if host.lower() not in {item.lower() for item in scope_hosts}:
        raise ValueError(f"target host `{host}` is not in --scope-host allowlist")


def generate_artifact(target: str, scope_hosts: list[str]) -> str:
    if target == "browser-js":
        return HOOK_JS
    if target == "playwright-python":
        return standalone_playwright_python()
    if target == "puppeteer":
        return standalone_puppeteer()
    if target == "frida-android-webview":
        return frida_android_webview(scope_hosts)
    raise ValueError(f"unsupported target: {target}")


def write_hook(path: str | None, target: str, scope_hosts: list[str]) -> None:
    artifact = generate_artifact(target, scope_hosts)
    if path:
        Path(path).write_text(artifact, encoding="utf-8")
        print(f"Wrote {target} runtime hook artifact to {path}")
    else:
        print(artifact)


async def run_playwright(args: argparse.Namespace) -> int:
    try:
        from playwright.async_api import async_playwright
    except Exception as exc:  # noqa: BLE001
        print(f"error: playwright is not installed or unavailable: {exc}", file=sys.stderr)
        return 2

    enforce_scope(args.url, args.scope_host)
    events: list[dict] = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=args.headless)
        context = await browser.new_context(ignore_https_errors=False)
        await context.add_init_script(HOOK_JS)
        page = await context.new_page()

        def on_console(message):
            text = message.text
            if text.startswith("__WUYUN_HOOK__"):
                try:
                    events.append(json.loads(text.removeprefix("__WUYUN_HOOK__")))
                except json.JSONDecodeError:
                    pass

        page.on("console", on_console)
        await page.goto(args.url, wait_until=args.wait_until, timeout=int(args.timeout * 1000))
        await page.wait_for_timeout(int(args.duration * 1000))
        await browser.close()

    payload = {
        "status": "captured",
        "url": args.url,
        "events": events,
        "limits": [
            *common_limits(),
        ],
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Wrote runtime capture to {args.output}")
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate or run browser runtime observation hooks.")
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate", help="write or print concrete runtime hook code")
    generate.add_argument(
        "--target",
        choices=["browser-js", "playwright-python", "puppeteer", "frida-android-webview"],
        default="browser-js",
        help="artifact to generate",
    )
    generate.add_argument("--scope-host", action="append", default=[], help="embed host allowlist for Frida templates")
    generate.add_argument("--output", help="output JS file; prints to stdout if omitted")

    run = sub.add_parser("run", help="run hook with Playwright against an authorized URL")
    run.add_argument("--url", required=True)
    run.add_argument("--scope-host", action="append", default=[], help="authorized host allowlist")
    run.add_argument("--authorize-runtime-observation", action="store_true", help="confirm authorization for this runtime capture")
    run.add_argument("--duration", type=float, default=5.0, help="seconds to observe after page load")
    run.add_argument("--timeout", type=float, default=30.0)
    run.add_argument("--wait-until", choices=["load", "domcontentloaded", "networkidle", "commit"], default="domcontentloaded")
    run.add_argument("--headless", action="store_true", help="run headless browser")
    run.add_argument("--output", help="write JSON capture to file")

    args = parser.parse_args(argv)
    if args.command == "generate":
        write_hook(args.output, args.target, args.scope_host)
        return 0
    if not args.authorize_runtime_observation:
        print("error: --authorize-runtime-observation is required to run against a URL", file=sys.stderr)
        return 2
    if not args.scope_host:
        print("error: --scope-host is required with --authorize-runtime-observation", file=sys.stderr)
        return 2
    try:
        return asyncio.run(run_playwright(args))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
