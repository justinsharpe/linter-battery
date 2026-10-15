#!/usr/bin/env python3
"""linter-battery — one call, every linter, one normalized JSON schema.

The deterministic half of the AI code-review class, owned outright. Runs a
local battery of linters over a diff, a staged set, or an explicit path list
and emits normalized findings as JSON — one schema regardless of which linter
produced the finding. The corpus never leaves the machine.

Design invariants:
- PLATFORM-AGNOSTIC: stdlib-only; every tool resolved via shutil.which; a
  missing tool is recorded as a skip, never a crash; no posix-only calls.
- LOCAL-ONLY: no tool that ships code off-machine (cloud linters excluded by
  design).
- FAIL-OPEN: the battery reports; gating is the caller's decision (--gate
  turns gate-level findings into a nonzero exit).
- CONFIG-DRIVEN: the tool list, file filters, and severity mapping live in
  linter-battery.json (or --config); add/remove/reweight linters without
  touching code.

Usage:
  linter_battery.py --staged                 # staged files of the cwd repo
  linter_battery.py --diff main              # files changed vs a git ref
  linter_battery.py --paths a/ b/ file.py    # explicit surface
Options:
  --deep        add slow-pass tools (ty, bandit)
  --gate        exit 1 if any gate-level finding
  --json PATH   write the full findings report as JSON
  --config PATH override the JSON config file
  --self-test   run the built-in self-test and exit
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(HERE, "linter-battery.json")

TIMEOUT_S = 45  # per tool invocation; the battery is fast, not thorough-per-tool
_RUN_TIMEOUT = TIMEOUT_S

# tool -> discovered binary (populated on first use); recorded so reports say
# what actually ran vs what was skipped.
_BIN: dict[str, str | None] = {}


# ── default config (mirrors the shipped linter-battery.json) ────────────────

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "timeout_s": 45,
    "file_limit": 400,
    "gate_on": ["error"],
    "tools": [
        {"name": "ruff", "binary": "ruff", "parser": "ruff",
         "files": {"extensions": [".py"]}, "severity": "error"},
        {"name": "ty", "binary": "ty", "parser": "ty",
         "files": {"extensions": [".py"]}, "deep": True, "severity": "error"},
        {"name": "bandit", "binary": "bandit", "parser": "bandit",
         "files": {"extensions": [".py"]}, "deep": True, "severity": "warning"},
        {"name": "oxlint", "binary": "oxlint", "parser": "oxlint",
         "files": {"extensions": [".ts", ".tsx", ".js", ".jsx"]},
         "severity": "warning", "severity_map": {"error": "error", "warning": "warning"}},
        {"name": "swiftlint", "binary": "swiftlint", "parser": "swiftlint",
         "files": {"extensions": [".swift"]},
         "severity": "warning", "severity_map": {"error": "error", "warning": "warning"}},
        {"name": "shellcheck", "binary": "shellcheck", "parser": "shellcheck",
         "files": {"extensions": [".sh", ".bash"]}, "severity": "warning"},
        {"name": "shfmt", "binary": "shfmt", "parser": "shfmt",
         "files": {"extensions": [".sh", ".bash"]}, "severity": "info"},
        {"name": "hadolint", "binary": "hadolint", "parser": "hadolint",
         "files": {"dockerfile": True}, "severity": "warning"},
        {"name": "actionlint", "binary": "actionlint", "parser": "actionlint",
         "files": {"workflow": True}, "severity": "error"},
        {"name": "typos", "binary": "typos", "parser": "typos",
         "files": {"docs": True}, "severity": "warning"},
        {"name": "vale", "binary": "vale", "parser": "vale",
         "files": {"docs": True}, "severity": "warning"},
        {"name": "gitleaks", "binary": "gitleaks", "parser": "gitleaks",
         "files": {"staged": True}, "severity": "error"},
    ],
}


# ── config loading ──────────────────────────────────────────────────────────

def load_config(path: str | None = None) -> dict[str, Any]:
    """Load the JSON config from `path`, the shipped default, or the embedded
    fallback — in that order. Always returns a dict; never raises for a
    missing file."""
    if path:
        with open(path) as fh:
            return json.load(fh)
    if os.path.isfile(DEFAULT_CONFIG_PATH):
        with open(DEFAULT_CONFIG_PATH) as fh:
            return json.load(fh)
    return DEFAULT_CONFIG


# ── low-level helpers ───────────────────────────────────────────────────────

def _which(name: str) -> str | None:
    if name not in _BIN:
        _BIN[name] = shutil.which(name)
    return _BIN[name]


def _run(cmd: list[str], cwd: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=_RUN_TIMEOUT, cwd=cwd, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


_ANSI_RE = None


def _strip_ansi(text: str) -> str:
    """Tools colorize even non-TTY on some hosts; findings must be parsed clean."""
    global _ANSI_RE
    if _ANSI_RE is None:
        import re as _re
        _ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")
    return _ANSI_RE.sub("", text)


def _path_matches(printed_path: str, queried_path: str) -> bool:
    """Tools print paths relative to their CWD (actionlint: '../../..'). Match by suffix."""
    if not printed_path:
        return False
    printed_norm = printed_path.replace("\\", "/")
    queried_norm = queried_path.replace("\\", "/")
    if printed_norm == queried_norm or printed_norm.endswith(queried_norm):
        return True
    # basename fallback for shortened forms
    return os.path.basename(printed_norm) == os.path.basename(queried_norm) and (
        os.path.dirname(queried_norm) in printed_norm or printed_norm.endswith(os.path.basename(queried_norm)))


def _finding(tool: str, file: str, line: Any, sev: str, msg: str) -> dict[str, Any]:
    try:
        line_i = max(1, int(line))
    except (TypeError, ValueError):
        line_i = 1
    return {"tool": tool, "file": file, "line": line_i,
            "severity": sev, "message": str(msg).strip()[:300]}


def _nearest_config(start: str, name: str) -> str | None:
    """Walk UP from a file to find the nearest config — CWD-independent
    (nondeterministic CWD resolution produces false-alarm storms; scanners
    must be deterministic across caller contexts)."""
    d = os.path.dirname(os.path.abspath(start))
    while True:
        cand = os.path.join(d, name)
        if os.path.isfile(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


# frozen historical records — typo-fixing a transcript/export falsifies the
# record. Substring match (not prefix): "…-export.md" counts.
_FROZEN_DOC_MARKERS = ("session-", "chat-", "handoff-", "loom-", "transcript", "export")


# ── git surface ─────────────────────────────────────────────────────────────

def _staged_files() -> list[str]:
    r = _run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"])
    return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]


def _diff_files(ref: str) -> list[str]:
    r = _run(["git", "diff", "--name-only", "--diff-filter=ACM", ref])
    return [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]


# ── file selection (config-driven) ──────────────────────────────────────────

def _select_files(files: list[str], fspec: dict[str, Any]) -> list[str]:
    if fspec.get("staged"):
        return []  # staged tools operate on the git staged set, not `files`
    if fspec.get("dockerfile"):
        return [f for f in files if os.path.basename(f).startswith("Dockerfile")]
    if fspec.get("workflow"):
        return [f for f in files if ".github" in f and f.endswith((".yml", ".yaml"))]
    if fspec.get("docs"):
        md = [f for f in files if f.endswith((".md", ".mdx"))]
        return [f for f in md if not any(m in os.path.basename(f).lower()
                                         for m in _FROZEN_DOC_MARKERS)]
    exts = tuple(fspec.get("extensions", []))
    return [f for f in files if f.endswith(exts)]


# ── per-tool parsers ────────────────────────────────────────────────────────
# Each parser returns raw findings: {"file", "line", "token", "message"}.
# `token` is an optional tool-level severity; the runner maps it through the
# tool's severity_map (falling back to the tool's default severity).

def _parse_ruff(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], "check", "--no-cache", "--output-format=concise", *files])
    out = []
    for line in (r.stdout or "").splitlines():
        # path:row:col: CODE msg
        parts = line.split(":", 3)
        if len(parts) >= 4 and parts[1].strip().isdigit():
            out.append({"file": parts[0], "line": int(parts[1]), "token": None, "message": parts[3]})
    return out


def _parse_ty(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], "check", *files])
    out = []
    for line in (r.stdout or "").splitlines():
        if line.startswith("error["):
            out.append({"file": "", "line": 0, "token": None, "message": line})
    return out


def _parse_bandit(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], "-q", "-f", "json", *files])
    out = []
    try:
        for res in json.loads(r.stdout or "{}").get("results", []):
            out.append({"file": res.get("filename", ""), "line": res.get("line_number", 0),
                        "token": None,
                        "message": f"[{res.get('issue_severity','')}] {res.get('issue_text','')}"})
    except json.JSONDecodeError:
        pass
    return out


def _parse_oxlint(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], *files])
    out = []
    for line in (r.stdout or "").splitlines():
        # path:row:col: severity eslint(rule): msg
        if ":" not in line:
            continue
        head, _, msg = line.partition(": ")
        parts = head.split(":")
        if len(parts) >= 2 and parts[0].endswith((".ts", ".tsx", ".js", ".jsx")):
            token = "error" if " error " in f" {msg[:30]} " else "warning"
            out.append({"file": parts[0], "line": int(parts[1]) if parts[1].isdigit() else 1,
                        "token": token, "message": msg})
    return out


def _parse_swiftlint(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], "lint", "--quiet", *files])
    out = []
    for line in (r.stdout or "").splitlines():
        # file:row:col: severity: Rule Violation: msg (rule)
        parts = line.split(":", 4)
        if len(parts) >= 5 and parts[1].strip().isdigit():
            token = "error" if "error" in parts[3] else "warning"
            out.append({"file": parts[0], "line": int(parts[1]), "token": token, "message": parts[4]})
    return out


def _parse_shellcheck(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        r = _run([spec["binary"], "-f", "gcc", f])
        for line in (r.stdout or "").splitlines():
            # gcc format: file:row:col: severity: msg [CODE]
            parts = line.split(":", 4)
            if len(parts) >= 4 and parts[1].strip().isdigit():
                # notes are real too here (SC2086 word-splitting ships as note)
                out.append({"file": parts[0], "line": int(parts[1]), "token": None, "message": parts[-1]})
    return out


def _parse_shfmt(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        r = _run([spec["binary"], "-d", f])
        if r.stdout and r.stdout.strip():
            out.append({"file": f, "line": 0, "token": None, "message": "formatting delta (shfmt -d)"})
    return out


def _parse_hadolint(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        r = _run([spec["binary"], "--no-fail", f], cwd=os.path.dirname(f) or ".")
        # hadolint format: file:LINE CODE message (paths relative to its CWD)
        text = r.stdout or r.stderr or ""
        for raw_line in text.splitlines():
            line = _strip_ansi(raw_line)
            parts = line.split(":", 2)
            if len(parts) == 3:
                head = parts[1].split()
                if head and head[0].isdigit() and _path_matches(parts[0], f):
                    out.append({"file": parts[0], "line": int(head[0]), "token": None, "message": parts[2]})
    return out


def _parse_actionlint(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        r = _run([spec["binary"], "-no-color", f], cwd=os.path.dirname(f) or ".")
        text = r.stdout or r.stderr or ""
        for line in text.splitlines():
            # format: path:line:col: message (path may be CWD-relative)
            if ":" not in line:
                continue
            parts = line.split(":", 3)
            if len(parts) >= 3 and parts[1].strip().isdigit() and _path_matches(parts[0], f):
                out.append({"file": parts[0], "line": int(parts[1]), "token": None,
                            "message": parts[3] if len(parts) > 3 else line})
    return out


def _parse_typos(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        cfg_path = _nearest_config(f, "_typos.toml")
        cfg = ["--config", cfg_path] if cfg_path else []
        r = _run([spec["binary"], *cfg, f])
        for line in (r.stdout or "").splitlines():
            if "should be" in line:
                out.append({"file": f, "line": 0, "token": None, "message": line.strip()})
    return out


def _parse_vale(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for f in files:
        # config resolved from the TARGET file's tree (CWD-independence);
        # vale's default format is FILE:LINE:COL: severity: message — split on
        # ':' and take the numeric second field.
        vcfg = _nearest_config(f, ".vale.ini")
        if not vcfg:
            continue
        r = _run([spec["binary"], "--config", vcfg, f])
        for line in (r.stdout or "").splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[1].strip().isdigit():
                out.append({"file": parts[0], "line": int(parts[1]), "token": None,
                            "message": ":".join(parts[3:]).strip()})
    return out


def _parse_gitleaks(files: list[str], spec: dict[str, Any]) -> list[dict[str, Any]]:
    r = _run([spec["binary"], "protect", "--staged", "--no-banner", "-v"])
    out = []
    for line in (r.stdout or "").splitlines():
        if line.strip().startswith("Finding:"):
            out.append({"file": "", "line": 0, "token": None, "message": line.strip()})
    return out


PARSERS: dict[str, Any] = {
    "ruff": _parse_ruff,
    "ty": _parse_ty,
    "bandit": _parse_bandit,
    "oxlint": _parse_oxlint,
    "swiftlint": _parse_swiftlint,
    "shellcheck": _parse_shellcheck,
    "shfmt": _parse_shfmt,
    "hadolint": _parse_hadolint,
    "actionlint": _parse_actionlint,
    "typos": _parse_typos,
    "vale": _parse_vale,
    "gitleaks": _parse_gitleaks,
}


# ── battery runner ──────────────────────────────────────────────────────────

def _run_tool(spec: dict[str, Any], files: list[str], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    name = spec["name"]
    fspec = spec.get("files", {})
    is_staged = bool(fspec.get("staged"))
    selected = _select_files(files, fspec)
    if not is_staged and not selected:
        return []
    binary = spec.get("binary", name)
    if not _which(binary):
        return [{"tool": name, "file": selected[0] if selected else "",
                 "line": 0, "severity": "skip", "message": f"{binary} not found"}]
    try:
        raw = PARSERS[spec["parser"]](selected, spec)
    except Exception as exc:  # noqa: BLE001 — fail-open: report, never crash
        return [{"tool": name, "file": "", "line": 0, "severity": "skip",
                 "message": f"scanner error: {exc}"}]
    out = []
    smap = spec.get("severity_map", {})
    default = spec.get("severity", "warning")
    for r in raw:
        out.append(_finding(name, r.get("file", ""), r.get("line", 0),
                            smap.get(r.get("token"), default), r.get("message", "")))
    return out


def run_battery(files: list[str], deep: bool = False, staged_secrets: bool = False,
                config: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = config or load_config()
    global _RUN_TIMEOUT
    _RUN_TIMEOUT = cfg.get("timeout_s", TIMEOUT_S)
    t0 = time.time()
    findings: list[dict[str, Any]] = []
    for spec in cfg.get("tools", []):
        if spec.get("deep") and not deep:
            continue
        if spec.get("files", {}).get("staged") and not staged_secrets:
            continue
        findings.extend(_run_tool(spec, files, cfg))
    errors = sum(1 for f in findings if f["severity"] == "error")
    return {"files": len(files), "findings": findings,
            "counts": {"total": len(findings), "errors": errors,
                       "warnings": sum(1 for f in findings if f["severity"] == "warning"),
                       "info": sum(1 for f in findings if f["severity"] == "info"),
                       "skipped": sum(1 for f in findings if f["severity"] == "skip")},
            "elapsed_s": round(time.time() - t0, 2)}


# ── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="linter-battery",
        description="One call, every linter, one normalized JSON schema.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--staged", action="store_true",
                   help="lint files staged in the current git repo")
    g.add_argument("--diff", metavar="REF", help="lint files changed vs a git ref")
    g.add_argument("--paths", nargs="+", metavar="PATH",
                   help="explicit files or directories to lint")
    ap.add_argument("--deep", action="store_true", help="add slow-pass tools (ty, bandit)")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 if any gate-level finding")
    ap.add_argument("--json", metavar="PATH", help="write the full findings report as JSON")
    ap.add_argument("--config", metavar="PATH",
                    help="JSON config file (default: linter-battery.json next to this script)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in self-test and exit")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.self_test:
        return _run_self_test()
    if not (args.staged or args.diff or args.paths):
        ap.error("one of --staged, --diff, or --paths is required")
    cfg = load_config(args.config)
    file_limit = cfg.get("file_limit", 400)

    if args.staged:
        files = _staged_files()
    elif args.diff:
        files = _diff_files(args.diff)
    else:
        files = []
        for p in args.paths or []:
            if os.path.isdir(p):
                for root, dirs, names in os.walk(p):
                    dirs[:] = [d for d in dirs if d not in
                               {".git", "node_modules", ".build", "venv", ".venv",
                                "DerivedData", ".worktrees", "checkouts"}]
                    files.extend(os.path.join(root, n) for n in names)
            elif os.path.isfile(p):
                files.append(p)
        files = files[:file_limit]  # battery bound: fast pass, not the full corpus

    report = run_battery(files, deep=args.deep, staged_secrets=bool(args.staged))

    print(f"linter-battery: {report['files']} files, {report['counts']['total']} findings "
          f"({report['counts']['errors']} errors / {report['counts']['warnings']} warnings / "
          f"{report['counts']['info']} info / {report['counts']['skipped']} skipped) "
          f"in {report['elapsed_s']}s")
    for f in report["findings"]:
        loc = f"{f['file']}:{f['line']}" if f["file"] else "(repo)"
        print(f"  [{f['severity']}] {f['tool']} {loc} — {f['message']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=1)
    gate_on = cfg.get("gate_on", ["error"])
    return 1 if (args.gate and any(f["severity"] in gate_on for f in report["findings"])) else 0


# ── self-test (runs with NO linters installed) ──────────────────────────────

def _run_self_test() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


class SelfTest(unittest.TestCase):
    """Exercises the skip path, the normalized JSON schema, and argument
    parsing — none of which require any linter to be installed."""

    def test_arg_parsing(self):
        ap = build_parser()
        ns = ap.parse_args(["--paths", "a.py", "b.py", "--deep", "--gate", "--json", "r.json"])
        self.assertEqual(ns.paths, ["a.py", "b.py"])
        self.assertTrue(ns.deep and ns.gate)
        self.assertEqual(ns.json, "r.json")
        self.assertEqual(ap.parse_args(["--diff", "main"]).diff, "main")
        self.assertTrue(ap.parse_args(["--staged"]).staged)
        self.assertTrue(ap.parse_args(["--self-test"]).self_test)
        # a mode is required unless --self-test
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                main(["--deep"])

    def test_json_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "clean.py")
            with open(f, "w") as fh:
                fh.write("print('hi')\n")
            report = run_battery([f], config=DEFAULT_CONFIG)
            for key in ("files", "findings", "counts", "elapsed_s"):
                self.assertIn(key, report)
            self.assertEqual(report["files"], 1)
            for k in ("total", "errors", "warnings", "skipped"):
                self.assertIsInstance(report["counts"][k], int)
            self.assertEqual(report["counts"]["total"], len(report["findings"]))
            for fd in report["findings"]:
                for key in ("tool", "file", "line", "severity", "message"):
                    self.assertIn(key, fd)
                self.assertIn(fd["severity"], ("skip", "info", "warning", "error"))

    def test_missing_tool_is_skip_not_crash(self):
        spec = {"name": "nope", "binary": "__linter_battery_missing__", "parser": "ruff",
                "files": {"extensions": [".py"]}, "severity": "error"}
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "a.py")
            with open(f, "w") as fh:
                fh.write("x = 1\n")
            findings = _run_tool(spec, [f], DEFAULT_CONFIG)
        self.assertTrue(any(x["severity"] == "skip" and x["tool"] == "nope" for x in findings),
                        f"missing binary must be a recorded skip, got {findings}")

    def test_skip_path_via_impossible_binary(self):
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
        for t in cfg["tools"]:
            t["binary"] = "__linter_battery_missing__"
        with tempfile.TemporaryDirectory() as tmp:
            f = os.path.join(tmp, "clean.py")
            with open(f, "w") as fh:
                fh.write("print('hi')\n")
            report = run_battery([f], config=cfg)
        skips = [x for x in report["findings"] if x["severity"] == "skip"]
        self.assertTrue(skips, "every tool should be recorded as a skip, none crash")
        self.assertTrue(all("not found" in x["message"] for x in skips))

    @unittest.skipUnless(os.path.exists(DEFAULT_CONFIG_PATH), "shipped config file not present")
    def test_shipped_config_matches_embedded(self):
        with open(DEFAULT_CONFIG_PATH) as fh:
            shipped = json.load(fh)
        self.assertEqual([t["name"] for t in shipped["tools"]],
                         [t["name"] for t in DEFAULT_CONFIG["tools"]])
        self.assertEqual(shipped.get("gate_on"), DEFAULT_CONFIG.get("gate_on"))
        for t in shipped["tools"]:
            e = next(x for x in DEFAULT_CONFIG["tools"] if x["name"] == t["name"])
            self.assertEqual(t.get("severity"), e.get("severity"))


if __name__ == "__main__":
    sys.exit(main())
