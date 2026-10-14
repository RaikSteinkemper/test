#!/usr/bin/env python3
"""Scannt heruntergeladene Modelle mit modelscan (Protect AI), picklescan und ClamAV.

Aufruf:  python scan_models.py /pfad/zum/modell [--report report.json]
Exit:    0 = sauber, 1 = Befund, 2 = Scanfehler
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run_modelscan(path: Path) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "modelscan.json"
        proc = subprocess.run(
            ["modelscan", "scan", "-p", str(path), "-r", "json", "-o", str(out), "-l", "ERROR"],
            capture_output=True, text=True,
        )
        report = json.loads(out.read_text()) if out.exists() else None
    # Exit-Codes: 0 sauber, 1 Befund, 2 Fehler, 3 keine unterstützten Dateien (z. B. nur .safetensors).
    # Der Report ist genauer als der Exit-Code (Befunde UND Fehler können gleichzeitig auftreten).
    if report and report["summary"]["total_issues"] > 0:
        status = "issues"
    elif proc.returncode == 2 or (report and report.get("errors")):
        status = "error"
    elif proc.returncode in (0, 3):
        status = "clean"
    else:
        status = "error"
    return {"exit_code": proc.returncode, "status": status, "report": report, "stderr": proc.stderr[-2000:]}


def run_picklescan(path: Path) -> dict:
    # picklescan überspringt .npy im Ordner-Modus, deshalb werden sie einzeln übergeben.
    targets = [path] + (sorted(path.rglob("*.npy")) if path.is_dir() else [])
    runs = []
    for target in targets:
        proc = subprocess.run(["picklescan", "-p", str(target)], capture_output=True, text=True)
        runs.append({"target": str(target), "exit_code": proc.returncode, "output": (proc.stdout + proc.stderr)[-5000:]})
    # Exit-Codes: 0 sauber, 1 gefährlicher Import gefunden, 2 Fehler
    codes = {r["exit_code"] for r in runs}
    status = "issues" if 1 in codes else "clean" if codes == {0} else "error"
    return {"status": status, "runs": runs}


def run_clamav(path: Path) -> dict:
    # Standardlimit ist 100 MB pro Datei; ClamAV kann höchstens knapp 2 GiB pro Datei, größere werden übersprungen.
    proc = subprocess.run(
        ["clamscan", "--recursive", "--infected", "--max-filesize=2047M", "--max-scansize=2047M", str(path)],
        capture_output=True, text=True,
    )
    # Exit-Codes: 0 sauber, 1 Malware gefunden, 2 Fehler
    status = {0: "clean", 1: "issues"}.get(proc.returncode, "error")
    return {"exit_code": proc.returncode, "status": status, "output": (proc.stdout + proc.stderr)[-5000:]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path, help="Modellordner oder einzelne Datei")
    parser.add_argument("--report", type=Path, help="Gesamtreport zusätzlich als JSON-Datei speichern")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"Pfad nicht gefunden: {args.path}", file=sys.stderr)
        return 2

    results = {
        "modelscan": run_modelscan(args.path),
        "picklescan": run_picklescan(args.path),
        "clamav": run_clamav(args.path),
    }
    statuses = {r["status"] for r in results.values()}
    verdict = "BLOCK" if "issues" in statuses else "ERROR" if "error" in statuses else "PASS"

    report = {"path": str(args.path.resolve()), "verdict": verdict, "scanners": results}
    text = json.dumps(report, indent=2, ensure_ascii=False)
    print(text)
    if args.report:
        args.report.write_text(text)

    for name, r in results.items():
        print(f"{name:<11} {r['status']}", file=sys.stderr)
    print(f"Ergebnis:   {verdict}", file=sys.stderr)
    return {"PASS": 0, "BLOCK": 1, "ERROR": 2}[verdict]


if __name__ == "__main__":
    sys.exit(main())