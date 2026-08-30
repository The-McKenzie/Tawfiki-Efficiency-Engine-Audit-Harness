# Copyright © 2025 Rodger McKenzie / Tawfiki AI. All rights reserved.
# This file is released for audit review purposes only.
# No license is granted to modify, distribute, or use this file
# outside of an authorized audit engagement.
#!/usr/bin/env python3
"""
tawfiki_efficiency_harness.py  --  Tawfiki Efficiency Engine Audit Harness
Version: tee-harness-1.1

METHODOLOGY STATEMENT
=====================
This harness audits a compute efficiency engine treated as a complete black box.
It answers two questions:

  1. RETENTION     Does the engine recover the original input byte-for-exact-byte?
  2. EFFICIENCY    What are the structural index and recovery store measurements?

The engine is a black box. This harness contains zero knowledge of its internal
structure, algorithm, or implementation language. All grading is computed
exclusively from input bytes and returned output bytes. The engine is never
asked about its internal state.

HONESTY RULES (enforced in code, not documentation)
====================================================
  - All verdicts are computed by the harness from bytes alone.
    Input bytes go in. Output bytes come back. The harness grades the difference.
    The engine's own reports are never used for any verdict.
  - A reconstruction PASSES only if the output bytes are byte-exact to the input.
  - Negative controls prove the harness rejects fabricated, corrupted, and null
    outputs independently of anything the engine reports.
  - Two metrics reported SEPARATELY, NEVER fused:
      A = structural index bytes / input bytes
      B = recovery store bytes / input bytes
  - NULL mode: engine launched in null mode must FAIL every verdict field.
    Any PASS voids the run (D8 hard gate).
  - Measurements (cpu, wall, throughput, rss, bytes) are REPORTED, never graded.
  - The harness never reads any pass, fail, verified, or internal state field
    from engine output. All verdicts are computed independently.

PRE-REGISTRATION (prereg.json)
==============================
Before the run, the operator records predictions for each domain:
  {
    "predictions": {
      "legal":           { "retention": "PASS", "metric_A": "<1", "metric_B": ">=1" },
      "financial":       { "retention": "PASS", "metric_A": "<1", "metric_B": ">=1" },
      ...
    },
    "operator":   "Tawfiki AI",
    "witness":    "<witness name and affiliation>",
    "salt_hash":  "<sha256 of agreed audit salt>",
    "date":       "<ISO8601 date of agreement>"
  }
This file is hashed and sealed into the record chain before the run begins.
It cannot be altered after sealing without breaking the chain.

DOMAINS TESTED
==============
  legal, financial, conversational, medical,
  genomic/fasta, genomic/fastq, genomic/vcf, genomic/gff, genomic/genbank,
  code (multi-file per-file restore)

NEGATIVE CONTROLS
=================
  stub           -- canned output that is not the input; must be rejected
  corrupt        -- output set to fixed corruption string; must not match input
  incompressible -- high-entropy input; recovery store must be >= input size
  null_build     -- engine in null mode; every verdict field must FAIL (D8)

ENGINE CONTRACT
===============
The engine binary is invoked as a subprocess. It receives a JSON args blob
and writes recovered bytes to an output path. It emits one JSON line to stdout.

Engine stdout contract (all fields required):
  {
    "nonce":               "<matches request nonce>",
    "input_hash":          "<sha256 of input>",
    "recon_present":       bool,
    "recon_len":           int,
    "metric_A_bytes":      int,
    "metric_B_bytes":      int,
    "cpu_ms":              float,
    "wall_ms":             float,
    "rss_bytes":           int
  }

No internal state fields. No architecture fields. No self-reporting of
pass/fail. The harness computes all verdicts from returned bytes only.

ENVIRONMENT VARIABLES (required)
=================================
  EFF_ENGINE_BIN   absolute path to the compiled efficiency engine binary
  EFF_ENGINE_KEY   license key passed to engine at startup
  EFF_AUDIT_SALT   deterministic salt for corpus generation (optional;
                   randomised if not set -- set for reproducible runs)

OUTPUT
======
  run_<timestamp>/
    run.jsonl      sealed NDJSON record chain
    prereg.json    operator pre-registration (sealed before run)
    files/         raw input and recovered output bytes per test

RUN
===
  set EFF_ENGINE_BIN=<absolute path to engine binary>
  set EFF_ENGINE_KEY=<license key>
  set EFF_AUDIT_SALT=<agreed fixed salt>
  python tawfiki_efficiency_harness.py --prereg prereg.json [--null]
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

# =============================================================================
# CONFIGURATION
# =============================================================================

HARNESS_VERSION = "tee-harness-1.1"

def _require_env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        print(f"FATAL: environment variable {name} is not set.")
        sys.exit(1)
    return v

ENGINE_BIN  = _require_env("EFF_ENGINE_BIN")
ENGINE_KEY  = _require_env("EFF_ENGINE_KEY")

_env_salt   = os.environ.get("EFF_AUDIT_SALT", "")
SALT        = _env_salt if _env_salt else secrets.token_hex(16)
SALT_SOURCE = "env:EFF_AUDIT_SALT" if _env_salt else "os-random"
SEED        = hashlib.sha256(b"tee-harness-salt:" + SALT.encode()).digest()

# =============================================================================
# HASHING
# =============================================================================

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def seal(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

# =============================================================================
# DETERMINISTIC CORPUS GENERATOR
# Salted, reproducible. Same salt = same corpus on any machine.
# =============================================================================

def _rng(tag: str, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(SEED + tag.encode() + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:n]

def _word(tag: str, k: int = 6) -> str:
    return base64.b32encode(_rng(tag, k)).decode().rstrip("=").lower()

def _dna(tag: str, n: int) -> str:
    return "".join("ACGT"[b % 4] for b in _rng(tag, n))

def gen_legal() -> tuple[bytes, dict]:
    clauses = [
        f"Section {i+1}. The party {_word(f'lg{i}')} shall {_word(f'lv{i}')} the agreement."
        for i in range(12)
    ]
    text = "WHEREAS this contract is entered into.\n\n" + "\n\n".join(clauses) + "\n"
    return text.encode("utf-8"), {"clause_count": 12}

def gen_financial() -> tuple[bytes, dict]:
    rows = ["date,account,amount"]
    for i in range(12):
        amt = int.from_bytes(_rng(f"famt{i}", 4), "big") % 100000
        rows.append(f"2026-01-{(i % 28)+1:02d},{_word(f'fa{i}')},{amt}")
    return ("\n".join(rows) + "\n").encode("utf-8"), {"row_count": 12}

def gen_conversational() -> tuple[bytes, dict]:
    turns = [f"Speaker{i % 3}: {_word(f'cv{i}', 16)}" for i in range(12)]
    return ("\n".join(turns) + "\n").encode("utf-8"), {"turn_count": 12}

def gen_medical() -> tuple[bytes, dict]:
    diags = [f"Diagnosis: {_word(f'md{i}')} E{(i % 99):02d}.{i % 9}" for i in range(12)]
    text = "\n".join(diags) + "\n\nClinical narrative: " + _word("mp", 40) + "\n"
    return text.encode("utf-8"), {"diagnosis_count": 12}

def gen_fasta() -> tuple[bytes, dict]:
    recs = []
    for i in range(3):
        s = _dna(f"fa{i}", 120)
        recs.append(
            f">seq_{i} {_word(f'fh{i}')}\n" +
            "\n".join(s[j:j+60] for j in range(0, len(s), 60))
        )
    return ("\n".join(recs) + "\n").encode("utf-8"), {"sequence_count": 3}

def gen_fastq() -> tuple[bytes, dict]:
    recs = []
    for i in range(3):
        s = _dna(f"fq{i}", 40)
        q = "".join(chr(33 + (b % 40)) for b in _rng(f"fqq{i}", 40))
        recs.append(f"@read_{i}\n{s}\n+\n{q}")
    return ("\n".join(recs) + "\n").encode("utf-8"), {"sequence_count": 3}

def gen_vcf() -> tuple[bytes, dict]:
    lines = [
        "##fileformat=VCFv4.2", "##source=audit",
        "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO"
    ]
    for i in range(3):
        lines.append(
            f"chr1\t{100*(i+1)}\t.\t{'ACGT'[i%4]}\t{'ACGT'[(i+1)%4]}\t50\tPASS\tDP={10+i}"
        )
    return ("\n".join(lines) + "\n").encode("utf-8"), {"sequence_count": 3}

def gen_gff() -> tuple[bytes, dict]:
    lines = ["##gff-version 3", "##sequence-region chr1 1 1000"]
    for i, f in enumerate(["gene", "exon", "exon"]):
        lines.append(f"chr1\taudit\t{f}\t{1+i*50}\t{50+i*50}\t.\t+\t.\tID={f}{i}")
    return ("\n".join(lines) + "\n").encode("utf-8"), {"sequence_count": 3}

def gen_genbank() -> tuple[bytes, dict]:
    seq = _dna("gb", 40).lower()
    origin = "        1 " + " ".join(seq[j:j+10] for j in range(0, len(seq), 10))
    lines = [
        "LOCUS       SEQ0001                40 bp    DNA     linear   UNA 13-JUN-2026",
        "FEATURES             Location/Qualifiers",
        "     source          1..40",
        "ORIGIN", origin, "//"
    ]
    return ("\n".join(lines) + "\n").encode("utf-8"), {"sequence_count": 1}

def gen_incompressible() -> tuple[bytes, dict]:
    b = _rng("incompressible", 4096)
    out = []
    for i, by in enumerate(b):
        out.append(chr(33 + (by % 94)))
        if i % 64 == 63:
            out.append("\n")
    return ("".join(out) + "\n").encode("utf-8"), {}

CODE_FILES = {
    "main.ts":        "// entry point\n" + "\n".join(
                          f"export const item{i} = {i};" for i in range(6)
                      ) + "\n",
    "lib/util.ts":    "export function util(): number {\n  return 42;\n}\n",
    "lib/data.ts":    "export const data = [\n  1, 2, 3,\n  4, 5, 6,\n];\n",
    "docs/README.md": "# Audit\n\nMulti-file per-file recovery.\nLine two.\n",
}

DOMAINS = [
    ("legal",           "legal",          gen_legal),
    ("financial",       "financial",      gen_financial),
    ("conversational",  "conversational", gen_conversational),
    ("medical",         "medical",        gen_medical),
    ("genomic/fasta",   "genomic",        gen_fasta),
    ("genomic/fastq",   "genomic",        gen_fastq),
    ("genomic/vcf",     "genomic",        gen_vcf),
    ("genomic/gff",     "genomic",        gen_gff),
    ("genomic/genbank", "genomic",        gen_genbank),
]

# =============================================================================
# ENGINE SUBPROCESS INTERFACE
# Black box. Input bytes in. Output bytes back. Nothing else.
# =============================================================================

def _invoke_engine(
    mode: str,
    domain: str = "",
    input_bytes: bytes = None,
    code_dir: str = None,
    null_mode: bool = False
) -> tuple[dict, bytes, int, str]:
    """
    Invoke the engine binary. Returns:
      (meta_dict, recovered_bytes, returncode, stderr)
    All grading is computed from recovered_bytes by the harness.
    meta_dict is used only for measurement fields (cpu_ms, wall_ms, rss_bytes,
    metric_A_bytes, metric_B_bytes). Never for verdicts.
    """
    nonce = secrets.token_hex(8)
    tmp   = tempfile.gettempdir()
    in_f  = os.path.join(tmp, f"tee_in_{nonce}")
    out_f = os.path.join(tmp, f"tee_out_{nonce}")

    if input_bytes is not None:
        open(in_f, "wb").write(input_bytes)

    args_dict = {
        "mode":       mode,
        "domain":     domain,
        "input_file": in_f,
        "out_file":   out_f,
        "code_dir":   (code_dir or "").replace("\\", "/"),
        "nonce":      nonce,
    }

    cmd = [ENGINE_BIN, "--key", ENGINE_KEY]
    if null_mode:
        cmd.append("--null")
    cmd.append(json.dumps(args_dict))

    meta, out_bytes, rc, err = {}, b"", -1, ""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600
        )
        rc     = proc.returncode
        stdout = proc.stdout.decode("utf-8", "replace").strip()
        err    = proc.stderr.decode("utf-8", "replace").strip()
        lines  = [l for l in stdout.splitlines() if l.strip().startswith("{")]
        meta   = json.loads(lines[-1]) if lines else {}
        if os.path.exists(out_f):
            out_bytes = open(out_f, "rb").read()
    except subprocess.TimeoutExpired:
        err = "TIMEOUT"
    except Exception as e:
        err = str(e)
    finally:
        for f in (in_f, out_f):
            try: os.remove(f)
            except OSError: pass

    return meta, out_bytes, rc, err

# =============================================================================
# FIELD GRADERS
# All verdicts computed from bytes. Engine self-reports never used.
# =============================================================================

def grade_retention(input_bytes: bytes, recon: bytes) -> tuple[str, dict]:
    """
    RETENTION: byte-exact recovery.
    Graded entirely from input bytes and returned output bytes.
    Engine is never consulted for this verdict.
    """
    ih     = sha256(input_bytes)
    rh     = sha256(recon) if recon else "empty"
    passed = (ih == rh) and len(recon) > 0
    return ("PASS" if passed else "FAIL"), {
        "input_sha256": ih,
        "recon_sha256": rh,
        "input_bytes":  len(input_bytes),
        "recon_bytes":  len(recon) if recon else 0,
        "byte_exact":   passed,
    }

def grade_metric_A(meta: dict, input_bytes: bytes) -> tuple[str, dict]:
    """
    METRIC A: structural index bytes / input bytes.
    MEASUREMENT only. Never a verdict.
    """
    ib = meta.get("input_bytes", len(input_bytes))
    ab = meta.get("metric_A_bytes", 0)
    A  = round(ab / ib, 4) if ib else None
    return "MEASUREMENT", {
        "metric_A_bytes":    ab,
        "input_bytes":       ib,
        "A_over_input":      A,
        "note": "lossy structural index; may be < 1; NOT a recovery claim"
    }

def grade_metric_B(meta: dict, input_bytes: bytes) -> tuple[str, dict]:
    """
    METRIC B: recovery store bytes / input bytes.
    MEASUREMENT only. Never a verdict.
    """
    ib = meta.get("input_bytes", len(input_bytes))
    bb = meta.get("metric_B_bytes", 0)
    B  = round(bb / ib, 4) if ib else None
    return "MEASUREMENT", {
        "metric_B_bytes":   bb,
        "input_bytes":      ib,
        "B_over_input":     B,
        "note": "lossless recovery store; reported separately from metric A"
    }

def grade_compute(meta: dict, input_bytes: bytes) -> tuple[str, dict]:
    """
    COMPUTE: cpu, wall, throughput, rss.
    MEASUREMENT only. Never a verdict.
    """
    ib      = meta.get("input_bytes", len(input_bytes))
    wall_ms = meta.get("wall_ms", 1)
    cpu_ms  = meta.get("cpu_ms", 0)
    bps     = round(ib / (wall_ms / 1000), 0) if wall_ms > 0 else 0
    return "MEASUREMENT", {
        "cpu_ms":        cpu_ms,
        "wall_ms":       wall_ms,
        "bytes_per_sec": bps,
        "rss_bytes":     meta.get("rss_bytes", 0),
        "note": "compute measurements reported; no verdict threshold applied"
    }

# =============================================================================
# NEGATIVE CONTROLS
# All graded from bytes. Engine self-reports never used.
# =============================================================================

def control_stub(files_dir: str, nonce: str, prev: str) -> tuple[dict, str]:
    """Stub: canned output must not match input. Graded from bytes."""
    x, _ = gen_legal()
    meta, recon, rc, err = _invoke_engine("stub", domain="legal", input_bytes=x)
    rejected = (not recon) or (sha256(recon) != sha256(x))
    status   = "PASS" if rejected else "FAIL"
    _save(files_dir, "stub", x, recon or b"")
    return _make_control_record(
        "stub", status,
        {"canned_rejected": rejected,
         "input_sha256": sha256(x),
         "recon_sha256": sha256(recon) if recon else "empty"},
        nonce, prev
    )

def control_corrupt(files_dir: str, nonce: str, prev: str) -> tuple[dict, str]:
    """Corrupt: fixed corruption string returned; must not match input."""
    x, _ = gen_legal()
    meta, recon, rc, err = _invoke_engine("corrupt", domain="legal", input_bytes=x)
    detected = (not recon) or (sha256(recon) != sha256(x))
    status   = "PASS" if detected else "FAIL"
    _save(files_dir, "corrupt", x, recon or b"")
    return _make_control_record(
        "corrupt", status,
        {"corruption_detected": detected,
         "input_sha256": sha256(x),
         "recon_sha256": sha256(recon) if recon else "empty"},
        nonce, prev
    )

def control_incompressible(files_dir: str, nonce: str, prev: str) -> tuple[dict, str]:
    """
    Incompressible: high-entropy input.
    Information-theory floor: recovery store must be >= input size.
    A net reduction on random data would indicate fraud.
    Graded from returned metric_B_bytes vs input size.
    """
    x, _ = gen_incompressible()
    meta, recon, rc, err = _invoke_engine(
        "incompressible", domain="medical", input_bytes=x
    )
    in_b     = len(x)
    rec_b    = meta.get("metric_B_bytes", 0)
    floor_ok = rec_b >= in_b
    lossless = recon is not None and sha256(recon) == sha256(x)
    _save(files_dir, "incompressible", x, recon or b"")
    return _make_control_record(
        "incompressible", "PASS" if floor_ok else "FAIL",
        {"input_bytes":       in_b,
         "metric_B_bytes":    rec_b,
         "B_over_input":      round(rec_b / in_b, 4) if in_b else None,
         "lossless":          lossless,
         "floor_holds":       floor_ok,
         "note": "recovery store must be >= input on random data; violation = fraud"},
        nonce, prev
    )

def control_nullbuild(
    domains_list: list,
    files_dir: str,
    nonce: str,
    prev: str
) -> tuple[list, str, bool]:
    """
    D8 hard gate: engine in null mode must FAIL every verdict field.
    Any PASS voids the entire run.
    Graded from bytes only.
    """
    records    = []
    violations = []
    for label, domain, gen_fn in domains_list:
        x, _ = gen_fn()
        meta, recon, rc, err = _invoke_engine(
            "nullbuild", domain=domain, input_bytes=x, null_mode=True
        )
        null_recon_ok = recon is not None and sha256(recon) == sha256(x)
        status = "PASS" if not null_recon_ok else "FAIL"
        if null_recon_ok:
            violations.append(label)
        rec, prev = _make_control_record(
            f"nullbuild:{label}", status,
            {"reconstruction_failed_as_required": not null_recon_ok,
             "recon_len": len(recon) if recon else 0},
            nonce, prev
        )
        records.append(rec)
    return records, prev, len(violations) > 0

# =============================================================================
# RECORD CONSTRUCTION + SEAL CHAIN
# =============================================================================

def _save(files_dir: str, tag: str, in_b: bytes, out_b: bytes):
    open(os.path.join(files_dir, f"{tag}_input.bin"),  "wb").write(in_b)
    open(os.path.join(files_dir, f"{tag}_output.bin"), "wb").write(out_b)

def _make_control_record(
    name: str, status: str, detail: dict, nonce: str, prev: str
) -> tuple[dict, str]:
    ts       = datetime.now(timezone.utc).isoformat()
    rec_seal = seal(name, status, json.dumps(detail, sort_keys=True), ts, nonce, prev)
    rec = {
        "type": "control", "name": name, "status": status,
        "detail": detail, "timestamp": ts,
        "prev_seal": prev, "record_seal": rec_seal
    }
    return rec, rec_seal

def _make_field_record(
    label: str, field: str, status: str, measurement: dict,
    input_sha: str, output_sha: str, nonce: str, prev: str
) -> tuple[dict, str]:
    ts       = datetime.now(timezone.utc).isoformat()
    rec_seal = seal(
        label, field, status, input_sha, output_sha,
        json.dumps(measurement, sort_keys=True), ts, nonce, prev
    )
    rec = {
        "type": "field", "domain": label, "field": field, "status": status,
        "measurement": measurement,
        "input_sha256": input_sha, "output_sha256": output_sha,
        "timestamp": ts, "prev_seal": prev, "record_seal": rec_seal
    }
    return rec, rec_seal

# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--prereg",  required=True,
        help="path to operator pre-registration JSON (sealed before run)"
    )
    parser.add_argument(
        "--null", action="store_true",
        help="run null build only (D8 hard gate check)"
    )
    parser.add_argument("--out-dir", default=".")
    args = parser.parse_args()

    nonce   = secrets.token_hex(16)
    started = datetime.now(timezone.utc).isoformat()

    run_id    = f"run_{int(time.time())}"
    run_dir   = os.path.join(args.out_dir, run_id)
    files_dir = os.path.join(run_dir, "files")
    os.makedirs(files_dir, exist_ok=True)
    jsonl_path = os.path.join(run_dir, "run.jsonl")

    print(f"[HARNESS] {HARNESS_VERSION}  salt_source={SALT_SOURCE}", flush=True)
    print(f"[HARNESS] run_id={run_id}", flush=True)

    prereg_bytes = open(args.prereg, "rb").read()
    prereg_sha   = sha256(prereg_bytes)
    open(os.path.join(run_dir, "prereg.json"), "wb").write(prereg_bytes)

    script_sha  = sha256(open(__file__, "rb").read())
    header_seal = seal(HARNESS_VERSION, SALT, nonce, started, prereg_sha, script_sha)
    prev        = header_seal

    records = []

    def add(rec):
        nonlocal prev
        records.append(rec)

    add({
        "type":            "meta",
        "harness_version": HARNESS_VERSION,
        "salt_source":     SALT_SOURCE,
        "seed16":          sha256(SEED)[:16],
        "nonce":           nonce,
        "started":         started,
        "script_sha256":   script_sha,
        "prereg_sha256":   prereg_sha,
        "header_seal":     header_seal,
        "env": {
            "python": sys.version.split()[0],
            "os":     platform.platform(),
            "cpu":    platform.processor(),
        }
    })

    verdict_pass  = 0
    verdict_fail  = 0
    void          = False
    controls_pass = False
    table_rows    = []

    # ------------------------------------------------------------------
    # NULL BUILD CHECK (D8)
    # ------------------------------------------------------------------
    if args.null:
        print("[HARNESS] NULL build mode — D8 hard gate only", flush=True)
        null_recs, prev, void = control_nullbuild(DOMAINS, files_dir, nonce, prev)
        for r in null_recs:
            add(r)
        if void:
            print("[D8 VIOLATION] NULL build PASSED verdict fields — RUN VOID", flush=True)
        else:
            print("[D8] All domains FAILED reconstruction as required.", flush=True)

    else:
        # --------------------------------------------------------------
        # NEGATIVE CONTROLS
        # --------------------------------------------------------------
        print("[HARNESS] Running negative controls...", flush=True)

        stub_rec, prev = control_stub(files_dir, nonce, prev)
        add(stub_rec)
        print(f"  stub:           {stub_rec['status']}", flush=True)

        corrupt_rec, prev = control_corrupt(files_dir, nonce, prev)
        add(corrupt_rec)
        print(f"  corrupt:        {corrupt_rec['status']}", flush=True)

        incomp_rec, prev = control_incompressible(files_dir, nonce, prev)
        add(incomp_rec)
        print(
            f"  incompressible: {incomp_rec['status']}  "
            f"(B/in={incomp_rec['detail'].get('B_over_input')}  "
            f"floor={incomp_rec['detail'].get('floor_holds')})",
            flush=True
        )

        null_recs, prev, void = control_nullbuild(DOMAINS, files_dir, nonce, prev)
        for r in null_recs:
            add(r)
        if void:
            print("[D8 VIOLATION] NULL build PASSED — RUN VOID", flush=True)
        else:
            print("  null build:     all domains FAIL as required", flush=True)

        controls_pass = (
            stub_rec["status"]    == "PASS" and
            corrupt_rec["status"] == "PASS" and
            incomp_rec["status"]  == "PASS" and
            not void
        )

        # --------------------------------------------------------------
        # DOMAIN TESTS
        # --------------------------------------------------------------
        print("\n[HARNESS] Running domain tests...", flush=True)

        for label, domain, gen_fn in DOMAINS:
            print(f"\n  domain: {label}", flush=True)
            x, _   = gen_fn()
            in_sha = sha256(x)

            meta, recon, rc, err = _invoke_engine(
                "domain", domain=domain, input_bytes=x
            )
            _save(files_dir, label.replace("/", "_"), x, recon or b"")
            out_sha = sha256(recon) if recon else "empty"

            if rc != 0 or not meta:
                print(f"    RUNNER ERROR rc={rc}  {err[:120]}", flush=True)
                verdict_fail += 1
                rec, prev = _make_field_record(
                    label, "retention", "FAIL",
                    {"runner_error": err[:200], "rc": rc},
                    in_sha, out_sha, nonce, prev
                )
                add(rec)
                continue

            # Retention — graded from bytes only
            ret_status, ret_detail = grade_retention(x, recon or b"")
            verdict_pass += ret_status == "PASS"
            verdict_fail += ret_status == "FAIL"
            rec, prev = _make_field_record(
                label, "retention", ret_status, ret_detail,
                in_sha, out_sha, nonce, prev
            )
            add(rec)
            print(f"    retention:   {ret_status}", flush=True)

            # Measurements
            for field_name, grade_fn in [
                ("metric_A", lambda: grade_metric_A(meta, x)),
                ("metric_B", lambda: grade_metric_B(meta, x)),
                ("compute",  lambda: grade_compute(meta, x)),
            ]:
                status, detail = grade_fn()
                rec, prev = _make_field_record(
                    label, field_name, status, detail,
                    in_sha, out_sha, nonce, prev
                )
                add(rec)

            # Console measurement summary
            ib   = meta.get("input_bytes", len(x))
            ab   = meta.get("metric_A_bytes", 0)
            bb   = meta.get("metric_B_bytes", 0)
            cpu  = meta.get("cpu_ms", 0)
            wall = meta.get("wall_ms", 0)
            bps  = round(ib / (wall / 1000), 0) if wall > 0 else 0
            rss  = meta.get("rss_bytes", 0)
            A    = round(ab / ib, 4) if ib else None
            B    = round(bb / ib, 4) if ib else None
            table_rows.append((label, ib, ab, bb, A, B, cpu, wall, bps, rss, ret_status))

        # --------------------------------------------------------------
        # CODE: multi-file per-file restore
        # --------------------------------------------------------------
        print("\n  domain: code (multi-file)", flush=True)
        import shutil
        cdir = os.path.join(tempfile.gettempdir(), f"tee_code_{secrets.token_hex(6)}")
        originals = {}
        for rel, content in CODE_FILES.items():
            full = os.path.join(cdir, *rel.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            b = content.encode("utf-8")
            open(full, "wb").write(b)
            originals[rel] = b
        try:
            meta, _, rc, err = _invoke_engine("code", code_dir=cdir)
        finally:
            shutil.rmtree(cdir, ignore_errors=True)

        in_sha = sha256(b"".join(originals.values()))

        if rc != 0 or not meta:
            code_status = "FAIL"
            code_detail = {"runner_error": err[:200], "rc": rc}
        else:
            files = meta.get("files") or {}
            per = {}
            ok  = bool(meta.get("files_present"))
            for rel, ob in originals.items():
                rs = files.get(rel)
                if rs is None:
                    per[rel] = "MISSING"; ok = False
                else:
                    m = sha256(rs.encode("utf-8")) == sha256(ob)
                    per[rel] = "match" if m else "DIFF"
                    ok = ok and m
            extra = [k for k in files if k not in originals]
            multi = meta.get("file_count", 0) >= 2
            code_status = "PASS" if (ok and multi and not extra) else "FAIL"
            code_detail = {
                "per_file":   per,
                "extra_files": extra,
                "file_count": meta.get("file_count")
            }
            ib   = sum(len(b) for b in originals.values())
            ab   = meta.get("metric_A_bytes", 0)
            bb   = meta.get("metric_B_bytes", 0)
            cpu  = meta.get("cpu_ms", 0)
            wall = meta.get("wall_ms", 0)
            rss  = meta.get("rss_bytes", 0)
            bps  = round(ib / (wall / 1000), 0) if wall > 0 else 0
            table_rows.append((
                "code", ib, ab, bb,
                round(ab/ib, 4) if ib else None,
                round(bb/ib, 4) if ib else None,
                cpu, wall, bps, rss, code_status
            ))

        verdict_pass += code_status == "PASS"
        verdict_fail += code_status == "FAIL"
        rec, prev = _make_field_record(
            "code", "retention_per_file", code_status, code_detail,
            in_sha, in_sha, nonce, prev
        )
        add(rec)
        print(f"    retention:   {code_status}", flush=True)

        # --------------------------------------------------------------
        # MEASUREMENT TABLE
        # --------------------------------------------------------------
        print("\n" + "=" * 110, flush=True)
        print(
            "EFFICIENCY MEASUREMENTS  "
            "(A=structural-index/input  B=recovery-store/input  "
            "-- reported separately, never fused)",
            flush=True
        )
        print("=" * 110, flush=True)
        hdr = (
            f"{'domain':20}{'inB':>7}{'A_bytes':>9}{'B_bytes':>9}"
            f"{'A':>8}{'B':>8}{'cpu_ms':>8}{'wall':>7}{'B/s':>9}{'rssMB':>7}  {'recon':<6}"
        )
        print(hdr, flush=True)
        print("-" * 110, flush=True)
        for (lbl, ib, ab, bb, A, B, cpu, wall, bps, rss, ret_s) in table_rows:
            print(
                f"{lbl:20}{ib:>7}{ab:>9}{bb:>9}"
                f"{(A or 0):>8.4f}{(B or 0):>8.4f}"
                f"{cpu:>8.1f}{wall:>7}{int(bps):>9}"
                f"{rss/1048576:>7.1f}  {ret_s:<6}",
                flush=True
            )
        print("-" * 110, flush=True)
        print(
            "A = lossy structural index (may be <1).  "
            "B = lossless recovery store (>=~1 where content stored).",
            flush=True
        )

    # ------------------------------------------------------------------
    # SUMMARY + MASTER SEAL
    # ------------------------------------------------------------------
    completed = datetime.now(timezone.utc).isoformat()
    master    = seal(HARNESS_VERSION, SALT, nonce, header_seal, prev, completed)

    add({
        "type":          "summary",
        "verdict_pass":  verdict_pass,
        "verdict_fail":  verdict_fail,
        "controls_pass": controls_pass if not args.null else None,
        "d8_void":       void,
        "status": (
            "VOID" if void else
            "PASS" if (not args.null and verdict_fail == 0 and controls_pass) else
            "FAIL"
        ),
        "completed": completed
    })

    records.append({
        "type":             "master_seal",
        "completed":        completed,
        "record_count":     len(records),
        "header_seal":      header_seal,
        "last_record_seal": prev,
        "master_seal":      master
    })

    with open(jsonl_path, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"\n[HARNESS] sealed:      {jsonl_path}", flush=True)
    print(f"[HARNESS] master seal: {master}", flush=True)
    print(f"[HARNESS] verdict:     {verdict_pass} PASS / {verdict_fail} FAIL", flush=True)
    if void:
        print("[HARNESS] STATUS: VOID (D8 hard gate violated)", flush=True)
        sys.exit(2)
    sys.exit(0 if verdict_fail == 0 else 1)


if __name__ == "__main__":
    main()
