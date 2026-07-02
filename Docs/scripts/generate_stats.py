#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATS_DIR = ROOT / "Stats"
OUT_DIR = ROOT / "generated"

NUMERIC_FIELDS = {
    "ElapsedMilliseconds",
    "ThroughputMegabytesPerSecond",
    "SpeedupVsSequentialNativeCpu",
    "ManagedReferenceRatio",
    "KeySizeBits",
    "DataSizeMegabytes",
}


def _norm_condition(cond: str | None) -> str:
    if not cond:
        return ""
    return cond.replace("chaergerON", "ChargerON")


def _parse_filename(filename: str) -> tuple[str, str, str]:
    name = filename.replace(".csv", "")
    parts = name.split("_")
    pc = parts[0]
    arch = ""
    cond = ""
    if len(parts) >= 2 and parts[1] in ("x64", "x86"):
        arch = parts[1]
        rest = parts[2:]
    else:
        rest = parts[1:]
    if rest:
        cond = "_".join(rest)
    return pc, arch, _norm_condition(cond)


def _safe_float(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return float(value)
    s = str(value).strip()
    if not s or s.lower() == "nan":
        return None
    try:
        return float(s)
    except Exception:
        return None


def _safe_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in {"true", "1", "yes"}


def _num_to_csv(value):
    if value is None:
        return ""
    if isinstance(value, float):
        if math.isnan(value):
            return ""
        return f"{value:.12g}"
    return str(value)


def _stdev_or_none(values: list[float]):
    if len(values) < 2:
        return None
    return statistics.stdev(values)


def _read_benchmark_csv(path: Path) -> tuple[dict[str, str], list[dict[str, object]]]:
    meta: dict[str, str] = {}
    data_lines: list[str] = []

    with path.open("r", encoding="utf-8", newline="") as f:
        for line in f:
            if line.startswith("#"):
                line = line.rstrip("\n")
                m = re.match(r"#([^,]+),(.*)$", line)
                if not m:
                    continue
                key = m.group(1).strip()
                val = m.group(2).strip()
                if len(val) >= 2 and val[0] == val[-1] == '"':
                    val = val[1:-1]
                meta[key] = val
            else:
                if line.strip():
                    data_lines.append(line)

    rows: list[dict[str, object]] = []
    if data_lines:
        reader = csv.DictReader(data_lines)
        for row in reader:
            out: dict[str, object] = {}
            for key, value in row.items():
                if key in NUMERIC_FIELDS:
                    out[key] = _safe_float(value)
                elif key == "Succeeded":
                    out[key] = _safe_bool(value)
                else:
                    out[key] = value.strip() if isinstance(value, str) else value
            rows.append(out)

    return meta, rows


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _num_to_csv(row.get(k, "")) for k in fieldnames})


def _sorted_unique(rows: list[dict[str, object]], keys: list[str], sort_keys: list[str]) -> list[dict[str, object]]:
    seen = set()
    out = []
    for row in rows:
        key = tuple(row.get(k, "") for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append({k: row.get(k, "") for k in keys})
    out.sort(key=lambda r: tuple(str(r.get(k, "")) for k in sort_keys))
    return out


def _group_summary(rows: list[dict[str, object]], group_cols: list[str]) -> list[dict[str, object]]:
    grouped: dict[tuple, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        key = tuple(row.get(c, "") for c in group_cols)
        grouped[key].append(row)

    out: list[dict[str, object]] = []
    for key, items in grouped.items():
        record = {col: key[idx] for idx, col in enumerate(group_cols)}
        ms_vals = [v for v in (_safe_float(item.get("ElapsedMilliseconds")) for item in items) if v is not None]
        mbps_vals = [v for v in (_safe_float(item.get("ThroughputMegabytesPerSecond")) for item in items) if v is not None]
        speed_vals = [v for v in (_safe_float(item.get("SpeedupVsSequentialNativeCpu")) for item in items) if v is not None]

        record.update(
            {
                "n": len(items),
                "mean_ms": statistics.mean(ms_vals) if ms_vals else None,
                "sd_ms": _stdev_or_none(ms_vals),
                "mean_mbps": statistics.mean(mbps_vals) if mbps_vals else None,
                "sd_mbps": _stdev_or_none(mbps_vals),
                "mean_speedup": statistics.mean(speed_vals) if speed_vals else None,
            }
        )
        out.append(record)

    out.sort(
        key=lambda r: (
            str(r.get("PC", "")),
            str(r.get("BuildArchitecture", "")),
            str(r.get("ConditionFile", "")),
            str(r.get("Algorithm", "")),
            _safe_float(r.get("KeySizeBits")) or -1,
            _safe_float(r.get("DataSizeMegabytes")) or -1,
            str(r.get("Engine", "")),
            str(r.get("Direction", "")),
        )
    )
    return out


def _filter_rows(rows: list[dict[str, object]], **criteria) -> list[dict[str, object]]:
    def _match_value(actual, expected) -> bool:
        if isinstance(expected, tuple):
            return any(_match_value(actual, item) for item in expected)
        if expected == "":
            return str(actual or "") == ""
        a_num = _safe_float(actual)
        e_num = _safe_float(expected)
        if a_num is not None and e_num is not None:
            return a_num == e_num
        return str(actual) == str(expected)

    out = []
    for row in rows:
        ok = True
        for key, expected in criteria.items():
            if not _match_value(row.get(key, ""), expected):
                ok = False
                break
        if ok:
            out.append(row)
    return out


def _arch_compare(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_pair: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        pair = (str(row.get("Engine", "")), str(row.get("Direction", "")))
        item = by_pair.setdefault(pair, {"Engine": pair[0], "Direction": pair[1], "x86": "", "x64": "", "ratio_x64_over_x86": ""})
        arch = str(row.get("BuildArchitecture", ""))
        item[arch] = row.get("mean_mbps", "")
    out = []
    for _, item in sorted(by_pair.items()):
        x86 = _safe_float(item.get("x86"))
        x64 = _safe_float(item.get("x64"))
        if x86 not in (None, 0) and x64 is not None:
            item["ratio_x64_over_x86"] = x64 / x86
        out.append(item)
    return out


def _power_compare(rows: list[dict[str, object]], pc: str, arch: str) -> list[dict[str, object]]:
    on_rows = _filter_rows(rows, PC=pc, Algorithm="Gcm", KeySizeBits=256, DataSizeMegabytes=64, ConditionFile="ChargerON", BuildArchitecture=arch)
    off_rows = _filter_rows(rows, PC=pc, Algorithm="Gcm", KeySizeBits=256, DataSizeMegabytes=64, ConditionFile="ChargerOFF", BuildArchitecture=arch)

    on_map = {(str(r.get("Engine", "")), str(r.get("Direction", ""))): _safe_float(r.get("mean_mbps")) for r in on_rows}
    off_map = {(str(r.get("Engine", "")), str(r.get("Direction", ""))): _safe_float(r.get("mean_mbps")) for r in off_rows}

    rows_out = []
    for pair in sorted(set(on_map) & set(off_map)):
        on_v = on_map[pair]
        off_v = off_map[pair]
        ratio = on_v / off_v if on_v is not None and off_v not in (None, 0) else None
        rows_out.append(
            {
                "Engine": pair[0],
                "Direction": pair[1],
                "ChargerOFF": off_v,
                "ChargerON": on_v,
                "ratio_on_over_off": ratio,
            }
        )
    return rows_out


def _wide_keysize(rows: list[dict[str, object]], pc: str, algo: str, arch: str, direction: str, size: int = 64) -> list[dict[str, object]]:
    src = _filter_rows(rows, PC=pc, Algorithm=algo, BuildArchitecture=arch, Direction=direction, DataSizeMegabytes=size)
    by_key: dict[str, dict[str, object]] = {}
    for row in src:
        key = str(int(float(row.get("KeySizeBits")))) if _safe_float(row.get("KeySizeBits")) is not None else str(row.get("KeySizeBits", ""))
        item = by_key.setdefault(key, {"KeySizeBits": _safe_float(row.get("KeySizeBits")), "NativeCpu": "", "OpenCl": "", "ManagedAes": ""})
        item[str(row.get("Engine", ""))] = row.get("mean_mbps", "")
    out = list(by_key.values())
    out.sort(key=lambda r: _safe_float(r.get("KeySizeBits")) or -1)
    return out


def _wide_datasize(rows: list[dict[str, object]], pc: str, algo: str, arch: str, direction: str, key_bits: int = 256) -> list[dict[str, object]]:
    src = _filter_rows(rows, PC=pc, Algorithm=algo, BuildArchitecture=arch, Direction=direction, KeySizeBits=key_bits)
    by_size: dict[str, dict[str, object]] = {}
    for row in src:
        size = _safe_float(row.get("DataSizeMegabytes"))
        size_key = str(int(size)) if size is not None and float(size).is_integer() else str(size)
        item = by_size.setdefault(size_key, {"DataSizeMegabytes": size, "NativeCpu": "", "OpenCl": "", "ManagedAes": ""})
        item[str(row.get("Engine", ""))] = row.get("mean_mbps", "")
    out = list(by_size.values())
    out.sort(key=lambda r: _safe_float(r.get("DataSizeMegabytes")) or -1)
    return out


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(STATS_DIR.glob("*.csv"))
    if not files:
        raise SystemExit(f"Nincs bemeneti CSV a(z) {STATS_DIR} mappában.")

    meta_rows: list[dict[str, object]] = []
    data_rows: list[dict[str, object]] = []

    for path in files:
        meta, rows = _read_benchmark_csv(path)
        meta["__file"] = path.name
        pc, arch, cond = _parse_filename(path.name)
        meta["PC"] = pc
        meta["ArchFile"] = arch
        meta["ConditionFile"] = cond
        if "BuildArchitecture" not in meta or not meta.get("BuildArchitecture"):
            meta["BuildArchitecture"] = arch
        meta_rows.append(meta)

        for row in rows:
            merged = dict(row)
            merged["__file"] = path.name
            for key, value in meta.items():
                if key not in merged:
                    merged[key] = value
            merged["ConditionFile"] = _norm_condition(str(merged.get("ConditionFile", "")))
            data_rows.append(merged)

    succeeded_rows = [row for row in data_rows if _safe_bool(row.get("Succeeded"))]

    group_cols = ["PC", "BuildArchitecture", "ConditionFile", "Algorithm", "KeySizeBits", "DataSizeMegabytes", "Engine", "Direction"]
    summary_rows = _group_summary(succeeded_rows, group_cols)
    _write_csv(
        OUT_DIR / "summary_all.csv",
        group_cols + ["n", "mean_ms", "sd_ms", "mean_mbps", "sd_mbps", "mean_speedup"],
        summary_rows,
    )

    machine_cols = [
        "PC", "BuildArchitecture", "ConditionFile", "FrameworkDescription", "WindowsVersion", "WindowsBuild",
        "ProcessorName", "ProcessorCoreCount", "ProcessorLogicalCoreCount", "ProcessorMaxClockMHz",
        "GpuName", "RamTotal", "PowerSource",
        "OpenClPlatformName", "OpenClPlatformVersion", "OpenClDeviceName", "OpenClDeviceVersion", "OpenClCVersion",
    ]
    machine_rows = []
    for row in meta_rows:
        machine_rows.append({k: row.get(k, "") for k in machine_cols})
    machine_rows = _sorted_unique(machine_rows, machine_cols, ["PC", "BuildArchitecture", "ConditionFile"])
    _write_csv(OUT_DIR / "machines.csv", machine_cols, machine_rows)

    machine_rows_pgf = []
    for row in machine_rows:
        machine_rows_pgf.append({k: str(v).replace(",", " ") for k, v in row.items()})
    _write_csv(OUT_DIR / "machines_pgf.csv", machine_cols, machine_rows_pgf)

    machine_summary_cols = [
        "PC", "BuildArchitecture", "PowerSourceHu", "WindowsBuild",
        "ProcessorName", "GpuName", "OpenClPlatformName",
    ]
    machine_summary_rows = []
    seen_summary = set()
    power_map = {"AC power": "Töltő", "Battery": "Akku"}
    for row in machine_rows:
        summary_row = {
            "PC": row.get("PC", ""),
            "BuildArchitecture": row.get("BuildArchitecture", ""),
            "PowerSourceHu": power_map.get(str(row.get("PowerSource", "")), str(row.get("PowerSource", ""))),
            "WindowsBuild": row.get("WindowsBuild", ""),
            "ProcessorName": row.get("ProcessorName", ""),
            "GpuName": row.get("GpuName", ""),
            "OpenClPlatformName": row.get("OpenClPlatformName", ""),
        }
        key = tuple(summary_row.get(k, "") for k in machine_summary_cols)
        if key in seen_summary:
            continue
        seen_summary.add(key)
        machine_summary_rows.append(summary_row)
    machine_summary_rows.sort(key=lambda r: (str(r.get("PC", "")), str(r.get("BuildArchitecture", "")), str(r.get("PowerSourceHu", ""))))
    _write_csv(OUT_DIR / "machines_summary.csv", machine_summary_cols, machine_summary_rows)
    _write_csv(
        OUT_DIR / "machines_summary_pgf.csv",
        machine_summary_cols,
        [{k: str(v).replace(",", " ") for k, v in row.items()} for row in machine_summary_rows],
    )

    pc2_case = _filter_rows(summary_rows, PC="PC2", Algorithm="Gcm", KeySizeBits=256, DataSizeMegabytes=64, ConditionFile="")
    if pc2_case:
        _write_csv(OUT_DIR / "pc2_arch_gcm256_64mb.csv", ["Engine", "Direction", "x86", "x64", "ratio_x64_over_x86"], _arch_compare(pc2_case))

    for cond in ["ChargerON", "ChargerOFF"]:
        pc3_case = _filter_rows(summary_rows, PC="PC3", Algorithm="Gcm", KeySizeBits=256, DataSizeMegabytes=64, ConditionFile=cond)
        if pc3_case:
            _write_csv(OUT_DIR / f"pc3_arch_gcm256_64mb_{cond}.csv", ["Engine", "Direction", "x86", "x64", "ratio_x64_over_x86"], _arch_compare(pc3_case))

    for arch in ["x64", "x86"]:
        rows = _power_compare(summary_rows, "PC3", arch)
        if rows:
            _write_csv(OUT_DIR / f"pc3_power_gcm256_64mb_{arch}.csv", ["Engine", "Direction", "ChargerOFF", "ChargerON", "ratio_on_over_off"], rows)

    for algo in ["Ctr", "Gcm"]:
        for arch in ["x64", "x86"]:
            for direction in ["Encrypt", "Decrypt"]:
                rows = _wide_keysize(summary_rows, "PC4", algo, arch, direction, 64)
                if rows:
                    _write_csv(OUT_DIR / f"pc4_{algo.lower()}_keysize_64mb_{arch}_{direction.lower()}.csv", ["KeySizeBits", "NativeCpu", "OpenCl", "ManagedAes"], rows)

    for algo in ["Ctr", "Gcm"]:
        for arch in ["x64", "x86"]:
            for direction in ["Encrypt", "Decrypt"]:
                rows = _wide_datasize(summary_rows, "PC4", algo, arch, direction, 256)
                if rows:
                    _write_csv(OUT_DIR / f"pc4_{algo.lower()}_datasize_key256_{arch}_{direction.lower()}.csv", ["DataSizeMegabytes", "NativeCpu", "OpenCl", "ManagedAes"], rows)

    speed_rows = []
    for row in summary_rows:
        if str(row.get("Engine", "")) != "OpenCl":
            continue
        speedup = _safe_float(row.get("mean_speedup"))
        if speedup is None:
            continue
        out = dict(row)
        cond = str(out.get("ConditionFile", "") or "")
        out["PowerState"] = {"ChargerON": "Töltőn", "ChargerOFF": "Akkuról"}.get(cond, "")
        speed_rows.append(out)
    speed_rows.sort(key=lambda r: _safe_float(r.get("mean_speedup")) or float("inf"))

    speed_cols = ["PC", "BuildArchitecture", "PowerState", "Algorithm", "KeySizeBits", "DataSizeMegabytes", "Direction", "mean_speedup", "mean_mbps"]

    if speed_rows:
        _write_csv(OUT_DIR / "speedup_bottom5.csv", speed_cols, speed_rows[:5])
        _write_csv(OUT_DIR / "speedup_top5.csv", speed_cols, list(reversed(speed_rows[-5:])))

        extrema_rows = []
        lo = dict(speed_rows[0])
        lo["Extreme"] = "Legkisebb"
        hi = dict(speed_rows[-1])
        hi["Extreme"] = "Legnagyobb"
        extrema_rows.extend([lo, hi])
        _write_csv(OUT_DIR / "speedup_extremes.csv", ["Extreme", *speed_cols], extrema_rows)

        arch_rows = []
        for arch in ["x64", "x86"]:
            subset = [r for r in speed_rows if str(r.get("BuildArchitecture", "")) == arch]
            if not subset:
                continue
            lo_arch = dict(subset[0])
            lo_arch["Extreme"] = "Legkisebb"
            lo_arch["Architecture"] = arch
            hi_arch = dict(subset[-1])
            hi_arch["Extreme"] = "Legnagyobb"
            hi_arch["Architecture"] = arch
            arch_rows.extend([lo_arch, hi_arch])
        if arch_rows:
            _write_csv(OUT_DIR / "speedup_arch_extremes.csv", ["Extreme", "Architecture", *speed_cols], arch_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
