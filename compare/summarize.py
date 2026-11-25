#!/usr/bin/env python3
"""Turns the results of `cargo bench` into the tables and the chart in readme.md.

Run the benchmarks first (see tests/compare.rs), then:

    python3 summarize.py            # prints the tables
    python3 summarize.py --chart    # also writes speed.svg

It only needs the standard library.
"""
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CRITERION = HERE / "target" / "criterion"
STRING_LENGTHS = [1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535]
# The tables of times stop here. Longer input is in the table of throughput, and in the chart.
TABLE_LENGTHS = [length for length in STRING_LENGTHS if length < 1024]
LONG_LENGTHS = [length for length in STRING_LENGTHS if length >= 1023]

# Directory name in target/criterion -> name in the tables. The order here is only used to break ties.
HASHERS = {
    "aHash": "**aHash** (AES)",
    "aHash-fallback": "**aHash** (fallback)",
    "foldhash-fast": "foldhash (fast)",
    "foldhash-quality": "foldhash (quality)",
    "rapidhash-fast": "rapidhash (fast)",
    "rapidhash-quality": "rapidhash (quality)",
    "rustc-hash": "rustc-hash (FxHash 2)",
    "fxhash": "fxhash (original FxHash)",
    "fnv": "fnv",
    "xxh3": "xxh3 (xxhash-rust)",
    "siphash-1-3": "SipHash-1-3 (std)",
    "siphash-2-4": "SipHash-2-4",
    "seahash": "seahash",
}

# The hashers which pass every test of SMHasher3. For aHash this is from running it (see ../smhasher), and for
# foldhash and rapidhash from running their crates through the same tests. For the others it is from the results
# which SMHasher3 publishes, or from their authors.
# (https://gitlab.com/fwojcik/smhasher3/-/blob/main/results/README.md)
PASSES_SMHASHER3 = {
    "aHash",
    "aHash-fallback",
    "foldhash-quality",
    "rapidhash-quality",
    "siphash-1-3",
    "siphash-2-4",
}


def estimate(*path):
    """The time Criterion reports for a benchmark, in ns. None if it has not been run."""
    file = CRITERION.joinpath(*map(str, path), "new", "estimates.json")
    if not file.exists():
        return None
    data = json.loads(file.read_text())
    return (data.get("slope") or data["mean"])["point_estimate"]


def load():
    results = {}
    for name in HASHERS:
        row = {"u64": estimate("u64", name)}
        for length in STRING_LENGTHS:
            row[length] = estimate("string", name, length)
        if row["u64"] is not None:
            results[name] = row
    return results


def fmt(ns):
    if ns is None:
        return ""
    if ns < 10:
        return f"{ns:.2f}"
    if ns < 100:
        return f"{ns:.1f}"
    return f"{ns:.0f}"


def table(results, columns, sort_key, names=None):
    """A markdown table with one row per hasher. The fastest time of each column is bold."""
    names = [n for n in (names or results) if n in results]
    names.sort(key=lambda n: results[n][sort_key])
    best = {key: min(results[n][key] for n in names) for key, _ in columns}
    lines = ["| Hasher | " + " | ".join(title for _, title in columns) + " |"]
    lines.append("|---|" + "---:|" * len(columns))
    for name in names:
        cells = []
        for key, _ in columns:
            text = fmt(results[name][key])
            cells.append(f"**{text}**" if results[name][key] == best[key] else text)
        lines.append(f"| {HASHERS[name]} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def throughput_table(results, lengths, names):
    """A markdown table of GB per second, with one row per hasher. The highest of each column is bold."""
    names = sorted((n for n in names if n in results), key=lambda n: -lengths[-1] / results[n][lengths[-1]])
    speed = {n: {length: length / results[n][length] for length in lengths} for n in names}
    best = {length: max(speed[n][length] for n in names) for length in lengths}
    lines = ["| Hasher | " + " | ".join(length_label(length) for length in lengths) + " |"]
    lines.append("|---|" + "---:|" * len(lengths))
    for name in names:
        cells = []
        for length in lengths:
            text = fmt(speed[name][length])
            cells.append(f"**{text}**" if speed[name][length] == best[length] else text)
        lines.append(f"| {HASHERS[name]} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------
# The chart: How fast a string is hashed against its length, as one line per hasher on log scales. The speed is the
# throughput, in bytes per nanosecond (which is GB per second), so that higher is better and the lines level off
# where a hasher reaches its full speed. The hashers which pass SMHasher3 and the ones which do not are in separate
# panels with the same axes, and aHash is in both.

# Hasher -> (color, dashed, label). A color is one hasher, or two variants of one: Then the second is dashed.
SERIES = {
    "aHash": ("c1", False, "aHash (AES)"),
    "aHash-fallback": ("c2", False, "aHash (fallback)"),
    "foldhash-quality": ("c3", False, "foldhash (quality)"),
    "foldhash-fast": ("c3", False, "foldhash (fast)"),
    "rapidhash-quality": ("c4", False, "rapidhash (quality)"),
    "rapidhash-fast": ("c4", False, "rapidhash (fast)"),
    "siphash-1-3": ("c5", False, "SipHash-1-3 (std)"),
    "siphash-2-4": ("c5", True, "SipHash-2-4"),
    "rustc-hash": ("c6", False, "rustc-hash"),
    "fxhash": ("c6", True, "fxhash (original)"),
    "fnv": ("c7", False, "fnv"),
    "xxh3": ("c8", False, "xxh3"),
    "seahash": ("c9", False, "seahash"),
}

LIGHT = dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9", axis="#c3c2b7",
             c1="#2a78d6", c2="#eb6834", c3="#1baf7a", c4="#eda100", c5="#e87ba4", c6="#008300", c7="#6250d6",
             c8="#e34948", c9="#898781")
DARK = dict(surface="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a", axis="#383835",
            c1="#3987e5", c2="#d95926", c3="#199e70", c4="#c98500", c5="#d55181", c6="#0ca30c", c7="#9085e9",
            c8="#e66767", c9="#898781")


def spread(targets, gap, low, high):
    """Moves the positions apart until no two are closer than `gap`, keeping them between `low` and `high`."""
    order = sorted(range(len(targets)), key=lambda i: targets[i])
    pos = [min(max(targets[i], low), high) for i in order]
    for _ in range(200):
        moved = False
        for i in range(1, len(pos)):
            overlap = gap - (pos[i] - pos[i - 1])
            if overlap > 0.01:
                pos[i - 1] -= overlap / 2
                pos[i] += overlap / 2
                moved = True
        shift = max(low - pos[0], 0) + min(high - pos[-1], 0)
        pos = [value + shift for value in pos]
        if not moved:
            break
    result = [0.0] * len(targets)
    for i, value in zip(order, pos):
        result[i] = value
    return result


def length_label(length):
    return str(length) if length < 1024 else f"{(length + 1) // 1024}K"


def chart(results, names):
    names = [n for n in names if n in results and n in SERIES]
    lengths = [length for length in STRING_LENGTHS if all(results[n].get(length) for n in names)]
    last = lengths[-1]

    def speed(name, length):
        return length / results[name][length]

    passing = [n for n in names if n in PASSES_SMHASHER3]
    failing = [n for n in names if n not in PASSES_SMHASHER3]
    # aHash is drawn in the second panel as well, to compare the others against.
    panels = [("Hashers which pass SMHasher3", passing),
              ("Hashers which do not pass SMHasher3", [n for n in ("aHash",) if n in results] + failing)]

    margin, gap, width = 16, 24, 880
    panel_w = (width - 2 * margin - gap) / 2
    tick_w, label_w = 40, 114
    plot_w, plot_h, plot_top = panel_w - tick_w - label_w, 300, 132
    plot_bottom = plot_top + plot_h
    height = plot_bottom + 58

    def css(colors):
        return "".join(f"--{key}:{value};" for key, value in colors.items())

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-labelledby="title desc" font-family="system-ui, -apple-system, \'Segoe UI\', sans-serif">',
        '<title id="title">Speed of hashing a string by its length, for each hasher</title>',
        f'<desc id="desc">Two line charts of the throughput in gigabytes per second of hashing a string of 1 to '
        f'{last} bytes, with both axes on a log scale: One for the hashers which pass SMHasher3 and one for those '
        f'which do not. The numbers are in the tables of compare/readme.md.</desc>',
        "<style>",
        f":root{{{css(LIGHT)}}}",
        f"@media (prefers-color-scheme: dark){{:root{{{css(DARK)}}}}}",
        ".surface{fill:var(--surface)}.title{fill:var(--ink);font-size:15px;font-weight:600}"
        ".sub{fill:var(--ink2);font-size:12px}.name{fill:var(--ink2);font-size:11px}"
        ".name.hl{fill:var(--ink);font-weight:600}.panel{fill:var(--ink);font-size:12px;font-weight:600}"
        ".tick{fill:var(--muted);font-size:10px;font-variant-numeric:tabular-nums}"
        ".grid{stroke:var(--grid);stroke-width:1}.minor{opacity:.55}.axis{stroke:var(--axis);stroke-width:1}"
        ".line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}.line.hl{stroke-width:3}"
        ".line.dash{stroke-dasharray:5 4}.halo{fill:none;stroke:var(--surface);stroke-width:5;stroke-linejoin:round}"
        ".lead{fill:none;stroke-width:1;opacity:.7}"
        + "".join(f".{c}{{stroke:var(--{c})}}" for c in sorted({v[0] for v in SERIES.values()})),
        "</style>",
        f'<rect class="surface" width="{width}" height="{height}" rx="8"/>',
        f'<text class="title" x="{margin}" y="30">Speed of hashing a string, by its length</text>',
        f'<text class="sub" x="{margin}" y="52">Gigabytes hashed per second: Higher is better. Both axes are log '
        f'scales, and are the same in both panels.</text>',
    ]

    values = [speed(n, length) for n in names for length in lengths]
    low = 10.0 ** math.floor(math.log10(min(values)))
    for step in (5, 2):
        if min(values) / low >= step * 1.1:
            low *= step
            break
    high = 10.0 ** math.floor(math.log10(max(values)))
    high *= next(step for step in (1, 2, 5, 10, 20) if max(values) * 1.1 <= high * step)

    def y(value):
        return plot_bottom - (math.log10(value) - math.log10(low)) / (math.log10(high) - math.log10(low)) * plot_h

    for index, (title, members) in enumerate(panels):
        x0 = margin + index * (panel_w + gap) + tick_w
        x1 = x0 + plot_w

        def x(length):
            return x0 + 8 + math.log(length) / math.log(last) * (plot_w - 16)

        out.append(f'<text class="panel" x="{x0 - tick_w}" y="{plot_top - 42}">{title}</text>')
        out.append(f'<text class="tick" x="{x0 - tick_w}" y="{plot_top - 18}">GB per second</text>')
        for exponent in range(math.floor(math.log10(low)), math.ceil(math.log10(high)) + 1):
            for digit in (1, 2, 5):
                tick = digit * 10.0 ** exponent
                if not low * 0.999 <= tick <= high * 1.001:
                    continue
                major = digit == 1
                out.append(f'<line class="grid{"" if major else " minor"}" x1="{x0}" x2="{x1}" '
                           f'y1="{y(tick):.1f}" y2="{y(tick):.1f}"/>')
                if major or abs(tick - low) < 1e-9 or abs(tick - high) < 1e-9:
                    out.append(f'<text class="tick" x="{x0 - 6}" y="{y(tick) + 3.5:.1f}" '
                               f'text-anchor="end">{tick:g}</text>')
        out.append(f'<line class="axis" x1="{x0}" x2="{x1}" y1="{plot_bottom}" y2="{plot_bottom}"/>')
        for position, length in enumerate(lengths):
            out.append(f'<line class="axis" x1="{x(length):.1f}" x2="{x(length):.1f}" y1="{plot_bottom}" '
                       f'y2="{plot_bottom + 4}"/>')
            # There is room to name every second length.
            if (len(lengths) - 1 - position) % 2 == 0:
                out.append(f'<text class="tick" x="{x(length):.1f}" y="{plot_bottom + 16}" '
                           f'text-anchor="middle">{length_label(length)}</text>')
        out.append(f'<text class="sub" x="{(x0 + x1) / 2:.1f}" y="{plot_bottom + 38}" text-anchor="middle">'
                   f'String length in bytes</text>')

        # aHash is drawn last, so it is on top.
        for name in sorted(members, key=lambda n: n.startswith("aHash")):
            color, dashed, _ = SERIES[name]
            points = " ".join(f"{x(length):.1f},{y(speed(name, length)):.1f}" for length in lengths)
            highlight = name.startswith("aHash")
            if highlight:
                out.append(f'<polyline class="halo" points="{points}"/>')
            out.append(f'<polyline class="line {color}{" hl" if highlight else ""}{" dash" if dashed else ""}" '
                       f'points="{points}"/>')
        # Each line is named where it ends. Names which would overlap are moved apart, and tied to their line.
        ends = [y(speed(name, last)) for name in members]
        places = spread(ends, 13, plot_top + 4, plot_bottom - 2)
        for name, end, place in zip(members, ends, places):
            color, _, label = SERIES[name]
            xe = x(last)
            out.append(f'<polyline class="lead {color}" points="{xe + 3:.1f},{end:.1f} {x1 + 4:.1f},{end:.1f} '
                       f'{x1 + 12:.1f},{place:.1f} {x1 + 16:.1f},{place:.1f}"/>')
            out.append(f'<text class="name{" hl" if name.startswith("aHash") else ""}" x="{x1 + 19:.1f}" '
                       f'y="{place + 3.5:.1f}">{label}</text>')
    out.append("</svg>")
    (HERE / "speed.svg").write_text("\n".join(out) + "\n")


def main():
    results = load()
    if not results:
        sys.exit(f"No results in {CRITERION}. Run the benchmarks first.")
    names = list(results)
    groups = [("which pass SMHasher3", [n for n in names if n in PASSES_SMHASHER3]),
              ("which do not pass SMHasher3", [n for n in names if n not in PASSES_SMHASHER3])]
    summary = [("u64", "u64"), (15, "15 byte string"), (1023, "1023 byte string")]
    for title, group in groups:
        print(f"## Summary (ns): Hashers {title}\n")
        print(table(results, summary, 15, group) + "\n")
    for title, group in groups:
        print(f"## Strings by length (ns): Hashers {title}\n")
        print(table(results, [(length, str(length)) for length in TABLE_LENGTHS], 15, group) + "\n")
    long_lengths = [length for length in LONG_LENGTHS if all(results[n].get(length) for n in names)]
    if len(long_lengths) > 1:
        for title, group in groups:
            print(f"## Long strings (GB per second): Hashers {title}\n")
            print(throughput_table(results, long_lengths, group) + "\n")
    if "--chart" in sys.argv:
        chart(results, names)
        print(f"\nWrote {HERE / 'speed.svg'}", file=sys.stderr)


if __name__ == "__main__":
    main()
