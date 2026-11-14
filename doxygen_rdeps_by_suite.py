#!/usr/bin/env python3
"""
Parse the jquery.js grep output for doxygen reverse build-deps, classify each
package by how likely it is to break when doxygen stops shipping jquery.js,
then ask rmadison which suites each risky package sits in.

Usage:
  # classify only (no network), prints tiers and writes classification.tsv
  ./doxygen_rdeps_by_suite.py doxygen-reverse-dependencies.txt --no-rmadison

  # full run: classify + rmadison, one list per suite in ./by-suite/
  ./doxygen_rdeps_by_suite.py doxygen-reverse-dependencies.txt

  # show every matching line with its tier/reason, and context under rm lines
  # (context needs results produced by scan_debian_dirs.py, not plain grep)
  ./doxygen_rdeps_by_suite.py scan-results.txt --no-rmadison --detail > detail.txt
  ./doxygen_rdeps_by_suite.py scan-results.txt --no-rmadison --detail LIKELY,CHECK,LOW
  # every matching line is also written to line-classification.tsv

  # also report packages that exist in the full rdeps list but were never grepped
  reverse-depends -b src:doxygen -r tenacious | awk '/^\\*/{print $2}' \\
      | LC_ALL=C sort -u > all-pkgs.txt
  ./doxygen_rdeps_by_suite.py doxygen-reverse-dependencies.txt --pkglist all-pkgs.txt

Tiers (highest wins per package):
  LIKELY  unguarded rm of jquery.js, or .install/.docs naming it explicitly
  CHECK   jquery.js handled in a way that needs the surrounding context
          (guards, variables, debputy/linktree, find/sed/grep logic)
  LOW     only .links / overrides / patches / READMEs: dead symlink at worst
  NONE    package was grepped and had no jquery.js mention
  UNSCANNED  only with --pkglist: in the list but absent from the results file
"""
import argparse
import collections
import pathlib
import re
import subprocess
import sys

TIER_ORDER = ["LIKELY", "CHECK", "LOW", "NONE", "UNSCANNED"]

LOC = re.compile(r"(?P<path>\S*?/debian/[^:\s]+):(?P<ln>\d+):(?P<txt>.*)$")
HDR = re.compile(r"^== (?P<pkg>\S+)\s*$")
PFX = re.compile(r"^(?P<pkg>[A-Za-z0-9][A-Za-z0-9+.\-]*): (?P<rest>\S+/debian/.*)$")


def parse(path):
    """Return (hits, ctx).
    hits: {pkg: [(file_rel_to_debian, lineno, text), ...]}
    ctx:  {pkg: {file: {lineno: text}}} from "@ctx" lines written by
          scan_debian_dirs.py (empty for older grep output)."""
    hits = collections.defaultdict(list)
    ctx = collections.defaultdict(lambda: collections.defaultdict(dict))
    cur = None
    for raw in pathlib.Path(path).read_text(errors="replace").splitlines():
        if raw.startswith("@ctx\t"):
            parts = raw.split("\t", 3)
            if cur is not None and len(parts) == 4 and parts[2].isdigit():
                rel = parts[1][len("debian/"):] if parts[1].startswith("debian/") else parts[1]
                ctx[cur][rel][int(parts[2])] = parts[3]
            continue
        m = HDR.match(raw)
        if m:
            cur = m.group("pkg")
            hits[cur]  # register packages with zero hits
            continue
        pkg, body = cur, raw
        m = PFX.match(raw)
        if m:  # second format: "pkg: src-ver/debian/file:line:text"
            pkg, body = m.group("pkg"), m.group("rest")
        if pkg is None:
            continue
        m = LOC.search(body)
        if not m:
            continue
        rel = m.group("path").split("/debian/", 1)[1]
        hits[pkg].append((rel, int(m.group("ln")), m.group("txt")))
    return hits, ctx


NON_BUILD_SUFFIX = (".links", ".lintian-overrides", ".lintian-override",
                    ".patch", ".html", ".local", ".in")
NON_BUILD_NAMES = {"changelog", "copyright", "control", "clean", "TODO",
                   "series", "not-installed"}


def classify_line(rel, txt):
    base = rel.rsplit("/", 1)[-1]
    if (rel.startswith(("patches/", "source/", "doxygen/"))
            or base in NON_BUILD_NAMES
            or base.startswith("README")
            or base.endswith(NON_BUILD_SUFFIX)):
        # .links.in is still just a links file
        return "LOW", "non-build file"
    t = txt.strip()
    if t.startswith("#"):
        return "LOW", "commented out"

    # exclusions and tolerant removals cannot fail on a missing file
    if re.search(r"-X\s*jquery", t):
        return "LOW", "-X exclusion"
    if re.search(r"(^|\s|;|&&)-\s*rm\b", t):  # make's leading "-" ignores errors
        return "LOW", "-rm (error ignored)"
    if re.search(r"\$\(RM\)|\$\{RM\}", t):    # RM = rm -f
        return "LOW", "$(RM) = rm -f"
    if re.search(r"\brm\s+(-[A-Za-z]*f[A-Za-z]*|--force)\b", t):
        return "LOW", "rm -f"
    if re.search(r"-delete\b|-exec\b", t) and "find" in t:
        return "LOW", "find -delete/-exec"

    # explicit install lists fail on a missing file
    if base.endswith((".install", ".docs", ".examples")):
        return "LIKELY", "file listed in %s" % base

    # bare rm
    if re.search(r"\brm\s+(?!-)", t):
        return "LIKELY", "unguarded rm"

    if re.search(r"\[\s*-[ef]\s", t) or re.search(r"\bif\b.*\bgrep\b", t):
        return "CHECK", "guard/condition, check exit status"
    if re.search(r"^[A-Z_]+\s*[:?]?=", t):
        return "CHECK", "path held in a variable"
    if base in ("debputy.manifest",) or base.endswith("linktrees"):
        return "CHECK", "debputy/linktree handling of missing source"
    if re.search(r"\b(dh_link|sed|perl)\b", t):
        return "LOW", "link/rewrite only, no failure on missing file"
    if re.search(r"\b(dh_install|dh_installdocs|xargs)\b", t):
        return "CHECK", "tool invoked on jquery.js"
    if re.search(r"\bln\b", t):
        return "LOW", "ln (creates link, no failure on missing target)"
    if base == "rules" or base.endswith(".mk") or base in ("Makefile", "dh_doxygen"):
        return "CHECK", "other reference in build file"
    return "LOW", "other"


def classify(hits):
    """Return ({pkg: (tier, why)}, {pkg: [(file, ln, text, tier, reason)]})."""
    out = {}
    per_line = {}
    for pkg, lines in hits.items():
        best, why = "NONE", ""
        per_line[pkg] = []
        prev = {}  # file -> (lineno, tier, text) of previous hit
        for rel, ln, txt in lines:
            tier, reason = classify_line(rel, txt)
            p = prev.get(rel)
            adjacent = p and p[0] == ln - 1
            if adjacent and tier in ("LIKELY", "CHECK"):
                t = txt.strip()
                has_verb = re.search(r"\b(rm|ln|find|dh_\w+|sed|perl)\b", t)
                if p[2].rstrip().endswith("\\") and not has_verb and p[1] == "LOW":
                    tier, reason = "LOW", "continuation of a tolerant command"
                elif re.search(r"\[\s*-[ef]\s", p[2]) and re.search(r"\brm\b", t):
                    tier, reason = "CHECK", "rm inside [ -f ] guard, check exit status"
            prev[rel] = (ln, tier, txt)
            per_line[pkg].append((rel, ln, txt, tier, reason))
            if TIER_ORDER.index(tier) < TIER_ORDER.index(best):
                best, why = tier, "%s:%d %s" % (rel, ln, reason)
        out[pkg] = (best, why)
    return out, per_line


RM_RE = re.compile(r"\brm\b|\$[({]RM[)}]")


def print_detail(pkg, tier, lines, ctx, n, context_all):
    """One header per matching line (tier + reason), context under rm lines."""
    print("== %s [%s]" % (pkg, tier))
    files = collections.OrderedDict()
    for rel, ln, txt, t, why in lines:
        files.setdefault(rel, []).append((ln, txt, t, why))
    have_ctx = bool(ctx.get(pkg))
    for rel, items in files.items():
        text = dict(ctx.get(pkg, {}).get(rel, {}))
        for ln, txt, _, _ in items:
            text[ln] = txt
        hit_lns = {ln for ln, _, _, _ in items}
        shown = set()
        for ln, txt, t, why in items:
            print("  %s:%d  [%s] %s" % (rel, ln, t, why))
            if not (context_all or RM_RE.search(txt)):
                continue
            if ln in shown:
                print("      (shown in the block above)")
                continue
            for j in range(ln - n, ln + n + 1):
                if j in text:
                    mark = ">" if j in hit_lns else " "
                    print("    %s %5d | %s" % (mark, j, text[j]))
                    shown.add(j)
            print()
    if not have_ctx:
        print("  (no context saved for this package: rescan it with "
              "scan_debian_dirs.py)")
    print()


def rmadison(pkgs, chunk=40):
    """Return rows (pkg, version, suite) for *source* entries."""
    rows = []
    for i in range(0, len(pkgs), chunk):
        part = pkgs[i:i + chunk]
        try:
            res = subprocess.run(["rmadison", "-u", "ubuntu", "-S"] + part,
                                 capture_output=True, text=True, timeout=180)
        except FileNotFoundError:
            sys.exit("rmadison not found (apt install devscripts)")
        for line in res.stdout.splitlines():
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 4 and "source" in cols[3]:
                rows.append((cols[0], cols[1], cols[2]))
        if res.returncode and not res.stdout:
            print("rmadison failed for: %s\n%s" % (" ".join(part), res.stderr),
                  file=sys.stderr)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results", help="the jquery.js grep output file")
    ap.add_argument("--pkglist", help="full package list (one per line)")
    ap.add_argument("--include-low", action="store_true",
                    help="also run rmadison for LOW packages")
    ap.add_argument("--suites", help="releases to keep (pockets like -updates/-proposed included), e.g. tenacious,resolute")
    ap.add_argument("--outdir", default="by-suite")
    ap.add_argument("--no-rmadison", action="store_true")
    ap.add_argument("--detail", nargs="?", const="LIKELY,CHECK", metavar="TIERS",
                    help="print every matching line with its tier and reason, "
                         "plus context under rm lines (default tiers: LIKELY,CHECK; "
                         "e.g. --detail LIKELY,CHECK,LOW)")
    ap.add_argument("--context", type=int, default=3,
                    help="context lines to show around a match (default 3)")
    ap.add_argument("--context-all", action="store_true",
                    help="show context under every matching line, not just rm lines")
    a = ap.parse_args()

    hits, ctx = parse(a.results)
    cls, per_line = classify(hits)
    if a.pkglist:
        for p in pathlib.Path(a.pkglist).read_text().split():
            cls.setdefault(p, ("UNSCANNED", "not present in results file"))

    with open("classification.tsv", "w") as f:
        for p in sorted(cls):
            f.write("%s\t%s\t%s\n" % (p, cls[p][0], cls[p][1]))

    with open("line-classification.tsv", "w") as f:
        f.write("package\ttier\tfile\tline\treason\ttext\n")
        for p in sorted(per_line):
            for rel, ln, txt, t, why in per_line[p]:
                f.write("%s\t%s\t%s\t%d\t%s\t%s\n"
                        % (p, t, rel, ln, why, txt.strip().replace("\t", " ")))

    by_tier = collections.defaultdict(list)
    for p, (t, _) in cls.items():
        by_tier[t].append(p)
    print("Packages parsed: %d" % len(cls))
    for t in TIER_ORDER:
        if by_tier[t]:
            print("  %-9s %d" % (t, len(by_tier[t])))
    print()
    for t in ("LIKELY", "CHECK"):
        print("== %s" % t)
        for p in sorted(by_tier[t]):
            print("  %-28s %s" % (p, cls[p][1]))
        print()
    if a.detail:
        want = [t.strip().upper() for t in a.detail.split(",")]
        print("== DETAIL (%s)\n" % ", ".join(want))
        for t in want:
            for p in sorted(by_tier[t]):
                print_detail(p, t, per_line.get(p, []), ctx, a.context, a.context_all)

    if by_tier["UNSCANNED"]:
        print("== UNSCANNED (%d), grep these too" % len(by_tier["UNSCANNED"]))
        print("  " + " ".join(sorted(by_tier["UNSCANNED"])[:40]) +
              (" ..." if len(by_tier["UNSCANNED"]) > 40 else ""))
        print()

    if a.no_rmadison:
        return

    wanted = by_tier["LIKELY"] + by_tier["CHECK"]
    if a.include_low:
        wanted += by_tier["LOW"]
    wanted = sorted(wanted)
    keep = set(a.suites.split(",")) if a.suites else None
    rows = rmadison(wanted)

    suites = collections.defaultdict(list)
    for pkg, ver, suite in rows:
        suite = suite.split("/")[0]  # "tenacious/universe" -> "tenacious"
        if keep and suite.split("-")[0] not in keep:  # match pockets too
            continue
        suites[suite].append((pkg, ver, cls[pkg][0]))

    outdir = pathlib.Path(a.outdir)
    outdir.mkdir(exist_ok=True)
    for suite, items in sorted(suites.items()):
        items.sort(key=lambda x: (TIER_ORDER.index(x[2]), x[0]))
        with open(outdir / ("%s.txt" % suite), "w") as f:
            for pkg, ver, tier in items:
                f.write("%-9s %-28s %s\n" % (tier, pkg, ver))
        n_l = sum(1 for i in items if i[2] == "LIKELY")
        print("%-24s %3d packages (%d LIKELY)" % (suite, len(items), n_l))
    missing = sorted(set(wanted) - {r[0] for r in rows})
    if missing:
        print("\nrmadison returned no source row for: " + " ".join(missing))


if __name__ == "__main__":
    main()