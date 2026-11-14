#!/usr/bin/env python3
"""
Fast jquery.js scan of Ubuntu source packages.

For each package it asks rmadison for the version and component in a release,
downloads only the small .dsc and the .debian.tar.* from the archive pool (no
upstream tarballs), and greps every file under debian/ except changelog and
copyright.

Output (default scan-results.txt) uses the same layout as your earlier grep
output, with a "== pkg" header for EVERY package that was scanned, so packages
with no hits are recorded as clean. Packages that could not be scanned are
written to scan-failures.txt with a reason.

Usage:
  awk -F'\\t' '$2=="UNSCANNED"{print $1}' classification.tsv > unscanned.txt
  ./scan_debian_dirs.py unscanned.txt
  cat doxygen-reverse-dependencies.txt scan-results.txt > combined.txt
  ./doxygen_rdeps_by_suite.py combined.txt --pkglist all-pkgs.txt --suites tenacious,resolute
"""
import argparse
import concurrent.futures as cf
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request


def pool_dir(mirror, comp, src):
    pre = src[:4] if src.startswith("lib") else src[0]
    return "%s/pool/%s/%s/%s" % (mirror, comp, pre, src)


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def dsc_debian_file(dsc_text):
    """Name of the debian tarball listed in a .dsc, or None for native packages."""
    names = re.findall(r"^ [0-9a-f]{32,128} \d+ (\S+)$", dsc_text, re.M)
    for n in names:
        if re.search(r"\.debian\.tar\.(xz|gz|bz2|zst)$", n):
            return n
    for n in names:
        if n.endswith(".diff.gz"):
            return n
    return None


def scan(src, ver, comp, mirror, pat, context=4):
    base = pool_dir(mirror, comp, src)
    v = ver.split(":", 1)[-1]  # epoch is not part of file names
    dsc = get("%s/%s_%s.dsc" % (base, src, v)).decode("utf-8", "replace")
    name = dsc_debian_file(dsc)
    if name is None:
        return "native package (debian/ is inside the main tarball)", [], {}
    if name.endswith(".diff.gz"):
        return "old 1.0 format (.diff.gz), not scanned", [], {}
    hits = []
    ctx = {}
    with tempfile.TemporaryDirectory() as td:
        f = pathlib.Path(td) / name
        f.write_bytes(get("%s/%s" % (base, name)))
        subprocess.run(["tar", "-xf", str(f), "-C", td, "debian"],
                       check=True, capture_output=True)
        root = pathlib.Path(td)
        for p in sorted((root / "debian").rglob("*")):
            if not p.is_file() or p.name in ("changelog", "copyright"):
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            rel = str(p.relative_to(root))
            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                if pat.search(line):
                    hits.append((rel, i, line))
                    lo, hi = max(1, i - context), min(len(lines), i + context)
                    for j in range(lo, hi + 1):
                        ctx.setdefault(rel, {})[j] = lines[j - 1]
    return "ok", hits, ctx


def format_pkg(p, hits, ctx):
    """Hit lines as before, plus "@ctx<TAB>file<TAB>line<TAB>text" context lines."""
    out = ["== %s" % p]
    hit_set = {(r, l) for r, l, _ in hits}
    for rel, ln, line in hits:
        out.append("%s/%s:%d:%s" % (p, rel, ln, line))
    for rel, d in sorted(ctx.items()):
        for ln, text in sorted(d.items()):
            if (rel, ln) not in hit_set:
                out.append("@ctx\t%s\t%d\t%s" % (rel, ln, text))
    return "\n".join(out) + "\n\n"


def versions(pkgs, release, chunk=40):
    info = {}
    for i in range(0, len(pkgs), chunk):
        part = pkgs[i:i + chunk]
        res = subprocess.run(
            ["rmadison", "-u", "ubuntu", "-S", "-s", release] + part,
            capture_output=True, text=True, timeout=180)
        for line in res.stdout.splitlines():
            c = [x.strip() for x in line.split("|")]
            if len(c) >= 4 and "source" in c[3]:
                comp = c[2].split("/", 1)[1] if "/" in c[2] else "main"
                info[c[0]] = (c[1], comp)
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pkglist")
    ap.add_argument("--release", default="tenacious")
    ap.add_argument("--mirror", default="http://archive.ubuntu.com/ubuntu")
    ap.add_argument("--pattern", default=r"jquery\.js")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--context", type=int, default=4,
                    help="lines of context to save around each match")
    ap.add_argument("--out", default="scan-results.txt")
    ap.add_argument("--failures", default="scan-failures.txt")
    a = ap.parse_args()

    pkgs = sorted(set(pathlib.Path(a.pkglist).read_text().split()))
    pat = re.compile(a.pattern)
    info = versions(pkgs, a.release)

    failures = []

    def work(p):
        if p not in info:
            return p, "no source row from rmadison in %s" % a.release, [], {}
        ver, comp = info[p]
        try:
            status, hits, ctx = scan(p, ver, comp, a.mirror, pat, a.context)
        except Exception as e:  # network, tar, missing file
            return p, "error: %s" % e, [], {}
        return p, status, hits, ctx

    done = 0
    with open(a.out, "w") as out, cf.ThreadPoolExecutor(a.jobs) as ex:
        for p, status, hits, ctx in ex.map(work, pkgs):
            done += 1
            if status == "ok":
                out.write(format_pkg(p, hits, ctx))
            else:
                failures.append((p, status))
            if done % 50 == 0:
                print("%d/%d" % (done, len(pkgs)), file=sys.stderr)
    with open(a.failures, "w") as f:
        for p, why in failures:
            f.write("%s\t%s\n" % (p, why))
    print("scanned ok: %d, not scanned: %d (see %s)"
          % (len(pkgs) - len(failures), len(failures), a.failures))


if __name__ == "__main__":
    main()