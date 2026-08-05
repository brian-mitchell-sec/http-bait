"""Regenerate DETECTORS.md from app/signatures.py.

The detector timeline is load-bearing for anything published from this data: a
count is only comparable across a window in which the signature existed for the
whole window. Keeping the timeline in a hand-written document guarantees it goes
stale, so it is generated, and CI diffs it.

  python3 gen_detectors.py          # writes DETECTORS.md in place
  python3 gen_detectors.py --stdout # print instead, for diffing
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

# Writes DETECTORS.md in place. It used to print to stdout while the README and
# AGENTS.md both said it regenerated the file, so anyone adding a signature saw
# a wall of markdown, assumed they were done, and failed CI.
_LINES: list[str] = []


def emit(text: str = "") -> None:
    _LINES.append(text)

from signatures import CVE_SIGNATURES, TOOL_INVOCATION_SIGNATURES  # noqa: E402
from formatters import SERVED_TOKEN_LEN, MIN_SERVED_TOKEN_LEN  # noqa: E402

SCOPES = {
    "path": "path + query",
    "content-type": "Content-Type header",
    "headers": "every occurrence of every header",
    "body": "raw body and its percent-decoded form",
    "any": "path, query, body and Content-Type",
}

emit("""# Detectors

Generated from `app/signatures.py` by `gen_detectors.py`. Do not edit by hand.

A detection count means nothing without knowing when the detector existed. Two
signatures in this table shipped *after* traffic they match had already
arrived, so their live counts and their rescan counts differ by construction.
`analyze.py --rescan` re-applies the current set to retained records and prints
both, with the `since` value beside each row.

`since` values:

- a date: the day that signature's **current form** shipped
- `initial`: present when collection began
- `unknown`: the signature is known to have changed, but this repository is a
  single squashed commit and the date is not recoverable from it. Do not guess
  one. Reconcile against the development history before citing a timeline.
""")

emit("## CVE and exploit signatures\n")
emit("`kind` separates payload-bearing attempts from path probes. Reaching")
emit("/vendor/phpunit/.../eval-stdin.php with no body is a scanner checking")
emit("whether PHPUnit is installed; the exploit needs PHP in the request body.")
emit("Report the two counts separately.\n")
emit("| id | kind | scope | since |")
emit("|---|---|---|---|")
for cve_id, _pattern, where, since, kind in CVE_SIGNATURES:
    emit(f"| `{cve_id}` | **{kind}** | {SCOPES.get(where, where)} | {since} |")

emit("\n## Tool-invocation signatures\n")
emit("These parse an already-bounded request. Nothing is evaluated, imported,")
emit("executed, or fetched.\n")
emit("| tool |")
emit("|---|")
for tool, _pattern in TOOL_INVOCATION_SIGNATURES:
    emit(f"| `{tool}` |")

emit("\n## Honeytoken geometry\n")
emit("How many leading characters of the token id each kind serves as one")
emit("contiguous run. The reuse detector scans at the minimum, so a kind that")
emit(f"serves a shorter run widens the scan automatically. Current minimum: "
      f"**{MIN_SERVED_TOKEN_LEN}**.\n")
emit("| kind | served run |")
emit("|---|---|")
for kind, n in sorted(SERVED_TOKEN_LEN.items()):
    flag = "  <- sets the scan width" if n == MIN_SERVED_TOKEN_LEN else ""
    emit(f"| `{kind}` | {n}{flag} |")

emit("""
### Why this table exists

The reuse detector originally matched only the full 16-character id. Two kinds
serve 12. A replayed database password therefore could not fire the detector at
all, across roughly 14% of everything ever issued, and the resulting "no second
replay" reads as a finding rather than as a blind spot. Nothing in the code
enforced the assumption, so nothing caught it.

`app/test_regressions.py::test_served_token_len_declarations_are_accurate`
now checks every number above against what the formatter actually emits.
""")


def main() -> int:
    text = "\n".join(_LINES) + "\n"
    if "--stdout" in sys.argv:
        sys.stdout.write(text)
        return 0
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DETECTORS.md")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(text)
    sys.stderr.write(f"wrote {os.path.basename(target)} ({len(_LINES)} lines)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
