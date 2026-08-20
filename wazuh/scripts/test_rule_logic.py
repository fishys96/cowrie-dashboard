#!/usr/bin/env python3
"""Offline sanity test for the Cowrie rule set. Runs anywhere -- no Wazuh needed.

verify_rules.sh is the authoritative test, but it needs a running manager. This
script catches the most common and most silent class of mistake (a field regex
that does not match what you think it does, or two sibling rules in the wrong
order) on a laptop, before anything is deployed.

It parses manager/rules/local_rules.xml, rebuilds the rule tree the way
wazuh-analysisd does -- match the <decoded_as> root, then walk <if_sid> children
in file order and take the FIRST sibling whose <field> patterns all match -- and
asserts every fixture resolves to its expected rule id and level.

    python3 test_rule_logic.py

CAVEAT: Python's `re` is not PCRE2. For the constructs used here (alternation,
\\b, (?i), \\s, anchors) the two agree, but this is a smoke test, not a
substitute for wazuh-logtest. Correlation rules (<if_matched_sid>, i.e. the
brute-force rule 100210) are stateful and are only tested by verify_rules.sh.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = HERE.parent / "manager" / "rules" / "local_rules.xml"
FIXTURES = HERE / "fixtures" / "cowrie_fixtures.jsonl"


class Rule:
    def __init__(self, el: ET.Element) -> None:
        self.sid = int(el.get("id"))
        self.level = int(el.get("level"))
        self.if_sid = el.findtext("if_sid")
        self.if_matched_sid = el.findtext("if_matched_sid")
        self.decoded_as = el.findtext("decoded_as")
        self.fields = [(f.get("name"), f.text or "") for f in el.findall("field")]
        self.description = el.findtext("description", "")

    def matches(self, event: dict) -> bool:
        for name, pattern in self.fields:
            if not re.search(pattern, str(event.get(name, ""))):
                return False
        return True


def load_rules() -> list[Rule]:
    rules = [Rule(el) for el in ET.parse(RULES).getroot().findall("rule")]
    # Correlation rules are stateful; excluded from this static evaluation.
    return [r for r in rules if r.if_matched_sid is None]


def resolve(event: dict, rules: list[Rule]) -> Rule | None:
    """Walk the rule tree the way analysisd does: first matching sibling wins."""
    current = next((r for r in rules if r.decoded_as == "json" and r.matches(event)), None)
    if current is None:
        return None
    while True:
        child = next(
            (r for r in rules if r.if_sid == str(current.sid) and r.matches(event)), None
        )
        if child is None:
            return current
        current = child


def main() -> int:
    rules = load_rules()
    print(f"loaded {len(rules)} non-correlation rules from {RULES.name}\n")

    failures = 0
    for line in FIXTURES.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fx = json.loads(line)
        got = resolve(fx["log"], rules)
        want_sid, want_level = fx["expect_sid"], fx["expect_level"]

        if got and got.sid == want_sid and got.level == want_level:
            print(f"  [pass] {fx['name']:<45} -> {got.sid} (level {got.level})")
        else:
            got_desc = f"{got.sid} (level {got.level})" if got else "no match"
            print(f"  [FAIL] {fx['name']:<45} -> {got_desc}, expected {want_sid} (level {want_level})")
            failures += 1

    # Guard the invariant that makes command classification correct: the sibling
    # rules under 100204 must be ordered most-severe-first, or a command that
    # trips two categories would alert at the lower severity.
    cmd_children = [r for r in rules if r.if_sid == "100204"]
    levels = [r.level for r in cmd_children]
    if levels == sorted(levels, reverse=True):
        print(f"\n  [pass] command rules ordered most-severe-first: {levels}")
    else:
        print(f"\n  [FAIL] command rules are out of order: {levels} (must descend)")
        failures += 1

    print()
    if failures:
        print(f"{failures} FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
