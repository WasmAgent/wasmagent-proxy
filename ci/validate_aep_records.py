#!/usr/bin/env python3
"""Validate emitted AEP record samples against the canonical wasmagent-protocol schema.

The schema is fetched (pinned) by ci/fetch_aep_schema.sh; this script never
edits or inlines it. Requires: python3 -m pip install jsonschema
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit("jsonschema is required: python3 -m pip install jsonschema")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, help="path to aep-record.schema.json")
    parser.add_argument("--samples-dir", required=True, help="directory of *.json sample records")
    args = parser.parse_args()

    schema = json.loads(Path(args.schema).read_text())
    validator = Draft202012Validator(schema)

    samples = sorted(Path(args.samples_dir).glob("*.json"))
    if not samples:
        sys.exit(f"no sample records found in {args.samples_dir}")

    failures = 0
    for sample in samples:
        record = json.loads(sample.read_text())
        errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))
        if errors:
            failures += 1
            print(f"FAIL {sample.name}")
            for err in errors:
                loc = "$." + ".".join(str(p) for p in err.absolute_path) if err.absolute_path else "$"
                print(f"  {loc}: {err.message}")
        else:
            print(f"OK   {sample.name}")

    if failures:
        sys.exit(f"{failures}/{len(samples)} sample record(s) failed schema validation")
    print(f"all {len(samples)} sample record(s) conform to the canonical aep-record schema")


if __name__ == "__main__":
    main()
