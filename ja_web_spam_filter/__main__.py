import argparse
import json
import sys
from contextlib import nullcontext

from . import SpamFilter


def main():
    parser = argparse.ArgumentParser(description="Classify Japanese web documents from UTF-8 JSONL.")
    parser.add_argument("input", nargs="?", default="-", help="JSONL file or - for stdin")
    args = parser.parse_args()
    classifier = SpamFilter()
    source = nullcontext(sys.stdin) if args.input == "-" else open(args.input, encoding="utf-8")
    with source as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or not isinstance(record.get("text"), str):
                    raise ValueError("expected an object with string text")
                url = record.get("url", "")
                if not isinstance(url, str):
                    raise ValueError("expected a string url")
            except ValueError as exc:
                parser.exit(2, f"Line {number}: {exc}\n")
            result = classifier.classify(url=url, text=record["text"])
            if "id" in record:
                result["id"] = record["id"]
            print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
