"""Reject Japanese web pages that contain confirmed or suspected word salad."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
import unicodedata

from .snapshot import POPULATION, REVISION


VERSION = "word-salad-high-recall-v1"
MIN_WITNESS = 28
JAPANESE = "ぁ-ゖァ-ヶ一-龯々"
EXAM_SITES = (
    "certjuken.com", "certshiken.com", "it-passports.com",
    "japancert.com", "jpexam.com", "jpshiken.com", "jptestking.com",
    "mogiexam.com", "pass4test.jp", "shikenpass.com", "tech4exam.com",
    "topexam.jp", "xhs1991.com",
)
EXAM_LINK = re.compile(
    r"https?://(?:[\w-]+\.)*(?:" + "|".join(re.escape(site) for site in EXAM_SITES) + r")(?=[:/?#]|$)",
    re.IGNORECASE,
)
INLINE_LINK = re.compile(
    rf"(?<=[{JAPANESE}])https?://[a-z0-9./_%+~?=&-]+\.html?(?=[ぁ-ゖァ-ヶ一-龯])"
    r"(?!より|から|へ|です|を参照|にアクセス|をご覧|はこちら)",
    re.IGNORECASE,
)
EXAM_WORD = (
    r"試験(?:問題(?:集)?|学習|準備|対策|勉強|番号|関連|時間|感想|攻略|情報|概要|資料|解説|参考|対応|練習|内容|合格|復習)?"
    r"|資格(?:参考|練習|問題|取得|試験|勉強|受験|認証|準備|認定|講座|関連|専|難|模)"
    r"|復習|模擬体験|問題集|問題(?:と解答|数|例|無料)|トレーニング(?:資料|費用)?|前提条件|受験記"
)
CODE = r"[A-Za-z0-9][A-Za-z0-9_.-]{2,47}"
INLINE_EXAM = re.compile(rf"(?<=[{JAPANESE}])({CODE})(?:{EXAM_WORD})(?=[{JAPANESE}])")
EXAM_AD = re.compile(rf"\b({CODE})[ \t]?(?:{EXAM_WORD})")
NARRATIVE = re.compile(r"そう言|そうい|というのだ|と思った|と言った|彼女|彼は|ぼく|僕|俺|だった|ていた")
JOIN_DEFECT = re.compile(r"します(?:します)+|したのの(?=[ぁ-ゖ])|したことこと|(?:のでを|のをを)(?=[ぁ-ゖ])")
FRAGMENTS = re.compile(r"[。！？!?\r\n]+")


def normalize(text):
    return unicodedata.normalize("NFKC", text)


def exam_code(token):
    return any(c.isdigit() for c in token) and any(c.isalpha() for c in token)


def text_reason(text):
    """Return a page-level reason for a known pattern, including on unseen rows."""
    return _normalized_reason(normalize(text))


def _normalized_reason(text):
    if EXAM_LINK.search(text):
        return "exam_campaign_link"
    if INLINE_LINK.search(text):
        return "link_spliced_into_japanese"
    for match in INLINE_EXAM.finditer(text):
        if exam_code(match[1]):
            return "exam_code_spliced_into_japanese"
    if NARRATIVE.search(text) and any(exam_code(m[1]) for m in EXAM_AD.finditer(text)):
        return "exam_ad_mixed_with_narrative"
    if sum(1 for _ in JOIN_DEFECT.finditer(text)) >= 2:
        return "repeated_corrupted_joins"
    if text.count("。") >= 12 or text.count("\n") >= 12:
        from keyword_risk import assess

        signals = assess(FRAGMENTS.split(text))
        if signals and signals.warrants_review():
            return "repeated_keyword_slots"
    return None


class WordSaladFilter:
    """Combine a revision-bound reviewed row set, copied witnesses, and broad rules."""

    def __init__(self, review=None):
        self.rows = frozenset()
        self.witnesses = None
        self.review_sha256 = None
        if review is not None:
            from ahocorasick_rs import AhoCorasick

            raw = Path(review).read_bytes()
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("revision") != REVISION:
                raise ValueError("The word-salad review refers to a different FineWeb2 revision")
            rows = data.get("rows")
            witnesses = data.get("witnesses")
            if (not isinstance(rows, list) or not rows
                    or any(type(row) is not int or not 0 <= row < POPULATION for row in rows)
                    or len(set(rows)) != len(rows)):
                raise ValueError("The word-salad review must contain unique FineWeb2 row numbers")
            if (not isinstance(witnesses, list)
                    or any(not isinstance(w, str) or len(w.strip()) < MIN_WITNESS for w in witnesses)):
                raise ValueError("The word-salad review contains an invalid text witness")
            self.rows = frozenset(rows)
            anchors = sorted({normalize(w) for w in witnesses})
            if anchors:
                self.witnesses = AhoCorasick(anchors)
            self.review_sha256 = hashlib.sha256(raw).hexdigest()

    def reason(self, text, *, row=None):
        if row in self.rows:
            return "confirmed_fineweb2_row"
        normalized = normalize(text)
        if self.witnesses is not None and self.witnesses.find_matches_as_indexes(normalized):
            return "reviewed_corrupted_passage"
        return _normalized_reason(normalized)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="UTF-8 JSONL documents with text and optional fineweb2_row, or - for stdin")
    parser.add_argument("--review", type=Path, help="Revision-bound local review JSON")
    args = parser.parse_args()
    try:
        gate = WordSaladFilter(args.review)
        counts = Counter(kept=0)
        source = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
        try:
            for number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict) or not isinstance(record.get("text"), str):
                    raise ValueError(f"Missing text in document on line {number}")
                row = record.get("fineweb2_row")
                if "fineweb2_row" in record and (type(row) is not int or not 0 <= row < POPULATION):
                    raise ValueError(f"Invalid FineWeb2 row on line {number}")
                reason = gate.reason(record["text"], row=row)
                counts[reason or "kept"] += 1
                if reason is None:
                    sys.stdout.write(line if line.endswith("\n") else line + "\n")
        finally:
            if source is not sys.stdin:
                source.close()
    except (ValueError, OSError) as exc:
        parser.exit(1, f"{exc}\n")
    print(json.dumps({"version": VERSION, "review_sha256": gate.review_sha256, "counts": counts}), file=sys.stderr)


if __name__ == "__main__":
    main()
