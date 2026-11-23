"""Document-level rules for Japanese web spam."""
from .spam_publisher_blocklist import PublisherBlocklist
from .spam_specialists import EXTRACTION_ONLY, blocking_spans, page_findings
from .word_salad_filter import text_reason


class SpamFilter:
    """Reuse a loaded URL registry across documents."""

    def __init__(self):
        self.blocklist = PublisherBlocklist()

    def classify(self, *, url: str, text: str) -> dict:
        if scope := self.blocklist.match(url):
            return {"reject": True, "stage": "url", "reasons": [scope]}
        if reason := text_reason(text):
            return {"reject": True, "stage": "word_salad", "reasons": [reason]}
        findings = blocking_spans(page_findings(text, url), len(text))
        reasons = sorted(findings.keys() - EXTRACTION_ONLY)
        return {"reject": bool(reasons), "stage": "text_rules" if reasons else None, "reasons": reasons}
