import unittest

from ja_web_spam_filter import SpamFilter


class FilterTest(unittest.TestCase):
    def test_ordinary_text_passes(self):
        result = SpamFilter().classify(url="https://example.org/", text="夕方に図書館へ寄りました。")
        self.assertFalse(result["reject"])

    def test_url_scope(self):
        result = SpamFilter().classify(url="https://sbic.sub.jp/example/", text="例文です。")
        self.assertTrue(result["reject"])
        self.assertEqual(result["stage"], "url")

    def test_text_scope(self):
        result = SpamFilter().classify(
            url="https://example.hatenablog.com/entry/2017/03/01/123456",
            text="ガリバーで査定を依頼しました。",
        )
        self.assertTrue(result["reject"])
        self.assertIn("dated-hatena-post-with-car-appraisal-and-dealer-name", result["reasons"])
