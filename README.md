# Japanese Web Spam Filter

A rule-based document filter extracted from the Japanese reading-corpus project. It accepts UTF-8 JSONL with a `text` field and an optional `url` and `id`. The output gives one verdict per input record, with rule identifiers for rejections.

```sh
python3 -m ja_web_spam_filter <<'JSONL'
{"id":"example","url":"https://example.org/diary","text":"夕方に図書館へ寄りました。借りていた本を返してから、近所を散歩しました。"}
JSONL
```

Python 3.11 or later is required. The checkout runs without third-party Python packages or network calls. You can also install it locally with `python3 -m pip install .`.

The filter runs the reviewed URL registry, standalone word-salad rules, and document-level text specialists. The URL registry was developed on a pinned Japanese FineWeb2 snapshot. Some entries deliberately trade source coverage for less spam. Use a held-out sample from your own corpus to evaluate that tradeoff.

The original pipeline also uses classifiers, archived cross-document witnesses, and sentence selection. Those stages account for additional rejections in the original audits. This package includes rule code and URL scopes. Corpus text, models, review records, and the endorsement fingerprint bank stay with the local corpus project.

The code is released under the [MIT License](LICENSE).

Run the smoke tests with `python3 -m unittest discover -s tests`.
