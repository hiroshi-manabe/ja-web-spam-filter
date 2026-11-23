"""Flag possible loss of neighboring-venue labels for extraction review."""

import re
from collections import Counter


DETAIL_PATH = re.compile(r"/(?:places?|spots?|shops?|restaurants?|stores?|venues?|facilit(?:y|ies)|attractions?)/[0-9]+(?:\.html?)?/?$", re.I)
# A venue noun used as the predicate of an introduction, not just a mention of a nearby shop.
VENUE = (r"(?:[一-龯々ァ-ヶー]{1,18}(?:店|屋|館|園|場|センター)|お店|商店|施設|公園|神社|寺院|"
         r"レストラン|カフェ|バー|バル|サロン|ホテル|ショップ|スタジオ|アトリエ|"
         r"ミュージアム|ギャラリー|テーマパーク|ダイニング|割烹|食堂|居酒屋|BAR|店)")
INTRODUCTION = re.compile(rf"({VENUE})(?:さん)?(?:です|である|となっています)?[。!?]|"
                          rf"({VENUE})(?:で、|として[、。]|ながら[、。])")
LIST_CONTEXT = re.compile(
    r"関連スポット|店舗一覧|周辺(?:情報|施設|スポット|のお店)|近くのお店|近くにあるプレース|"
    r"(?:館内|園内|敷地内|ホテル内|ミュージアム内|テーマパーク内)(?:の|にある|には|限定)|"
    r"(?:ホテル|テーマパーク)[^。\n]{0,18}(?:\d+階|の宿泊者|内限定)|併設|複合施設|ショッピングモール|商業施設|テナント|"
    r"フードコート|駅ビル|商店街(?:です|にあるお店を)|施設内には|敷地内には|"
    r"口コミ|クチコミ|レビュー|訪問記|店舗を紹介|スポットを紹介|各店舗|"
    r"(?m:^[|【#■◆●・▼]|^(?:まずは|次に|続いて|最後に|一軒目|二軒目|三軒目))"
)
ANCHOR = re.compile(r"[一-龯々]{2,}|[ァ-ヶー]{3,}")
GENERIC = {"お店", "店", "施設", "名店", "本格店", "人気店", "専門店", "料理店", "飲食店", "出店", "日本初出店"}


def mixed_venue_descriptions(text, path):
    """Identify unlabelled blurbs on detail URLs as an advisory extraction finding."""
    if not DETAIL_PATH.search(path) or not 140 <= len(text) <= 4000:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not 4 <= len(lines) <= 20 or LIST_CONTEXT.search(text):
        return False
    if any(not 22 <= len(line) <= 210 or "。" not in line for line in lines):
        return False

    descriptions = []
    labels = set()
    for line in lines:
        # Qualify each card using its own opening sentence. A paragraph about one
        # venue can legitimately recommend other shops later in that paragraph.
        lead = line[:line.index("。") + 1]
        match = INTRODUCTION.search(lead)
        if match:
            descriptions.append(lead)
            label = match[1] or match[2]
            if label not in GENERIC:
                labels.add(label)
    if len(descriptions) < 3 or len(descriptions) * 2 < len(lines) or len(labels) < 2:
        return False
    shared_topics = Counter()
    for line in lines:
        shared_topics.update({word[i:i + 4] for word in ANCHOR.findall(line)
                              for i in range(len(word) - 3)})
    if max(shared_topics.values(), default=0) * 3 >= len(lines) * 2:
        return False
    # Consistent shared content in multiple leads is evidence for sections or
    # reviews of one business. Require multiple independent introductions.
    lead_words = [set(ANCHOR.findall(s)) - GENERIC for s in descriptions]
    independent = sum(all(len(words & other) < 2 for j, other in enumerate(lead_words) if i != j)
                      for i, words in enumerate(lead_words))
    return independent >= 3
