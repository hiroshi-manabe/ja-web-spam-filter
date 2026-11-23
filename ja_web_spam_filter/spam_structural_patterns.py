"""Additional source evidence for repeated offers and damaged web passages."""

from collections import defaultdict
import re
from urllib.parse import unquote, urlsplit

from .regional_rewrite import regional_copy_overlays
from .word_salad_filter import normalize


VERSION = "spam-structural-v5"
TABLE_FIELD = re.compile(r"(?m)^\s*\|([^|\r\n]{1,96})\|\|([^|\r\n]{1,240})\|")
BOOK_TITLE = re.compile(r"(?:作品|書籍|商品)?タイトル|書籍名")
BOOK_PRICE = re.compile(r"\s*[0-9]{2,6}(?:円)?\s*")
BOOK_FIELD = re.compile(r"電子(?:貸本|書籍)|無料(?:タダ)?読み|試し読み|レンタル")
PROMOTIONAL_ACTION = re.compile(r"公式|サンプル|無料|試し読み|会員登録|クーポン|キャンペーン")
CLINIC_BRANCH = re.compile(r"(?<=クリニック)[一-龯々ぁ-ゖァ-ヶー]{2,14}院(?=の|で|は|に|へ)")
COUNTY_PREFIX = re.compile(r"(?:(?![都道府県市区町村郡])[一-龯々ヶケ]){2,10}郡$")
REVIEW_CUE = re.compile(r"口コミ|悪い評判|良い評判|レビュー")
LOCAL_PROMO = re.compile(r"加盟店|全国|スピード融資|即日融資|WEB申込|自動契約機|公式サイト")
LOCAL_SERVICE = re.compile(r"借り入れ|返済|お金を借り|宅配|配送|申込み|購入|クーポン")
DATE = re.compile(r"(?<![0-9])(?:19|20)[0-9]{2}[/-](?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12][0-9]|3[01])(?![0-9])")
SCRAPED_CUE = re.compile(r"FAQ|更新日時|回答数|閲覧数|サポート|続きを(?:見る|読む)|検索結果|ダウンロード")
KATAKANA = re.compile(r"[ァ-ヶー]")
BOUNDARY = re.compile(r"[。！？!?\r\n]")

PROFILE_INTRO = re.compile(r"無料登録|登録ボタン")
PROFILE_PROMOTION = re.compile(r"出会い系|プロフィール設定|マッチングアプリ")
PROFILE_VOICE = re.compile(r"私|自分|お互い|連絡|募集中|お願いします|よろしく|相手")
MUNICIPAL_SUFFIX = re.compile(r"[一-龯々ヶケぁ-ゖァ-ヶー]{2,20}[市区町村]")
NUMERIC_PLACEHOLDER = re.compile(
    r"(?<![A-Za-z0-9Ａ-Ｚａ-ｚ０-９])[XＸ][NＮ][UＵ][MＭ][XＸ](?=\s*(?:つ|[年月日時分秒人個本発回倍]|mm|cm|kg|[％%]))"
)
ORPHANED_PROMPT = re.compile(r"(を[ぁ-ゖ一-龯々]{1,12}?には)(?=[がのではにをもやとから])")
REPAIR_COPY = re.compile(r"修理.{0,15}ドレスアップ.{0,80}カラーチェンジ")
LISTING_WORD = re.compile(r"美品|新品|様専用|未使用|限定品")
NON_WHEEL = re.compile(r"フーディ|仮面ライダー|譜面台|ワンピース|ダウンコート")
INLINE_LATIN_QUERY = re.compile(
    r"(?<=[\s、。])([ァ-ヶー]{2,12}) +([A-Z][a-z]{2,}(?: +[A-Za-z][A-Za-z0-9-]{1,}){1,7})(?=[、。！？\n])"
)



def book_offer(text):
    """Return a field signature and two varying values for a repeated ebook offer."""
    text = normalize(text)
    if not 160 <= len(text) <= 2400 or text.count("||") < 5:
        return None
    fields = [(name.strip(), value.strip()) for name, value in TABLE_FIELD.findall(text)]
    if len(fields) < 5:
        return None
    title = next((value for name, value in fields if BOOK_TITLE.fullmatch(name)), "")
    price = next((value for name, value in fields if name.endswith("価格") and BOOK_PRICE.fullmatch(value)), "")
    if len(title) < 3 or not price:
        return None
    if text.count(title) < 4 or not BOOK_FIELD.search(text) or not PROMOTIONAL_ACTION.search(text):
        return None
    schema = tuple(name.replace(title, "〈題〉") for name, _ in fields
                   if not name.endswith("はこちら"))
    if len(schema) < 5 or not any(BOOK_FIELD.search(name) for name in schema):
        return None
    return schema, title, int(price.removesuffix("円"))


def book_campaign_rows(observations):
    """Identify template peers with different titles and prices on different sites."""
    from register_audit import name_of_site

    groups = defaultdict(list)
    for row, host, offer in observations:
        schema, title, price = offer
        groups[tuple(schema)].append((row, name_of_site(host), title, price))
    matched = set()
    for group in groups.values():
        if len({host for _, host, _, _ in group}) < 3:
            continue
        if len({title for _, _, title, _ in group}) < 3 or len({price for _, _, _, price in group}) < 2:
            continue
        for row, site, own_title, _ in group:
            peers = {(host, title) for _, host, title, _ in group if host != site and title != own_title}
            if len({host for host, _ in peers}) >= 2 and len({title for _, title in peers}) >= 2:
                matched.add(row)
    return matched


def exact_locality_variation(a, b):
    from template_index import _different, _signature_spans, template_signature

    def signature(text):
        text = text.strip()
        for start, end in reversed(_signature_spans(text)):
            if text[end - 1] not in "町村":
                continue
            county = COUNTY_PREFIX.search(text, max(0, start - 11), start)
            if county:
                text = text[:county.start()] + text[start:]
        return template_signature(text)

    pair = [signature(text) for text in (a, b)]
    if any(p is None for p in pair):
        return False
    (shape_a, value_a), (shape_b, value_b) = pair
    return shape_a == shape_b and value_a != value_b and _different(value_a, value_b)


def paired_variation_spans(match):
    """Return matching witness spans supported by location or branch substitution."""
    locality = []
    clinic = []
    strong_locality = False
    for witness in match["witnesses"]:
        _, _, a, b, _ = witness
        a, b = normalize(a).strip(), normalize(b).strip()
        if min(len(a), len(b)) >= 40 and all(LOCAL_SERVICE.search(t) for t in (a, b)):
            if exact_locality_variation(a, b):
                locality.append(witness)
                if all(LOCAL_PROMO.search(t) for t in (a, b)) and min(len(a), len(b)) >= 60:
                    strong_locality = True
        branches = [CLINIC_BRANCH.search(t) for t in (a, b)]
        if (all(branches) and branches[0][0] != branches[1][0]
                and all(REVIEW_CUE.search(t) for t in (a, b))
                and CLINIC_BRANCH.sub("〈院〉", a) == CLINIC_BRANCH.sub("〈院〉", b)):
            clinic.append(witness)
    if strong_locality and (len(locality) >= 2 or any(min(len(w[2]), len(w[3])) >= 70 and len(w[4]) >= 3
                                                    for w in locality)):
        yield "locality_in_repeated_pitch", locality
    if len(clinic) >= 3:
        yield "clinic_branch_in_repeated_review_copy", clinic


def stitched_search_snippets(text):
    """Flag long lines with several out-of-order snippet dates and search metadata."""
    text = normalize(text)
    snippet_lines = []
    for line in text.splitlines():
        if len(line) < 240:
            continue
        dates = [tuple(map(int, re.split(r"[-/]", m[0]))) for m in DATE.finditer(line)
                 if m.start() and line[m.start() - 1].isspace()]
        if len(set(dates)) >= 3 and any(a > b for a, b in zip(dates, dates[1:])):
            snippet_lines.append(line)
    return len(snippet_lines) >= 2 and len(set(SCRAPED_CUE.findall(" ".join(snippet_lines)))) >= 2


def inserted_heading_spans(text):
    """Locate a copied early heading that interrupts a katakana word farther down."""
    lines = text.splitlines()[:4]
    for heading in dict.fromkeys(line.strip() for line in lines):
        if not 10 <= len(heading) <= 96 or " " not in heading and "：" not in heading and ":" not in heading:
            continue
        for match in re.finditer(re.escape(heading), text):
            start, end = match.span()
            if not (start and end < len(text) and KATAKANA.fullmatch(text[start - 1])
                    and KATAKANA.fullmatch(text[end])):
                continue
            # Match the sentence containing the insertion so offsets retain source fidelity.
            left = max((m.end() for m in BOUNDARY.finditer(text, 0, start)), default=0)
            right = BOUNDARY.search(text, end)
            yield left, right.end() if right else len(text)


def numeric_placeholder_spans(text):
    """Find the original fragments with an unexpanded number in a quantity."""
    for mention in NUMERIC_PLACEHOLDER.finditer(text):
        start, end = mention.span()
        left = max((m.end() for m in BOUNDARY.finditer(text, 0, start)), default=0)
        right = BOUNDARY.search(text, end)
        yield left, right.end() if right else len(text)


def repeated_orphaned_prompt(text):
    """Recognize a full query fragment repeatedly used as a grammatical argument."""
    text = normalize(text)
    suffixes = defaultdict(list)
    for m in ORPHANED_PROMPT.finditer(text):
        suffixes[m[1]].append(text[m.end()])
    return any(len(values) >= 6 and len(set(values)) >= 3 for values in suffixes.values())


def repair_catalog_spans(match, records):
    """Locate mechanically changed repair copy mixed with unrelated product listings."""
    ids = [match[side]["row"] for side in ("a", "b")]
    if not all(row in records for row in ids):
        return
    texts = [normalize(records[row]["text"]) for row in ids]
    if not all(text.count("ホイール") >= 2 and len(set(LISTING_WORD.findall(text))) >= 2 for text in texts):
        return
    witnesses = match["witnesses"]
    if len(witnesses) < 2 or not any(
            all(REPAIR_COPY.search(normalize(w[i])) for i in (2, 3)) for w in witnesses):
        return
    for witness in witnesses:
        if any(NON_WHEEL.search(normalize(witness[i])) for i in (2, 3)):
            yield witness


def structural_overlays(records, pairs, reference_offers=()):
    """Return evidence-labeled spans using one frozen batch and optional book references."""
    results = defaultdict(lambda: defaultdict(set))
    observations = list(reference_offers)
    for row, record in records.items():
        text = record["text"]
        if stitched_search_snippets(text):
            results[row]["stitched_search_snippets"].add((0, len(text)))
        if repeated_orphaned_prompt(text):
            results[row]["repeated_malformed_query_slot"].add((0, len(text)))
        damaged_quantities = list(numeric_placeholder_spans(text))
        if damaged_quantities:
            results[row]["unexpanded_numeric_placeholder"].update(damaged_quantities)
        headings = list(inserted_heading_spans(text))
        if headings:
            results[row]["heading_inserted_into_katakana"].update(headings)
        if offer := book_offer(text):
            try:
                host = urlsplit(record["url"]).hostname
            except ValueError:
                host = None
            if host:
                observations.append((row, host, offer))
    for row in book_campaign_rows(observations) & records.keys():
        results[row]["book_title_price_template"].add((0, len(records[row]["text"])))
    for match in pairs:
        batches = list(paired_variation_spans(match))
        if repair := list(repair_catalog_spans(match, records)):
            batches.append(("repair_ad_with_unrelated_products", repair))
        for reason, witnesses in batches:
            for i, side in enumerate(("a", "b")):
                row = match[side]["row"]
                if row not in records:
                    continue
                text = records[row]["text"]
                for witness in witnesses:
                    start, surface = witness[i], witness[2 + i]
                    if start >= 0 and text.startswith(surface, start):
                        results[row][reason].add((start, start + len(surface)))
    for row, span in regional_profile_intro_overlays(records).items():
        results[row]["regional_profile_landing_intro"].add(span)
    for row, spans in regional_copy_overlays(records).items():
        results[row]["ordered_regional_rewrite"].update(spans)
    return results


def regional_profile_offer(text, url, *, relaxed_profiles=False):
    """Find a municipal landing intro followed by independent first-person entries."""
    try:
        page = urlsplit(url)
    except ValueError:
        return None
    path = normalize(unquote(page.path.rstrip("/")))
    place = path.rsplit("/", 1)[-1]
    if not page.hostname or not MUNICIPAL_SUFFIX.fullmatch(place):
        return None
    from locality_templates import _gazetteer

    if place not in _gazetteer()[0]:
        return None
    raw_lines = text.splitlines(keepends=True)
    lines = [normalize(line).strip() for line in raw_lines]
    if not 7 <= len(lines) <= 80:
        return None
    intro = "".join(lines[:2])
    if (not intro.startswith(place) or intro.count(place) < 2
            or not PROFILE_INTRO.search(intro) or not PROFILE_PROMOTION.search(intro)):
        return None
    profiles = [line for line in lines[2:] if 18 <= len(line) <= 180]
    if sum(bool(PROFILE_VOICE.search(line)) for line in profiles) < 3 and (
            not relaxed_profiles or len(profiles) < 6):
        return None
    scope = (page.hostname.removeprefix("www."), path.rsplit("/", 1)[0].rsplit("/", 1)[0],
             intro.replace(place, "〈地名〉"))
    return scope, place, path, sum(map(len, raw_lines[:2]))


def regional_profile_intro_overlays(records, *, relaxed_profiles=False):
    """Mark the copied introduction when its municipality varies across real pages."""
    groups = defaultdict(list)
    for row, record in records.items():
        if offer := regional_profile_offer(record["text"], record["url"], relaxed_profiles=relaxed_profiles):
            scope, place, path, end = offer
            groups[scope].append((row, place, path, end))
    return {row: (0, end)
            for pages in groups.values() if len({place for _, place, _, _ in pages}) >= 3
            and len({path for _, _, path, _ in pages}) >= 3
            for row, _, _, end in pages}


def inline_foreign_query_leads(text):
    """Find repeated brand strings followed by different in-line English query phrases."""
    found = defaultdict(set)
    for match in INLINE_LATIN_QUERY.finditer(normalize(text)):
        found[match[1]].add(match[2])
    return {brand: sorted(queries) for brand, queries in found.items() if len(queries) >= 4}
