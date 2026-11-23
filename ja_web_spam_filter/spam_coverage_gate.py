"""Experimental corpus gate for corroborated template reuse and malformed prose."""

from difflib import SequenceMatcher
from collections import Counter, defaultdict
import re
from statistics import fmean, median
from urllib.parse import unquote, urlsplit

from .word_salad_filter import normalize, text_reason


VERSION = "spam-coverage-v6"
BOUNDARY = re.compile(r"[。!?！？\r\n]+")
BARE_PARTICLE = re.compile(r"^(?:[はがをにでのも]|から|より)(?=[一-龯ぁ-ゖァ-ヶ]{2})")
BROKEN_MONTH = re.compile(r"(?<!\d)(?:19|20)\d{2}[ \t]*年[ \t]*(?:1[3-9]|[2-9]\d)[ \t]*月")
BROKEN_JOIN = re.compile(r"しますします|したのの(?=[ぁ-ゖ])|のでを(?=[ぁ-ゖ])|のをを(?=[ぁ-ゖ])")
REPLACEMENT = re.compile(r"�{2,}")
PROMOTION = re.compile(r"お(?:すすめ|得|支払|試し|申込|問合)|オススメ|ご(?:案内|紹介|登録|購入)|"
                       r"最安|激安|無料|口コミ|見積|送料無料|キャッシュバック|サービス|ランキング|限定")
ACTION = re.compile(r"購入|登録|検索|ダウンロード|インストール|試し読み|視聴|お申し込|比較|査定|"
                    r"情報を.*(?:確保|入手)|を楽しむ|を見つけ|借入|借りる|相談|を探す|予約|探す")
CATALOG = re.compile(r"メーカー希望価格|販売価格|商品番号|製品番号|商品コード|在庫状況|商品名")
INLINE_PRODUCT = re.compile(r"【[^】]{5,90}】")
MIXED_PRODUCT_CODE = re.compile(
    r"[ぁ-ゖァ-ヶ][A-Z]+[-_]?[0-9][A-Z0-9_-]{1,18}[ \t]*"
    r"(?:[一-龯ァ-ヶー]{2,}[ \t]+){1,4}[一-龯ァ-ヶー]{2,}"
)
COMPOUND_QUERY = re.compile(r"[一-龯ァ-ヶ]{2,}[ \t]+[一-龯ァ-ヶ]{2,}[ \t]+[一-龯ァ-ヶ]{2,}")
QUERY_SEO = re.compile(r"の最新情報|の情報を検索|が必ず見つかり|に関連した情報|関係する最新情報")
SPLIT_KATAKANA = re.compile(r"[ァ-ヶー]{2,}[一-龯]{2,4}[ァ-ヶー](?=[のはをもにでがァ-ヶ])")
SCRAPED_PORTAL = re.compile(r"このポストから無料でダウンロードしてインストール|"
                           r"pdf版の歌詞が必要な場合.{1,90}mp3を無料でダウンロード", re.I)
REPEATED_PITCH = re.compile(r"(?:を購入する際には豊富な決済方法|は月額制ではなくて、購入する|"
                            r"あらゆる環境で.{2,90}を楽しむことができます|獲得Tポイント\|{2})")
PRICE_KEYS = re.compile(r"\d[0-9,.]*円|\d\s*(?:mm|cm|個入り|メートル|フィート)(?![A-Za-z])")
COPY_SALES = re.compile(r"スーパー[ \t]*コピー|コピー時計|N級品|レプリカ.{0,14}(?:販売|価格|通販)", re.IGNORECASE)
LANGUAGE_DEBRIS = re.compile(r"\bX{3,}X*\b|[一-龯ぁ-ゖ][ \t]*,[ \t]*[一-龯ぁ-ゖ]")
DEFECTIVE_SLOT = re.compile(r"(?:には|ので|ために)(?:の|を)[ぁ-ゖ]{1,3}(?=[一-龯])|"
                           r"(?:商品|製品)に[ァ-ヶ]{3,}[一-龯]{2,4}を[一-龯ァ-ヶ]{2,}(?:は|が)")
REGION_SEGMENT = re.compile(r"(?:北海道|東京都|(?:京都|大阪)府|[一-龯]{2,4}県)")
CITY_SEGMENT = re.compile(r"[一-龯々ヶケぁ-ゖァ-ヶ]{1,18}[市区町村]")
COMMERCIAL_BODY = re.compile(r"契約|料金|お得|無料|費用|キャンペーン|価格|プラン|コース|申込|評判|比較|相談")
KANA = re.compile(r"[ぁ-ゖ]")
CONTENT = re.compile(r"[一-龯]{2,}|[ァ-ヶー]{3,}")
REPEATED_EBOOK_DEFINITION = re.compile(
    r"電子(?:書籍|コミック|漫画).{2,60}を(?:買う|購入する)(?:という|とい[うっ]).{0,15}"
    r"(?:ネット|インターネット|ウェブ).{0,40}(?:情報|データ).{0,15}(?:取得|ゲット|入手)"
)
TESTIMONIAL = re.compile(r"(?m)(?:^|[。\n])\s*[（(]([一-龯々ぁ-ゖァ-ヶ]{3,12})様[）)]\s*([^\n。]{40,200})。")
TITLE_PITCH = re.compile(r"電子(?:書籍|貸本).{0,55}(?:レンタル|購入).{0,36}(?:サンプル|試し読み)")
CAMPAIGN_COPY = re.compile(r"会員登録|出会い|好み.{0,15}見つかります|楽しい時間を過ごす|探したけど欲しい")
AFFILIATE_BODY = re.compile(r"試し読み|公式サイト|今すぐ|キャンペーン|特典|無料登録|ランキング|人気|発行")


def mismatched_locality(text, url):
    """A commercial page served under a locality route without that locality in its prose."""
    try:
        segments = [s for s in unquote(urlsplit(url).path).strip("/").split("/") if s]
    except ValueError:
        return False
    for region, city in zip(segments, segments[1:]):
        if not REGION_SEGMENT.fullmatch(region) or not CITY_SEGMENT.fullmatch(city):
            continue
        if city in text or city[:-1] in text or region in text:
            return False
        from template_index import _place_hierarchy

        labels, _, _ = _place_hierarchy()
        return (region,city) in labels and len(set(COMMERCIAL_BODY.findall(text))) >= 4
    return False


def document_reason(text, url=""):
    """Return a conservative description of page-level evidence, or None."""
    text = normalize(text)
    baseline = text_reason(text)
    if baseline:
        return baseline
    attributions = defaultdict(set)
    for author, quote in TESTIMONIAL.findall(text):
        attributions["".join(quote.split())].add(author)
    if any(len(authors) >= 2 for authors in attributions.values()):
        return "identical_testimonial_with_distinct_names"
    if BROKEN_MONTH.search(text):
        return "damaged_date"
    if len(REPLACEMENT.findall(text)) >= 3:
        return "garbled_runs"
    paragraphs = [p.strip() for p in BOUNDARY.split(text) if len(p.strip()) >= 16]
    if sum(bool(BARE_PARTICLE.match(p)) for p in paragraphs) >= max(5, len(paragraphs)//5):
        return "empty_grammar_slots"
    broken = len(BROKEN_JOIN.findall(text))
    if broken and len(QUERY_SEO.findall(text)) >= 2:
        return "broken_promotional_prose"
    if SCRAPED_PORTAL.search(text):
        return "download_template"
    if len(REPEATED_PITCH.findall(text)) >= 2:
        return "repeated_storefront_pitch"
    if REPEATED_EBOOK_DEFINITION.search(text) and len(PROMOTION.findall(text)) >= 3:
        return "book_title_in_generic_definition"
    if url and text.count("。") >= 7 and mismatched_locality(text,url):
        return "commercial_copy_on_unreferenced_locality_route"
    if len(COPY_SALES.findall(text)) >= 3 and len(PROMOTION.findall(text)) >= 3:
        return "repeated_replica_pitch"
    if broken and (sum(bool(BARE_PARTICLE.match(p)) for p in paragraphs) >= 4
                   or len(DEFECTIVE_SLOT.findall(text)) >= 2):
        return "empty_grammar_slots"
    if len(LANGUAGE_DEBRIS.findall(text)) >= 8 and len(PROMOTION.findall(text)) >= 3:
        return "mixed_punctuation_and_promotion"
    if CATALOG.search(text):
        if (len(MIXED_PRODUCT_CODE.findall(text)) >= 2 or len(SPLIT_KATAKANA.findall(text)) >= 5
                or len(INLINE_PRODUCT.findall(text)) >= 2
                and any(p.count("【") >= 1 and len(p) > 125 and len(PRICE_KEYS.findall(p)) >= 1
                        for p in paragraphs)):
            return "catalog_inserted_into_prose"
        if any(len(PRICE_KEYS.findall(p)) >= 5 and len(p) > 120 for p in paragraphs):
            return "interleaved_catalog_fields"
        if broken and len(PRICE_KEYS.findall(text)) >= 4:
            return "malformed_product_pitch"
    if broken and len(PRICE_KEYS.findall(text)) >= 8:
        return "malformed_product_pitch"
    if len(QUERY_SEO.findall(text)) >= 2 and len(COMPOUND_QUERY.findall(text)) >= 3:
        return "repeated_search_query"
    if "いろいろなキーワードが検索されている" in text and len(QUERY_SEO.findall(text)) >= 1:
        return "search_keyword_boilerplate"
    return None


class FluencyScreen:
    """Use a local causal model to score a fixed spread of substantial passages."""

    threshold = 5.2

    def __init__(self, directory):
        from collect_precision_nospin import disable_spinning
        from projected_lm import ProjectedModel

        self.model = ProjectedModel(directory)
        disable_spinning(self.model,directory)

    def score(self, text):
        from passage_methods import source_fragments

        lines = [normalize(p.text) for p in source_fragments(text)
                 if 24 <= len(p.text) <= 220 and len(KANA.findall(p.text)) >= 5]
        if len(lines) > 12:
            n = len(lines)-1
            lines = [lines[round(i*n/11)] for i in range(12)]
        tokenized = [self.model.tokenizer.encode(s,add_special_tokens=False).ids[:86] for s in lines]
        seq = [[self.model.bos]+tokens for tokens in tokenized if len(tokens) >= 14]
        if len(seq) < 6:
            return None
        losses = self.model.losses_at(seq,[0]*len(seq),[len(s)-1 for s in seq])
        return median(fmean(sorted(values)[2:-2]) for values in losses)


def multi_edit_witness(a, b):
    """Identify reused passage structure with several distinct lexical changes."""
    a,b = ("".join(s.split()) for s in (normalize(a),normalize(b)))
    if min(len(a),len(b)) < 42:
        return False
    edits = SequenceMatcher(None,a,b,autojunk=False).get_opcodes()
    substitutions = [(a[i:j],b[k:l]) for kind,i,j,k,l in edits
                     if kind == "replace" and CONTENT.search(a[i:j]) and CONTENT.search(b[k:l])]
    return len(set(substitutions)) >= 2


def reworked_series(witnesses):
    """Require separate nearby rewrites plus a promotional cue for weaker alignments."""
    for left, right, a, b, _ in witnesses:
        if not (AFFILIATE_BODY.search(a) and AFFILIATE_BODY.search(b)):
            continue
        if any(0 < abs(left-i) <= 350 and 0 < abs(right-j) <= 350
               and min(len(other_a),len(other_b)) >= 50
               for i,j,other_a,other_b,_ in witnesses):
            return True
    return False


def pair_overlays(pairs, page_lengths=None):
    """Use paired promotional copy to mark the witnessed spans on each source page."""
    overlays = defaultdict(set)
    campaign_evidence = defaultdict(list)
    title_evidence = defaultdict(set)
    repeated_slots = defaultdict(list)
    for match in pairs:
        distinct_hosts = match["a"]["host"] != match["b"]["host"]
        qualifying = []
        spun = 0
        for left, right, a, b, substitutions in match["witnesses"]:
            a_norm, b_norm = normalize(a), normalize(b)
            if page_lengths and any(before and after for before, after in substitutions):
                left_page, right_page = match["a"], match["b"]
                if (distinct_hosts and min(len(a), len(b)) >= 37
                        and all(PROMOTION.search(text) or CAMPAIGN_COPY.search(text) for text in (a_norm, b_norm))):
                    campaign_evidence[left_page["row"]].append((left, right_page["host"], a))
                    campaign_evidence[right_page["row"]].append((right, left_page["host"], b))
                if (distinct_hosts and min(len(a_norm), len(b_norm)) >= 55
                        and all(PROMOTION.search(text) or CAMPAIGN_COPY.search(text)
                                for text in (a_norm, b_norm))):
                    for (first, second), count in Counter(map(tuple, substitutions)).items():
                        if count >= 2 and min(len(first), len(second)) >= 3:
                            repeated_slots[left_page["row"]].append((left, first, second, right_page["host"]))
                            repeated_slots[right_page["row"]].append((right, second, first, left_page["host"]))
                if all(TITLE_PITCH.search(text) for text in (a_norm, b_norm)):
                    title_evidence[left_page["row"]].add((right_page["row"], b_norm))
                    title_evidence[right_page["row"]].add((left_page["row"], a_norm))
            if all(PROMOTION.search(s) and ACTION.search(s) for s in (a_norm,b_norm)):
                qualifying.append((left,right,a,b))
            if distinct_hosts and multi_edit_witness(a,b):
                spun += 1
        if spun >= 2 or distinct_hosts and reworked_series(match["witnesses"]):
            qualifying = [entry[:4] for entry in match["witnesses"]]
        elif len(qualifying) < (1 if distinct_hosts else 2):
            continue
        for left,right,a,b in qualifying:
            overlays[match["a"]["row"]].add((left,left+len(a)))
            overlays[match["b"]["row"]].add((right,right+len(b)))
    if page_lengths:
        from register_audit import name_of_site

        for row, evidence in campaign_evidence.items():
            size = page_lengths.get(row, 0)
            if not 0 < size <= 1400:
                continue
            sites = {name_of_site(host) for _, host, _ in evidence}
            offsets = {offset for offset, _, _ in evidence}
            repeated_affiliate = any(
                len(text) >= 65 and len(ACTION.findall(normalize(text))) >= 2
                for _, _, text in evidence
            )
            if len(sites) >= 3 and (len(offsets) >= 2 or repeated_affiliate):
                overlays[row].add((0, size))
        for row, evidence in repeated_slots.items():
            size = page_lengths.get(row, 0)
            if not 0 < size <= 1400:
                continue
            slots = defaultdict(set)
            for offset, own_value, peer_value, host in evidence:
                slots[offset, own_value].add((peer_value, name_of_site(host)))
            if any(len({host for _, host in peers}) >= 5 and len({value for value, _ in peers}) >= 5
                   for peers in slots.values()):
                overlays[row].add((0, size))
        for row, peers in title_evidence.items():
            size = page_lengths.get(row, 0)
            if 0 < size <= 1400 and len({page for page, _ in peers}) >= 3 and len({text for _, text in peers}) >= 3:
                overlays[row].add((0, size))
    return overlays
