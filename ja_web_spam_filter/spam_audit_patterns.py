"""Document-level signals for copied offers, damaged prose and mixed source blocks."""

import re
from collections import defaultdict
from urllib.parse import unquote, urlsplit

from .word_salad_filter import normalize


BOOK_PROVIDER = re.compile(r"BookLive!?|ブックライブ|Renta!?|電子書籍.{0,4}レンタ", re.I)
BOOK_ACTION = re.compile(r"試し読み|無料サンプル|無料で(?:読|見)|続きはコチラ|表紙クリック|公式.{0,6}コチラ")
BOOK_LAYOUT = re.compile(r"評判|品揃え|支払|決済|無料アプリ|会員登録|電子書籍ストア|電子コミック|ジャンル分け")
PUBLISHER_LINKS = re.compile(r"表紙クリック|続きはコチラ|コチラから|[↓]{3,}")
SEARCH_DATE = re.compile(r"(?<!\d)(?:19|20)\d{2}[/-]\d{1,2}[/-]\d{1,2}(?!\d)")
SEARCH_METADATA = re.compile(r"PDFをダウンロード|メタデータをダウンロード|RIS形式|更新日時|閲覧数|検索結果")
PRODUCT_LIST = re.compile(r"(?m)^[-●]\s+[^\r\n]{14,}")
CATALOG_CODE = re.compile(r"\b[A-Z0-9-]{5,}\b|送料無料|中古.{0,5}ランク|限定特価")
CATALOG_LAYOUT = re.compile(r"商品(?:情報|詳細|仕様|名|番号|説明)|適合表|在庫|送料無料|販売価格|選択肢|出品")
SEO_SPLICE = re.compile(r"(?m)^.{4,70}の情報を検索[!！]|■{2,}\d{2,5}■{2,}")
JOB_INVITE = re.compile(r"求人(?:情報)?サイト(?:へ|に|を)|当サイトに掲載|登録はこちら|仕事をしてみませんか")
JOB_STACK = re.compile(r"求人.{0,20}求人|(?:顔出し|アリバイ)|(?:優良|お勧め).{0,18}求人")
COPY_PRICE = re.compile(r"コピー時計|スーパーコピー|N級品|レプリカ時計")
COPY_DOMAIN = re.compile(r"(?:swisscopy|watchcopy|copywatch|copytokei)", re.I)
PRODUCT_FRAGMENT = re.compile(r"(?m)^.{3,75}(?:カテゴリ|メーカー名|レーベル)[：:].{1,100}")
PRODUCT_SIGNUP = re.compile(r"サンプル(?:動画|視聴)|無料会員登録|会員のみ")
BROKEN_AFFILIATE = re.compile(
    r"(?:とき|場合|うち)は.{0,7}でしかない|"
    r"(?<=[ぁ-ゖ一-龯])[がをに][ \t]+(?=と(?:判|言|考)|です|ます)|"
    r"恋愛が実って恋愛関係|交際相手のことを切りなく|"
    r"(?<=[ぁ-ゖ一-龯])のを手段|(?:量|金額)へまする|"
    r"モイスチュア効果[努を]|(?:角質|手中)世話|野生原材料|"
    r"血行促進威力|保湿の威力|肌の難事|効用を守|ウェートではない|"
    r"利用を相手にして|付帯サービスをキープ|伴侶の収入へ|肌を.{0,6}メラニンを付与|"
    r"東京の人気沿線や更には東京|カッティングやシャンプー.{0,12}デザインをデザイン|"
    r"(?:(?:しか|ので)ない|ば(?:のため|の事))の.*(?:腕時計|付属品)"
)
LEGAL_FORM = re.compile(r"反しない限り|決するところによる|なければならない|とみなすことができる|科せられない")
LEGAL_NOISE = re.compile(r"を(?:負担|保有|買収)と示される|(?:を|と)示される|通常は[一-龯ぁ-ゖ]{1,10}にしなければならない")
KEYWORD_NOUN = re.compile(r"無排卵の写真|無排卵が履|(?:無排卵|病名|卵巣)を(?:撮|しなければ)|不妊に.{0,5}アップ")
MALFORMED_QUERY = re.compile(r"完全無料占い未登録|手相恋愛|恋愛師")
LOAN = re.compile(r"返済|融資|借り入れ|キャッシング|カードローン|借金")
GRAFT = re.compile(r"脱毛|ムダ毛|角質|スキンケア")
ROUTE = re.compile(r"(?:/article/\d{4}-\d{2}-\d{2}-\d+/\d+-\d+/?$|/[^/]{5,20}/[^/]{5,20}\d{5,}\.html?$)")
AFFILIATE_BOOK_ROUTE = re.compile(r"/([^/]{2,25})/\1[_-]\d+/[^/]*\d+\.html?$")
REGIONAL_PITCH = re.compile(r"お勧め|おすすめ|比較|見積|購入|返金|申込|試算|公式サイト|特典|口コミ")
REGIONAL_SPIN = re.compile(r"(?:確約|実践|実行|体験|最善|実情|想起|実態|仕組み|効能|効用|本質|根本|幾つ|是非|肝要|是が非でも|相応|適切|案件|荷重|用法|対処|満載|結実|実現|処置)")
REPEATED_REPAIR_PHRASE = re.compile(r"筋肉筋肉|必要とと考え|だとということ|少ない金額の融資を相手に|をしてして下")
FRAGMENTED_CAPTURE = re.compile(r"(?m)(?:^|\n)(?=[^\n]{150})(?:[^\n]*?)(?:…|\.\.\.|[A-Za-z] +[A-Za-z]).{0,100}")
REVIEW_GRAFT = re.compile(r"ランク上位商品|ランキング上位商品|b\s*y\s*楽\s*天|詳しくはこちら|楽天市場")
LITERAL_LANGUAGE = re.compile(r"上部の上部|私たちは、あなたが|品質の発見されています|問題の解決に対処するために")
CAMPAIGN_MONEY = re.compile(r"無料一括査定|新車値引き|一括査定|査定時期|現金化")
CAMPAIGN_CAR = re.compile(r"ピーターラビット|ラビットホール|どっち安い\.?\d|[。！？]も新しい")
EPOCH_CATALOG = re.compile(r"/1970/01/01/")
MARKETPLACE_FIELDS = re.compile(r"商品の状態|発送元の地域|発送までの日数|新品、未使用|出品者負担|商品レビューを行ってください")
COPIED_MARKETPLACE = re.compile(r"(?i)/jp\.php|/pickup/|/index\.php.*\.html|\?.+\.html")
TRACKING_PROMOTION = re.compile(r"https?://[^/\s]+/(?:tracking|track)/af/")
BLOG_PROMOTION = re.compile(r"無料ブログ|アフィリエイターデビュー|収益アップ|無料お試し")
BODY_CARE = re.compile(r"薄毛|育毛|抜け毛|頭皮")
STREAMING_OFFERS = re.compile(r"無料お試し期間|全話無料で視聴|レンタル動画に使える|何話からでも無料")
STORE_APP_NAVIGATION = re.compile(
    r"(?m)^[ \t]*アプリでサクサク記事が読めます[。 \t]*\r?\n"
    r"[ \t]*アプリで店舗の取扱いが確認できます[。 \t]*$"
)
AMAZON_QUESTION_WIDGET = re.compile(
    r"商品情報、Q&A、レビューで回答を検索[^\n]*\r?\n"
    r"[^\n]{20,85}\r?\n有効な質問が入力されていることを確認してください。"
    r"質問は編集することができます。または、そのまま投稿してください。"
)
BOOKSTORE_EMPTY_REVIEW = re.compile(r"まだレビューはありません。[ \r\n]*作品の好きなところを書いてみませんか[？?]")
RETAILER_SHIPPING_WIDGET = re.compile(
    r"中が透けて見えない袋でお届けしますので、外からはどんな商品かわかりません。"
    r"[ \r\n]*ゆうパックの送り状の品名欄には"
)
LOADING_PLACEHOLDER = re.compile(r"(?m)^Initialising \.\.\.[ \t]*\r?$")
BROWSER_COMPATIBILITY_NOTICE = re.compile(
    r"お使いのブラウザー[（(]Internet Explorer 11より古いブラウザー[）)]は"
    r"マイクロソフトによるサポートが\d{4}年\d{1,2}月に終了しております。"
    r"(?:[。！？\n]*[^。！？\n]{0,85}(?:アクセスできなくなります|バージョンアップ)[^。！？\n]{0,130}。){0,2}"
)
PROPERTY_ARCHIVE_LAYOUT = re.compile(
    r"過去から現在まで[^。\n]{0,32}掲載のあった賃貸物件情報を元に作成した参考ページです"
)
PROPERTY_ARCHIVE_FIELDS = re.compile(r"建物詳細・設備・空室情報データ|最新の空室状況のご確認|駅から徒歩\d+分の位置")
MIXED_AFFILIATE_LAYOUT = re.compile(r"★ もっと[^\n]{2,55}を見る ★|★ まだみたことがないキミは登録しよう ★|ネットの妄想 つぶやき")
AFFILIATE_REVIEW_SECTIONS = re.compile(r"口コミ評判&悪い口コミ|料金&お手当相場|入会[〜~～]デートまでの流れ")
EPISODE_CARD = re.compile(r"(?m)^\|(?:放送|話数|制作|声優)\|\||^第\d{1,3}話[ 　『「]")
MALFORMED_VERB = re.compile(
    r"量を順法|効き目を掴み取るが|スタートを斬られ|頭脳をしてでも|"
    r"価値がきっとあるでしょう|表と裏を買収|心配事の女の人|ぶっ続けましょう|"
    r"(?:鳩|ハト)(?:で防鳥|がなくなった|になりたい)|出資を行って教えている"
)


def unreferenced_regional_offer(text, path):
    from template_index import _place_hierarchy

    path_parts = path.strip("/").split("/")
    if len(path_parts) < 2 or not 550 <= len(text) <= 3750:
        return False
    region, place = path_parts[-2:]
    labels, _, _ = _place_hierarchy()
    if (region, place) not in labels or region in text or place[:-1] in text:
        return False
    return (len(REGIONAL_SPIN.findall(text)) >= 9 and len(set(REGIONAL_PITCH.findall(text))) >= 2
            or REPEATED_REPAIR_PHRASE.search(text))


def copied_sentence_runs(text):
    for part in re.split(r"[。！？\r\n]", normalize(text)):
        cleaned = "".join(part.split())
        if 35 <= len(cleaned) <= 260:
            yield cleaned


class CorroboratedCopies:
    """Match multiple distinct copied sentences against previously verified spam sources."""

    def __init__(self, references):
        from ahocorasick_rs import AhoCorasick

        anchors = defaultdict(set)
        for row, text in references:
            for sentence in set(copied_sentence_runs(text)):
                anchors[sentence].add(row)
        distinct = sorted(anchors)
        self.rows = [anchors[s] for s in distinct]
        self.matcher = AhoCorasick(distinct) if distinct else None

    def contains_copy(self, text):
        if self.matcher is None:
            return False
        text = "".join(normalize(text).split())
        matches = defaultdict(set)
        for idx, start, end in self.matcher.find_matches_as_indexes(text):
            for row in self.rows[idx]:
                matches[row].add((idx, start, end))
        for hits in matches.values():
            if len({i for i, _, _ in hits}) >= 3 and sum(end - start for _, start, end in hits) >= 165:
                return True
        return False


def reason(text, url):
    """Return an observed document pattern, or None when corroboration is weak."""
    text = normalize(text)
    try:
        page = urlsplit(url)
        path = unquote(page.path)
        query = page.query
    except ValueError:
        path = ""
        host = ""
        query = ""
    else:
        host = page.hostname or ""
    head = text[:430]
    if (path.startswith("/realtime/search") and "ベストツイート" in head
            and "画像・動画を常に展開する" in head):
        return "realtime_search_snippet_aggregation"
    if len(set(MIXED_AFFILIATE_LAYOUT.findall(text))) >= 3:
        return "affiliate_catalog_with_unrelated_article"
    if (host.removeprefix("www.") == "comp-liance.co.jp" and path.startswith("/papakatsu/")
            and len(AFFILIATE_REVIEW_SECTIONS.findall(text)) >= 5 and text.count("公式サイト") >= 3):
        return "repeated_affiliate_conversion_page"
    if PROPERTY_ARCHIVE_LAYOUT.search(head) and len(set(PROPERTY_ARCHIVE_FIELDS.findall(text))) >= 2:
        return "generated_property_archive"
    if path.startswith("/search/") and len(LOADING_PLACEHOLDER.findall(head)) >= 4:
        return "search_results_with_repeated_loading_placeholder"
    if (BOOK_PROVIDER.search(head) and len(BOOK_PROVIDER.findall(text)) >= 2
            and len(set(BOOK_ACTION.findall(text))) >= 2
            and (len(set(PUBLISHER_LINKS.findall(head))) >= 2 or len(set(BOOK_LAYOUT.findall(text))) >= 3)):
        return "repeated_ebook_affiliate_funnel"
    if (AFFILIATE_BOOK_ROUTE.search(path) and BOOK_PROVIDER.search(head)
            and len(BOOK_PROVIDER.findall(text)) >= 2 and BOOK_ACTION.search(text)):
        return "ebook_pitch_on_generated_catalog_route"
    if len(SEARCH_DATE.findall(text)) >= 3 and len(set(SEARCH_METADATA.findall(text))) >= 2:
        return "mixed_search_results_with_download_metadata"
    if (len(SEO_SPLICE.findall(head)) >= 2 or
            EPOCH_CATALOG.search(path) and SEO_SPLICE.search(head)
            and len(set(BOOK_LAYOUT.findall(text))) >= 2):
        return "catalog_with_generated_query_and_marker"
    if (ROUTE.search(path) and (len(PRODUCT_LIST.findall(text)) >= 7
            or len(CATALOG_CODE.findall(text)) >= 13 and len(set(CATALOG_LAYOUT.findall(text))) >= 2)):
        return "synthetic_route_with_mixed_catalog"
    if (host.endswith((".web.app", ".firebaseapp.com")) and len(text) >= 1300
            and len(FRAGMENTED_CAPTURE.findall(text)) >= 2 and len(re.findall(r" [A-Za-z]{2,}", text)) >= 5):
        return "chopped_snippets_on_bulk_search_route"
    if len(set(JOB_INVITE.findall(text))) >= 2 and len(set(JOB_STACK.findall(text))) >= 2:
        return "stacked_region_job_landing_pitch"
    if COPY_DOMAIN.search(host) and (COPY_PRICE.search(text) or len(re.findall(r"時計|付属品", text)) >= 4):
        return "imitation_watch_storefront"
    if PRODUCT_FRAGMENT.search(head) and len(set(PRODUCT_SIGNUP.findall(head))) >= 2:
        return "affiliate_catalog_spliced_into_prose"
    if len(set(BROKEN_AFFILIATE.findall(text))) >= 2:
        return "repeated_incompatible_word_substitutions"
    if len(set(LEGAL_FORM.findall(text))) >= 3 and len(LEGAL_NOISE.findall(text)) >= 4:
        return "unrelated_terms_in_statutory_sentence_frames"
    if len(set(KEYWORD_NOUN.findall(text))) >= 2 or len(MALFORMED_QUERY.findall(text)) >= 6:
        return "keyword_forced_into_unrelated_word_slots"
    if (len(text) >= 4500 and text[-150:] in text[:1400]
            and len(set(REGIONAL_PITCH.findall(text))) >= 3):
        return "recycled_lead_and_tail_in_long_promotional_page"
    if unreferenced_regional_offer(text, path):
        return "rewritten_pitch_on_unrelated_municipality_route"
    if len(set(CAMPAIGN_MONEY.findall(text))) >= 2 and len(set(CAMPAIGN_CAR.findall(text))) >= 2:
        return "unrelated_phrases_spliced_into_car_pitch"
    if len(set(REVIEW_GRAFT.findall(text))) >= 2 and re.search(r"(?m)^この広告は、?90日以上|ランキング上位商品.{0,80}詳しくはこちら", text, re.S):
        return "copied_product_review_aggregation"
    if re.search(r"(?m)^(?:製品の説明|商品の説明)", text) and len(LITERAL_LANGUAGE.findall(text)) >= 2:
        return "garbled_machine_translated_product_page"
    if len(set(MARKETPLACE_FIELDS.findall(text))) >= 4 and (
            COPIED_MARKETPLACE.search(path + "?" + query) or len(text) >= 1800):
        return "marketplace_listing_mixed_with_other_product_text"
    if len(set(MALFORMED_VERB.findall(text))) >= 2:
        return "repeated_corrupt_verb_argument_pairs"
    if (TRACKING_PROMOTION.search(text) and len(set(BLOG_PROMOTION.findall(text))) >= 3
            and BODY_CARE.search(head) and len(BODY_CARE.findall(text)) >= 4):
        return "affiliate_tracking_pitch_spliced_into_body_care"
    if (len(set(STREAMING_OFFERS.findall(text))) >= 3 and len(set(EPISODE_CARD.findall(text))) >= 4
            and re.search(r"31日間.{0,15}無料|無料.{0,15}31日間", text)):
        return "reused_streaming_pitch_in_episode_catalog"
    if (len(LOAN.findall(text)) >= 3 and len(GRAFT.findall(text)) >= 3
            and any(LOAN.search(line) and GRAFT.search(line) for line in text.splitlines())):
        return "stitched_loan_and_body_care_pitch"
    return None


class AuditPatterns:
    def __init__(self, reference=None, revision=None):
        self.copies = None
        if reference:
            if reference["revision"] != revision:
                raise ValueError("Copy references use a different FineWeb2 revision")
            self.copies = CorroboratedCopies((row["row"], row["text"]) for row in reference["pages"])

    def reason(self, text, url):
        blocked = reason(text, url)
        if blocked:
            return blocked
        if self.copies and self.copies.contains_copy(text):
            return "multiple_sentences_copied_from_verified_spam"
        return None

    def overlays(self, text, url):
        if blocked := self.reason(text, url):
            return {blocked: [(0, len(text))]}
        navigation = [(match.start(), match.end()) for match in STORE_APP_NAVIGATION.finditer(text)]
        result = {"repeated_store_app_navigation": navigation} if navigation else {}
        compatibility = [match.span() for match in BROWSER_COMPATIBILITY_NOTICE.finditer(text)]
        if compatibility:
            result["browser_compatibility_notice"] = compatibility
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            return result
        widgets = {"amazon.co.jp": AMAZON_QUESTION_WIDGET, "ebookjapan.yahoo.co.jp": BOOKSTORE_EMPTY_REVIEW,
                   "adult.monkey.co.jp": RETAILER_SHIPPING_WIDGET, "monkey.co.jp": RETAILER_SHIPPING_WIDGET}
        if widget := widgets.get(host.removeprefix("www.")):
            spans = [(match.start(), match.end()) for match in widget.finditer(text)]
            if spans:
                result["retailer_repeated_widget"] = spans
        return result
