"""Type-specific evidence for Japanese web spam and extraction damage."""

from base64 import b64decode
from binascii import Error as InvalidBase64
from collections import Counter, defaultdict
import hashlib
from itertools import combinations, pairwise
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from . import spam_audit_patterns as audit
from . import spam_composition as composition
from . import spam_coverage_gate as gate
from . import spam_relay_structure as relays
from . import spam_slot_structure as slots
from . import spam_venue_structure as venue_structure
from . import spam_structural_patterns as structural
from .regional_rewrite import municipality_route
from .word_salad_filter import (
    EXAM_AD, EXAM_LINK, INLINE_EXAM, INLINE_LINK, JOIN_DEFECT, NARRATIVE,
    exam_code, normalize,
)

VERSION = "spam-specialists-public-v205"


def receipt():
    modules = (audit, gate, structural, composition, relays, slots, venue_structure)
    paths = [Path(__file__), *(Path(module.__file__) for module in modules)]
    return {"version": VERSION, "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}

# Weak signals are useful for review but cannot reject a sentence by themselves.
REVIEW_ONLY = {
    # The archived PlaceHub witnesses had a labeled nearby-places section.
    # FineWeb2 lost the links and labels but kept the individual descriptions.
    "unlabelled-neighbouring-venue-cards",
    "anonymous-business-blurbs-mixed-on-single-place-id",
    "anonymous-restaurant-blurbs-merged-under-one-place",
    "short-anonymous-restaurant-collage-on-place-detail",
    # The source contains a WordPress image and linked related-story teasers.
    "attachment-page-filled-with-unlabelled-clipped-story-and-quote-fragments",
    "single-place-entry-with-unlabelled-descriptions-of-unrelated-venues",
    "single-restaurant-record-made-of-unlabelled-multiple-venue-blurbs",
    "single-venue-record-assembled-from-unlabelled-shop-blurbs",
    "single-shop-with-unlabelled-venue-montage-including-play-facility",
    "single-venue-record-mixing-unlabelled-dining-and-retail-cards",
    "single-dining-venue-made-from-unlabelled-competing-restaurant-descriptions",
    "single-attraction-record-with-unlabelled-museum-and-park-blurbs",
    "catalog-editorial-islands",
    "literal-product-rendering",
    "instruction-meaning-distortion",
    "literal-pun-translation",
    "fluent-paraphrase-campaign",
    "keyword-replacement-across-topics",
    "retailer-query-and-count",
    "same-topic-bad-substitutions",
    "directory-description-after-listing",
    "marketplace-review-of-other-product",
    "single-affiliate-ranking-review-join",
    "sentence-numbered-snippet-montage",
    "keyword-question-diary",
    "comma-joined-scrape-journal",
    "repeated-dating-query-at-line-end",
    "query-sitemap-snippet-footer",
    "translated-faq-stuffing",
    "repurposed-article-with-promotional-tail",
    "suitcase-locality-skincare-montage",
    "spun-prose-in-unsourced-quote-frames",
    "scrape-page-with-fake-rating",
    "unrelated-review-headlines-after-product-review",
    "unrelated-plots-in-affiliate-editor-note",
    "advertising-words-prefixed-to-unrelated-sentences",
    "location-card-in-generic-commerce-copy",
    "affiliate-testimonial-with-spun-impression",
    "synthetic-answers-on-opaque-route",
    "marketplace-results-with-fake-ratings",
    "query-collage-with-source-metadata",
    "regional-loan-affiliate-bracket",
    "recycled-appraisal-article",
    "clipped-pseudo-diary-with-pr-footer",
    "doorway-with-query-list-and-repeated-title",
    "scraped-amazon-reviews-under-repeated-product-title",
    "cross-category-listing-with-food-footer",
    "multiple-product-term-collisions",
    "search-prompts-in-résumé-advice",
    "electronics-support-source-montage",
    "water-server-copy-with-wall-renovation-footer",
    "repeated-job-doorway-headings",
    "dating-brand-keyword-carpet",
    "download-snippets-in-generated-archive",
    "downloadable-course-affiliate-endorsement",
    "unrelated-retail-copy-stitch",
    "casino-affiliate-with-pasted-operator-terms",
    "municipality-pitch-with-unrelated-generic-prose",
    "local-buyback-with-substituted-town",
    "synthetic-marketplace-review-layout",
    "scraped-article-with-catalog-cards",
    "rewritten-pseudo-diary-with-affiliate-graft",
    "legal-fraction-rewritten-as-calendar-date",
    "debt-advice-with-incompatible-word-substitutions",
    "job-site-portal-with-generic-ranked-pitches",
    "diary-with-erased-subject-slots",
    "repeated-streaming-query-in-spun-text",
    "forum-pasted-paid-manual-pitch",
    "streaming-signup-spliced-to-retailer-cards",
    "regional-repair-pitch-with-recycled-city",
    "appraisal-query-joined-to-literature",
    "recruiting-article-with-retailer-graft",
    "furniture-rewrite-with-unrelated-odor-article",
    "regional-search-doorway-with-pasted-office",
    "trading-signal-pitch-on-translated-article",
    "repeated-sale-title-inside-pasted-clinic-article",
    "full-diary-in-republication-template",
    "engagement-gated-clickbait",
    "regional-dating-query-in-unrelated-fragments",
    "reposted-market-news-with-duplicated-conversion-footer",
    "external-article-with-copied-paywall",
    "literary-placeholder-after-site-footer",
    "headline-only-feed-montage",
    "place-used-as-verb-in-keyword-spam",
    "repeated-product-title-in-copied-sports-article",
    "unrelated-catalog-after-rare-import-pitch",
    "staged-dialogue-leading-to-supplement-pitch",
    "anonymous-forum-opening-in-feed-wrapper",
    "news-reprint-before-vehicle-search-keyword-block",
    "full-personal-post-with-reprint-credit",
    "translated-tutorial-with-reversed-dimensions",
    "foreign-gambling-brand-repeated-in-copied-prose",
    "adult-locality-keyword-in-unrelated-opening-hours",
    "dating-testimonial-joined-to-local-news",
    "pet-service-definition-in-generated-diary",
    "retail-keyword-heading-over-copied-fiction",
    "copyright-limited-reprint-with-racing-signup",
    "sports-report-in-source-only-wrapper",
    "generated-items-route-with-products-inside-prose",
    "syndicated-market-report-with-offsite-sales",
    "witnessed-personal-story-mirror",
    "trading-software-pitch-with-diary-filler",
    "stock-diary-with-car-link-keyword-list",
    "witnessed-cinema-review-mirror",
    "repeated-catalog-cards-inside-technical-article",
    "empty-bibliography-and-spliced-reference-snippets",
    "local-fitness-pitch-after-unrelated-howto-bait",
    "bare-forum-replies-on-third-party-site",
    "alternating-headline-and-source-montage",
    "unanswered-query-before-unrelated-clickthrough",
    "witnessed-uncredited-news-mirror",
    "broadcast-transcript-with-preserved-video-markup",
}
STRUCTURAL = {
    "stitched_search_snippets": "search-result-compilation",
    "repeated_malformed_query_slot": "contaminated-grammar-slot",
    "unexpanded_numeric_placeholder": "unexpanded-numeric-placeholder",
    "heading_inserted_into_katakana": "heading-splits-word",
    "book_title_price_template": "title-and-price-in-fields",
    "locality_in_repeated_pitch": "location-in-reused-intro",
    "clinic_branch_in_repeated_review_copy": "clinic-branch-review-slot",
    "repair_ad_with_unrelated_products": "repair-product-slot",
    "regional_profile_landing_intro": "regional-landing-with-profile-stream",
    "ordered_regional_rewrite": "ordered-rewrite-on-municipality-routes",
}

FIELD = re.compile(r"送料込み|販売価格|商品の状態|発送元の地域|商品番号|商品コード|メーカー希望価格|在庫状況|"
                   r"出品者負担|商品説明|限定数量製品|ブランド[:：]|ご入札をお控え|追加画像が必要|"
                   r"最安価格|商品名|送料は別途|同梱区分|ネット在庫状況|\d{1,3}(?:,\d{3})+円")
REVIEW_JOIN = re.compile(r"\bby\s*楽天|b\s*y\s*楽\s*天|ランキング上位商品|レビューを書い?て|"
                         r"詳しくはこちら|\b(?:Reviews:|customer reviews|[1-5]\s*/\s*5\s*stars\b)", re.I)
PRODUCT_VOICE = re.compile(r"購入しました|気に入りました|良かったです|届きました|使っています|注文しました")
MARKET_LISTING = re.compile(r"が通販できます|がフリマアプリ|を出品します|商品状態を確認")
SEARCH_JOIN = re.compile(r"(?m)^\s*20\d{2}[/.-]\d{1,2}[/.-]\d{1,2}|Yahoo!?知恵袋|"
                        r"更新日時|回答数|閲覧数|続きを(?:見る|読む)|関連記事|\bPDFをダウンロード")
SERP_COUNTS = re.compile(r"\bRead:\s*[\d,]+|[\d,]+件の検索結果|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, 20\d{2} [·・]")
APP_SEARCH_ROUTE = re.compile(r"/(?:android|ios|iphone|download|app)-[a-z\d-]+\.html?$", re.I)
APP_SOURCES = re.compile(r"Google Play|App Store|動作環境|サポート\s*&\s*ガイド|関連記事|ダウンロード\s*[.。]", re.I)
LOANS = re.compile(r"ヤミ金|ブラック融資|消費者金融|キャッシング|カードローン")
LOAN_OFFER = re.compile(r"即日.{0,8}(?:審査|融資|借り)|融資を受けられ|融資を専門")
EDITORIAL = re.compile(r"警視庁|容疑者|逮捕|市議会|通信社|米メディア|試合|後半|旅行記|観光スポット|"
                       r"空港ラウンジ|搭乗|ホテル|スコア|動画.{0,12}シェア|シェアされると|"
                       r"政府|文書|担当相|公表|取材")
DIRECTORY = re.compile(r"(?:検索結果|求人|転職情報)なら.{0,40}[!！]|選べる条件|掲載件数|ヒット件数|"
                       r"求人が見つかります|検索条件|次のページ")
TEMPLE_DIRECTORY_ROUTE = re.compile(r"^/otera/[a-z_]+[0-9]+/?$")
TEMPLE_LISTING = re.compile(
    r"(?ms)^[|｜]所在地[^\n]*\n.*?^[|｜]交通アクセス[^\n]*\n")
TEMPLE_DESCRIPTION = re.compile(r"(?m)^(?:[^\n()（）、。0-9０-９|｜]{2,30}(?:神社|寺)(?:と)?は、|"
                                r"[^\n。]{0,37}地域にある神社です。)")
DIRECTORY_FOOTER = re.compile(r"(?m)^基本情報を見る[ \t]*\r?\n")
TEMPLE_FILLER = re.compile(r"代表的な寺院|寺院のような|様々な宗教活動|夜間を楽しむ|香りが強く|建てられたはじめて")
NUMBERED_SNIPPET_ROUTE = re.compile(r"^/[a-z]{4,30}\d{4,10}\.html?$")
DETACHED_SENTENCE_NUMBER = re.compile(r"(?m)[。！？!?]([1-9]\d?)[ \t]*\r?$")
RANKING_REVIEW_HEAD = re.compile(r"(?m)^[^\n]{1,36}\d{4}年\d{1,2}月\d{1,2}日[ \t]+ランキング上位商品↑")
RANKING_REVIEW_LINK = re.compile(r"(?m)^詳しくはこちら[ \t]+b[ \t]+y[ \t]+楽[ \t]+天")
SHOPPING_SEARCH_HEAD = re.compile(r"情報を検索[!！]")
SHOPPING_OFFER = re.compile(r"激安[!！][ \t]*セールス価格はコチラ[!！]")
SCRAPE_JOURNAL_ROUTE = re.compile(r"^/(?:journal|[a-z]{4,7}\d{1,3})/[^/]+-[0-9a-f]{6}/?$")
DATING_KEYWORD_TAIL = re.compile(r"(?m)([一-龯]{2,8}(?:のママ活|[ で]出会い))[ \t]*\r?$")
QUERY_SITEMAP = re.compile(r"(?m)^/[ \t]*\r?\nsitemap 0\r?\nsitemap 1\r?\nsitemap 2\r?\nsitemap 3\b")
TERMINAL_PROMO = re.compile(r"ミュゼ[ \t]+トライアングル|⇒礼服女性|ヤフパ以上に今注目の出会える注目の恋活アプリ")
SOURCELESS_QUOTE_LEAD = re.compile(r"(?m)^(?:私が|今日|本日|素人ですが|なんとなく)"
                                    r"[^\n「]{0,50}(?:情報で[はす]|限りで[はす])[^\n「]{0,4}「")
SOURCELESS_QUOTE_CLOSE = re.compile(r"[。！？!?]」(?:だと|と、|のように|な、)[^\n]{0,60}(?:です|ます)。")
MARKETPLACE_REVIEW_ROUTE = re.compile(r"/pickup/[A-Z][0-9]{4,10}/?$")
MARKETPLACE_PICKUP_QUERY = re.compile(r"pickup/[A-Z][0-9]{4,10}")
MARKETPLACE_REVIEW_LABEL = re.compile(r"(?m)^(?:[a-z][a-z0-9_]{1,23}さん|(?:- )?ソース)[ \t]*\r?$", re.I)
FAKE_RATING_HEAD = re.compile(r"^Rated\r?\n[1-5](?:\.\d)?/5 based on\r?\n[0-9,]+ customer reviews\r?\n"
                              r"[A-Z][a-z]+ \d{1,2}, 20\d{2}\b")
FAKE_RATING_ROUTE = re.compile(r"^/[^/]+/page-\d+-20\d{2}-\d{2}-\d{2}\.html?$")
REVIEW_HEADLINES_MARKER = re.compile(r"(?m)^その他の感想[ \t]*\r?$")
AFFILIATE_EDITOR_NOTE = re.compile(r"(?ms)^管理人より一言[ \t]*\r?\n.{80,6000}?"
                                   r"(?=^安心・安全に美少女ゲームを楽しむために[ \t]*\r?$)")
CATEGORY_AD_PREFIX = re.compile(r"[。！？!?](ブックメーカー|プロモーション|ボーナス|カジノ|casino|bonus|william|"
                                r"入金|出金|賭け|オッズ|配当|サプリメント|わきが|ワキガ|多汗症|"
                                r"発汗|クリニック|手術|スキンケア)(?=[ぁ-ゖァ-ヺ一-龯])", re.I)
LOCATION_CARD = re.compile(r"(?m)^\|地名\|\|([^|\r\n]{2,30})\|[ \t]*\r?\n"
                           r"\|ユウビンバンゴウ\|\|〒?\d{3}-\d{4}\|[ \t]*\r?\n"
                           r"\|住所など\|\|[^|\r\n]{4,65}\|[ \t]*\r?\n"
                           r"\|読み方\|\|[ァ-ヺー・ ]{6,80}\|")
LOCATION_COMMERCE = re.compile(r"買取|査定|融資|求人|お申込|見積もり|最安|割引|無料相談|出会い")
AFFILIATE_TESTIMONIAL = re.compile(
    r"(?m)^[^\n]{0,24}(?:効果と評価|口コミ|評判|感想)[^\n]{0,30}(?:一から|一人で)"
    r"[^\n]{0,48}(?:時間|難|根気|苦労)[^\n]{0,28}\r?\n"
    r"(?:感じ方|考え方)は[^\n]{2,24}ですが、(?:個人的な|素直な|全体を通した)"
    r"[^\n]{3,32}\r?\n[^\n]{8,100}\(\^")
AFFILIATE_SKEPTICAL = ("購入者の声や暴露記事", "サポートは充実かな", "試してみたくなる")
MODEL_TURNS = re.compile(r"(?m)^Model[ \t]*\r?\n20\d{2}-\d{2}-\d{2}\b")
RATING_RESULT_HEADER = re.compile(r"^約[\d,]+件\r?\n\d+ (?:のうち 100 に基づく [\d,]+ ユーザーの評価"
                                  r"|out of 100 based on [\d,]+ user ratings)", re.I)
QUERY_METADATA = (
    re.compile(r"閲覧数\s*:\s*[\d,]+|回答数\s*:\s*\d+"),
    re.compile(r"Duration: \d+:\d{2}|[\d,]+ views\."),
    re.compile(r"お礼\s*:\s*\d+枚|mixiニュース|チューニング設定"),
)
REGIONAL_LOAN_ROUTE = re.compile(r"/(?:mobit|yushi)[^/?]*(?:/|\.html?$)")
PR_MARKUP_FOOTER = re.compile(r'\[PR\]<a href="">https?://[^"\s]+">')
PSEUDO_DIARY_TRANSITION = re.compile(r"最近気になって|明日も笑って|気になりますよね|そうそう[、。]|気になるんですけど")
DOORWAY_ENTRY = re.compile(r"(?m)^↓(?:ご入場|ｲﾁｵｼ|イチオシ)↓|^\[ENTER\]$")
AMAZON_CUSTOMER = re.compile(r"(?m)^Amazon[ \t]+カスタマー[ \t]+[1-5][ \t]*\r?$")
AMAZON_SCRAPE_ROUTE = re.compile(r"^/[a-z]+/[A-Z][a-z]+\d{4,10}\.html?$")
CATALOG_SHIPPING_FOOTER = "同じお届け先でも異なる温度帯の商品とは同梱はできません。"
PRODUCT_TERM_COLLISIONS = (
    re.compile(r"即日脱毛に対応している金融業者|クレジットカードに脱毛機能|脱毛を受ける.{0,12}(?:金利|業者から)"),
    re.compile(r"産婦人科を買|性器をダメにしたときは買い|ファッションサイト[^。\n]{0,35}胎児がイチオシ"),
    re.compile(r"近頃[^。]{0,30}話題になることも多い便秘ってまだ行った|直腸でお茶を濁す|便秘でもみんなが熱狂"),
)
RESUME_QUERY_AD = re.compile(r"(?m)^(?:履歴書 探しにちょうど良い情報をご用意いたしました。|"
                             r"わずかな情報も見逃さない職務経歴書 書き方情報に精通したサイトです。)")
JOB_DOORWAY_HEADING = re.compile(
    r"(?m)^(\S{1,15} .{5,38}求人) (?:紹介|登録無料|利用無料|紹介手数料無し|仲介料金無し|お勧め)[ \t]*$")
DOWNLOAD_SCRAPE_ROUTE = re.compile(r"^/[a-z]{4,18}\d{4,6}[a-z]{2,12}/\d{4,9}\.html?$")
RETAIL_SPLICE_TOPICS = (
    (re.compile(r"ミートソース|レトルト|トマトソース"), re.compile(r"フェミニン|コーディネート|レースを使")),
    (re.compile(r"身長を伸ばすサプリ"), re.compile(r"黄ぐすみ|美容液|色の白いは七難隠す")),
    (re.compile(r"ヘッドライト|LEDフォグランプ"), re.compile(r"無水フタ|ステンレス製|フィスラー")),
    (re.compile(r"キャロウェイ|ゴルフシャフト"), re.compile(r"石材|石工|墓石|花崗岩")),
)
SHIPPING_FIELDS = re.compile(r"商品の状態|配送料の負担|発送元の地域|発送までの日数|送料込み\(出品者負担\)|らくらくメルカリ便")
REVIEW_SCORE_ROW = re.compile(r"(?m)^[一-龯々ぁ-ゖァ-ヺーA-Za-z0-9_ ]{2,23}[ \t]+[1-5][ \t]*$")
GENERATED_CARD_ROUTE = re.compile(r"(?:/[a-z]{3,22}\d{3,12}[a-z]{0,14}/|/[a-z]{1,18}\d{3,12}\.html?$|"
                                  r"/index\.php/[a-z0-9_-]{15,}|/\d{3,}/[a-z]+[a-z0-9_-]{9,})")
WALL_LOCAL_TERMS = re.compile(r"外壁塗装|水素水サーバー|ウォーターサーバー|バストアップ|豊満|豊胸|"
                              r"育毛|発毛|薄毛|借金|任意整理|債務整理|婚活|結婚相談所|美容液|角質層|化粧水")
LOCAL_MAILIN = re.compile(r"全国対応|宅配買取|オンライン無料査定|出張査定|店舗に足を運ばず")
LOCAL_BUYBACK_TITLE = re.compile(r"^([一-龯々ヶケ]{2,15}(?:市|町|村|区))(?=にて|にお住まい|で)")
SCRAPED_EDITORIAL = re.compile(r"著者|出版社|掲載誌|作品|プロフィール|巻末|書評|評論|ポエム|詩集|"
                               r"企業・投資家情報|掲載日|発表作品|筆者|書籍|発売日")
COMMERCE_CARDS = re.compile(r"商品名|メーカー|送料無料|アウトレット|廃盤|定価|未使用|発送|ネット通販")
DISJOINT_AFFILIATE = re.compile(r"(?:【PR】|\[PR\]|こちらからご登録|広告をクリック|楽天市場|情報を検索[!！])")
COMMON_DIARY_PIVOTS = re.compile(r"気になるんですけど|気付いたら|最近気になって|どうなんでしょう|"
                                 r"知ってましたか|なんだか気にな|はてさて|話は変わりますが|明日も笑って")
ROTATING_DATING_BRAND = re.compile(r"LoveKind|LOVE[☆★]?FOOL|フレアイ|セレブ紹介所|トクヨク|"
                                  r"ふれあい広場|愛アプリ|エプロン|Mocom", re.I)
PRODUCT_REVIEW_TOPIC_MISMATCHES = (
    (re.compile(r"釣り糸|PEライン"), re.compile(r"成長期サプリ"), re.compile(r"スプーン|規定量")),
    (re.compile(r"指輪|シルバーリング"), re.compile(r"ドライヤー|風量"), re.compile(r"髪|乾く")),
    (re.compile(r"ゴルフシューズ"), re.compile(r"泡立ち"), re.compile(r"油汚れ|洗剤")),
)
SYNTHETIC_PATH = re.compile(r"/(?:[a-z]{3,30}[\d]{4,}|[a-z0-9-]{13,})\.(?:s?html?|php)$", re.I)
PRICE_CARD = re.compile(r"\|{1,2}[¥￥][\d,]+(?:円)?\|")
IMPLAUSIBLE = re.compile(
    r"徹頭徹尾していな|日記に取り去|冷蔵庫に起こる|高世論|"
    r"どれもこれもは惚れ込|聞きいて|を対策でき|ワンショットの量が大きめ理由|"
    r"品質混合物|時計をクリアします|考慮に考慮に|恋人トラップ混合物|"
    r"通信死者の霊ます|[A-Za-z]{3,}ます[。！？]|の名前になりましたます"
)
INSTRUCTION_DISTORTION = re.compile(r"蒸気バリア|断熱.{0,50}(?:スコアをつけ|絶縁に関して)|"
                                    r"ハサミに行きます|あなたはあなたが.{5,30}を持っているよう")
LITERAL_QA = re.compile(r"(?m)^\s*\d{1,2}[.．]\s*[^\n？?]+[？?]")
LITERAL_IDIOM = re.compile(r"牛が帰宅するまで|犬に伝えますが.{0,20}放牧|ジャガイモには目があり|"
                           r"彼ら(?:を|に)私の犬に|笑わせるでしょう")
CALQUE_PRODUCT = re.compile(r"品質混合物|時計をクリアします|考慮に考慮に|"
                             r"ロマンチックにしてください|迅速な物流を持|物流と安全な包装を持")
IN_MARKETING = re.compile(r"無料試し読み(?:コーナー|はこちら|はコチラ)|無料サンプル(?:&試し読み)?|"
                           r"表紙クリック|続きはコチラ|電子(?:貸本|書籍).{0,30}(?:購入|レンタル)")
BOOK = re.compile(r"電子(?:貸本|書籍|コミック)|BookLive|Renta|パピレス", re.I)
BOOK_PARAPHRASE = re.compile(r"試し読み.{0,35}(?:購入|不安)|スマホ.{0,20}(?:電子|漫画|マンガ)|"
                              r"電子(?:貸本|書籍|コミック).{0,30}(?:決済|支払)|"
                              r"(?:布団|ベッド).{0,25}(?:寝そべ|読み)|無料サンプル")
FILM_PITCH = re.compile(r"フル動画を無料(?:視聴|で見)|今すぐ.{0,60}(?:動画|無料)|動画配信状況|"
                         r"全話無料|無料トライアル|無料お試し期間")
APP_PITCH = re.compile(r"ダウンロード.{0,22}(?:インストール|設定)|(?:インストール|最も検索された).{0,25}ダウンロード|"
                        r"下記カテゴリー内の.{0,65}ダウンロード")
SONG_PITCH = re.compile(r"(?i)pdf版の歌詞.{0,100}mp3を無料でダウンロード|"
                         r"(?:曲|歌詞|楽曲|音楽).{0,50}mp3.{0,16}ダウンロード")
LOCAL_MOVING = re.compile(r"([一-龯々ぁ-ゖァ-ヶー]{2,15}[市区町村])から"
                          r"([一-龯々ぁ-ゖァ-ヶー]{2,15}[市区町村])への?引[っ越こし]{1,5}")
BATCH_OFFER = re.compile(r"料金相場|費用相場|見積り|引越しした人の口コミ|単身パック|一括査定")
TRANSIT_FIELDS = re.compile(r"駅名|駅番号|所属路線|路線名|乗降人員|鉄道会社|運営会社名|駅情報|開業年月日|\|乗車")
STATION_QUERY = re.compile(r"駅周辺.{0,45}(?:情報を検索|情報を探|と検索すると)|駅周辺でを探")
LONG_QUERY = re.compile(r"([^。！？\n]{6,45})の?に(?:関して詳しく|関連した情報|関係する最新情報)")
REPEATED_LANDING_QUERY = re.compile(r"に関係する最新情報.{0,38}に関連した情報|"
                                    r"を間違いなく確保|の情報を、どのサイトよりも詳細")
CATALOG_COMMAS = re.compile(r",/.{1,45}\.(?:s?html?|php),|\.\w{2,4},/|[\d,]+円[,、] *[\w一-龯ァ-ヶ]")
LOAN_SLOTS = re.compile(r"スピード融資|24時間振込|WEB申込|自動契約機|提携金融機関")
JOB = re.compile(r"求人|募集|アルバイト|採用|幼稚園|保育士")
LOCAL_TARGET = re.compile(r"[一-龯々ヶケ]{2,12}[市区町村](?=で|の|に|へ|.{1,12}駅)")
DATING_ACTION = re.compile(r"(?:出会い系.{0,16}|に)登録して|出会い系に求め|楽しい時間を過ご")
RETAIL_RESULT = re.compile(r"楽天市場.{0,35}[\d,]+件.{0,30}価格比較|検索結果.{0,20}[\d,]+件")
DATING_PITCH = re.compile(r"サクラがいない|(?:こちら|当)の?(?:サイト|ページ)で.{0,28}紹介|"
                           r"(?:出会い系|出会い).{0,18}(?:登録|安心|サイト)|出会いを求めている")
RETAIL_FIELDS = re.compile(r"商品一覧|検索結果|全\s*\d[\d,]*\s*件|[\d,]+件中|業界最安|送料無料")
LEGAL_FORM = re.compile(r"とみなすことができる|決するところによる|各号に掲げる|法第\d+条")
SEMANTIC_SWAP = re.compile(r"(?:の気温になる日もある|が紅葉する|が導入されています|を開催することが多く|"
                            r"を相手にして|の製品群|が履|を撮ら|に色を).{0,12}")
SWAP_COLLISIONS = re.compile(r"人事考課.{0,160}マッチングアプリ|の水深.{0,140}出会い系|"
                             r"の関心事.{2,18}[市区町村]をツイッター|の新作の公開.{0,20}割り切り予約|"
                             r"車.{0,32}売却前.{0,34}ジャーナリスト志望")
BROKEN_LITERAL = re.compile(r"通信死者の霊ます|[A-Za-z]{3,}ます[。！？]|"
                            r"(?:を取る|を取り).{0,8}塩のピンチ|あなたはあなたが|歯車線に沿")
BROKEN_INLINE = re.compile(r"[ぁ-ゖ][a-zA-Z]{5,}[ぁ-ゖ一-龯]|"
                           r"のDMM化|(?:を|が)[ぁ-ゖ]{0,4}、を|しっかりと育てられ.{0,22}生息.{0,20}異性",
                           re.I)
BROKEN_MONTAGE = re.compile(r"のDMM化|(?:を|が)[ぁ-ゖ]{0,4}、を|生息.{0,24}異性|"
                            r"思い出したいコード.{0,14}から歯|(?:不滅|数値)は、私も親もファン")
UNRELATED_BLOG_TITLE = re.compile(r"(?m)^([^。\n]{3,24})に関する誤解を解いておくよと[^\n]{2,25}\n"
                                 r"\1はひとまずおいといて[。.]")
DESIGN_SERVICE = re.compile(r"名刺を作成|印刷用データ|入稿|あらかじめ用意されたデザイン")
CONSULT_SERVICE = re.compile(r"相談実績|不倫に関する相談|調査実績|法律相談|無料相談の実例")
MARKET_SPECS = re.compile(r"\|商品(?:名|詳細)|\|モデル|【(?:対象年齢|サイズ|備考|材質)】|SKU[:：]|品番[:：]")
GIFT_OPENING = re.compile(r"(?:お返し.{0,15}お祝い|お歳暮.{0,14}ギフト|熨斗.{0,14}包装)")
TOPIC_CLUES = tuple(re.compile(p) for p in (
    r"カジノ|スロット|賭け|入金", r"ダウンロード|アプリ|設定画面|インストール",
    r"送料無料|商品番号|発送|落札|ご入札", r"恋愛|交際|出会い",
    r"金利|カードローン|融資|借り入れ", r"試合|前半|後半|選手",
    r"ホテル|搭乗|空港|観光", r"商品仕様|在庫状況|販売価格",
))
APPRAISAL_CAMPAIGN = tuple(re.compile(pattern) for pattern in (
    r"一括査定サービスをして[^。\n]{0,45}買取相場",
    r"中古車査定をするサイトでの一括査定にカギを握る",
    r"車査定を成功させる場合の(?:肝心|かなめ|必要不可欠|重要)",
    r"所定の項目[^。\n]{0,50}一括かつゼロ円で\s*5[~〜～―ー-]10社[^。\n]{0,30}買取業者",
    r"高額で売却することができる通常より高額",
))
WATER_DELIVERY_CAMPAIGN = tuple(re.compile(pattern) for pattern in (
    r"(?:水代|水の料金)と電気[^。\n]{0,44}はばかることなくガブガブ",
    r"アクアクララ[^。\n]{0,120}(?:月|ヶ月)\s*350円ということができます",
    r"クリクラ[^。\n]{0,120}(?:粉乳|ドライミルク)の栄養[^。\n]{0,16}(?:効果|影響|作用|インパクト)",
    r"放射能問題やダイオキシン[^。\n]{0,125}お水を子供に",
    r"クリクラは[^。\n]{0,30}安全(?:基準|対策)で[^。\n]{0,76}RO膜[^。\n]{0,10}システム",
))
MATCHMAKING_CAMPAIGN = tuple(re.compile(pattern) for pattern in (
    r"月収を気にするあまり[^。\n]{0,10}赤い糸で結ばれた相手を取りこぼす",
    r"結婚紹介所のような所は[^。\n]{0,25}身辺調査があ",
    r"お見合いブーム[^。\n]{0,130}相手をサーチして[^。\n]{0,38}デートをする場所",
    r"婚活.{0,2}を赤ちゃんを(?:増加させる|増やす)\s*1手段として",
    r"婚活パーティー[^。\n]{0,25}大人の社交界[^。\n]{0,65}(?:認識|マナー)があるのか",
    r"一緒にマナー教室を受講したり[^。\n]{0,21}スポーツのゲームを観戦",
))
REVIEW_ATTRIBUTION_FOOTER = re.compile(
    r"(?m)^[ \t]*(?:"
    r"口コミ(?:の)?内容は[、，,]\s*好意的[・･]否定的なものも含めて[^。\n]{1,45}さんの主観的なご感想です。"
    r"|口コミは[、，,]\s*実際に衣装を購入[・･]レンタル[・･]試着した方々の主観的なご意見[・･]ご感想です。"
    r"(?:[ \t]*あくまでも参考情報のひとつとしてご活用ください。)?"
    r"(?:[ \t]*\nまた[、，,]\s*口コミに記載されているサービス内容[・･]スタッフ[・･]運営会社等は[、，,]\s*"
    r"投稿された方が購入[・･]レンタル[・･]試着した当時のものです。)?"
    r"(?:[ \t]*\n現在とは異なる場合がございますので[、，,]\s*"
    r"現在の状況は直接各ブランド[・･]ショップにご確認ください。)?"
    r")"
)
REPEATED_PAGE_BOILERPLATE = (
    ("review-directory-sort-instructions",
     "編集部が実際に足を運んで厳選した",
     re.compile(r"こだわりの条件で検索したり、口コミのランキングで並べ替えることもできます。")),
    ("regional-property-sales-blurb",
     "マンション・一戸建て・土地の売却をお考えの方",
     re.compile(r"また、知識・経験ともに豊富な不動産売却のエキスパートがご相談から査定、"
                r"販売計画の立案、売却までを全力でサポートいたします。"
                r"\s*お客様の大切な資産である不動産を、スムーズに安心して少しでも高く"
                r"売却できるよう誠実な対応を心掛けております。")),
    ("ebook-auto-purchase-widget",
     "この作品の次の最新刊を発売日に自動的に購入し、本棚にお届けします。",
     re.compile(r"自動購入の登録は後でいつでも解除できます。")),
    ("used-watch-inventory-blurb",
     "親切なプライスや商品の信頼性が裏打ちしていると思います。",
     re.compile(r"親切なプライスや商品の信頼性が裏打ちしていると思います。"
                r"\s*全在庫商品の販売平均は2[-–]3週間であり、なかには掲載後数分や1[-–]3日で"
                r"売れてしまう商品も多々あります。\s*新商品は「LINE[＠@]」にて掲載しておりますので、"
                r"チェックしていただけるとありがたいです。")),
    ("sold-property-notification-blurb",
     "はお陰様で販売を終了致しました。",
     re.compile(r"弊社問合せフォームにてご要望頂けましたら、当お部屋でキャンセル等が発生した場合、"
                r"他のお部屋が販売になりました際にご紹介させて頂きます。")),
    ("science-series-description",
     "サイエンス365days",
     re.compile(r'["“「]サイエンス365days["”」]\s*は、あの科学者が生まれた、あの現象が発見された、'
                r'など科学に関する歴史的な出来事を紹介するコーナーです。')),
    ("saved-job-search-widget",
     "保存した検索条件が10件を超えたため、保存ができませんでした。",
     re.compile(r"マイページの保存した求人検索条件から不要な条件を削除してください。")),
    ("investment-risk-disclaimer",
     "本レポートの内容に関する一切の権利は当社にあります",
     re.compile(r"お取引いただく各商品等には価格の変動・金利の変動・為替の変動等により、"
                r"投資元本を割り込み、損失が生じるおそれがあります。")),
    ("community-group-directory-blurb",
     "認定NPO法人ウィメンズアクションネットワークの活動をご紹介します。",
     re.compile(r"各地の女性に関する運動体・グループをご紹介します。\s*あなたのグループも是非ご紹介ください。")),
)
CORROBORATED_PAGE_TEMPLATES = (
    ("regional-loan-query-in-lender-name", (
        r"[市区町村]のレイク家族バレないは、新生銀行",
        r"【レイク】[^。\n]{0,60}3項目で3秒診断",
    )),
    ("betting-product-with-joined-race-report", (
        r"当商品購入日より\d+日以内に\d+年分\d+日間分",
        r"馬券購入を実施しイン有利の馬場",
    )),
    ("hair-loss-article-with-broken-rewrites", (
        r"症状になるでろう症状になるであろう",
        r"髪の毛のスピードが手遅れになる",
    )),
    ("medical-term-collisions-in-scraped-dentistry", (
        r"歯並びや噛み合わせの問題\s*[•・]",
        r"葛根湯は副作用のない薬なので",
        r"歯周病に関する.{0,3}大きな誤解",
    )),
    ("personal-finance-pitch-with-corrupted-copy", (
        r"子供が居ても大丈夫!!短期間でお金を貯める方法\s*-\s*子供が居ても大丈夫!!",
        r"はっきりって難しいところ",
        r"人見知りでもしっかり得するちょっと相談に乗るだけ",
    )),
    ("mobile-plan-copy-with-inserted-dating-brand", (
        r"とら婚\s+とら婚の\d+日間の通信上限",
        r"ララコールはショートメッセージ",
    )),
    ("foreign-search-tag-with-career-scrape", (
        r"^土木建築関連の職に関わる情報はいえらぶキャリ",
        r"どうする[？?]建築学生",
        r"「大手病」という病を発症",
    )),
    ("catalog-scrape-with-unrelated-products", (
        r"^人間工学に基づき、独自性[·・]機能性に優れた.{0,8}VARIER",
        r"JJ6203 VARIER バリエール",
        r"BALDO.{0,30}CORSA",
    )),
    ("casino-forum-promotional-snippet-join", (
        r"^出金手数料も不要\.",
        r"賭けっ子リンリンから出金",
        r"ビットコインカジノ広告\.",
        r"iOS \d+\.\d+以降が必要です",
    )),
    ("cross-topic-scrape-with-numbered-sitemaps", (
        r"(?:sitemap \d+\s*){4,}",
        r"スバルが新車を出します",
        r"シフォンタイムは旬の国産素材",
    )),
    ("language-school-scrape-with-false-wikipedia-credit", (
        r"<<会社URL:https?://",
        r"キーワード無しの関連情報\s*該当する記事がありませんでした",
        r"※テキストはWikipedia\s*より引用しています",
    )),
    ("mistranslated-cat-research-with-broken-phrases", (
        r"東京のソフィア大学からの行動科学者",
        r"人間の休憩面はすべて猫に同じように見えます",
        r"秒で猫が区切られています",
    )),
    ("beauty-ad-spliced-with-damaged-posts", (
        r"^恥ずかしい気持ちはよくお世話になってますか",
        r"身長\d+度にプルプル震え",
        r"もっとライトを自分で縛り上げ",
    )),
    ("multilingual-video-directory-with-keyword-footer", (
        r"^首页\s+国产自拍\s+国产剧情\s+国产AV\s+高清无码",
        r"直达页尾\s+返回首页\s+返回顶部\s*$",
    )),
    ("rewritten-cosmetics-with-duplicated-sales-lead", (
        r"^ホワイトニングを目的として値段の張る化粧品をゲットしても",
        r"クレンジンミルクやふんわりしたクレンジングクリーム",
        r"ホワイトニングを目的として値段の張る化粧品をゲットしても[^\n]+。\s*$",
    )),
    ("moving-quote-article-with-broken-splices", (
        r"年度末のひっきりなしね時期",
        r"前日に引越しの予約をキャンセル",
        r"家を購入したことで、よそに行きました",
    )),
    ("affiliate-amplifier-review-aggregation", (
        r"ランキング上位商品[\s↑]{0,8}ATW-SP707",
        r"ワイヤードマイクの付属商品も紹介されているともっとよかった",
        r"オーディオテクニカ",
    )),
    ("water-product-copy-with-meeting-minutes", (
        r"フレシャスの新型サーバーのデュオの特徴は第1回定期総会",
        r"ウォーターサーバーの家庭用は買うこともできるけど",
    )),
    ("income-query-with-scraped-game-responses", (
        r"^オンラインで早くお金を稼ぐ\|オンラインで早くお金を稼ぐ",
        r"ボスジョブやフリーサ強盗",
        r"私は星五武器5本持ち",
        r"Legal\s*\|\s*Sitemap\s*$",
    )),
    ("name-inserted-in-unrelated-topic-scrape", (
        r"^西島悠也\|包丁が苦手",
        r"西島悠也だけでもクリアできる",
        r"西島悠也なドーム",
    )),
    ("regional-loan-pitch-with-broken-clauses", (
        r"^富田一色町エリアで融資を受ける",
        r"その際残っているなら対応によって与える印象",
        r"対応のスピード[^。]{0,80}プロミス|対応がとてもよい感じのプロミス",
    )),
    ("rental-fee-search-scrape-with-unrelated-debt", (
        r"^ゲオでのdvdの延滞料金\s*\.",
        r"延滞(?:料金|金).{0,25}踏み倒",
        r"国金の返済ができない場合",
    )),
    ("fashion-listing-with-literary-scrape", (
        r"^\|【FENDI】[^\n]{0,90}ネックレス",
        r"ピーターラビットの初版は素描",
        r"BONPOINT.{0,20}スカート",
    )),
    ("product-review-outline-with-machine-generated-queries", (
        r"^どのような猫 水 器を購入すべきか",
        r"完璧な商品を購入するための専門家のアドバイス",
        r"このようなリストで経験を共有",
    )),
    ("hair-treatment-affiliate-with-duplicated-links", (
        r"^育毛剤や育毛シャンプーが頭皮にいいように",
        r"せっかくの育毛シャンプーはゴミ箱行き",
        r"(https?://[^/\s]+\.seesaa\.net/)\s+\1\s+-\s+URL",
    )),
    ("spun-beauty-copy-with-malformed-body-phrases", (
        r"^小形なおっぱい不平の成人女性",
        r"おっぱいに容積が大きくなります",
        r"栄養補助食品いうものは総てやり損じ",
    )),
    ("regional-profile-ad-with-local-address-list", (
        r"^こんにちは。ゆうきです。\s*僕は日々出逢い系SNS",
        r"上伊那郡中川村近くで欲求不満なシングルマザー",
        r"場所一覧\s+大草/片桐/葛島/四徳",
    )),
    ("translated-entertainment-tag-index-montage", (
        r"^MyHeritageによると.{0,110}Deep Nostalgia",
        r"コブラ会の新しいシーズン",
        r"SDF-1",
    )),
    ("football-report-grafted-onto-phone-repair", (
        r"^ワールドカップ出場権を得たペルー代表",
        r"基盤を壊してしまう可能性もあります",
        r"ガラス割れ・バッテリー交換・音声が聞こえない・水没",
    )),
    ("security-product-pitch-with-broken-translation", (
        r"^[a-z0-9.]+\s+除去[: ]+解決策",
        r"より古い、より新しい発明の脅威",
        r"この強力なツールから逃れる",
    )),
    ("enzyme-product-with-joined-promotional-snippets", (
        r"お試し割引\s*[•・]\s*こんな飲み方だと生酵素サプリ",
        r"酵水素328選生サプリメント",
        r"タイミングは食前[!！]ダイエットに効果的",
    )),
    ("marketplace-apparel-reviews-grafted-onto-ceramics", (
        r"^.{0,70}(?:御猪口|お猪口|ぐい呑み)\s+この商品に関連するタグ",
        r"(?:^|\s)[a-z]{10,14}\s+[\s\S]{0,100}発送日時指定不可",
        r"生地.{0,80}履きやすい",
    )),
    ("comic-download-affiliate-query-template", (
        r"漫画村やzipでダウンロードするより安全に無料でダウンロード",
        r"コミックシーモアで無料でダウンロードできる[？?]",
        r"ebookjapanで無料でダウンロードできる[？?]",
    )),
    ("football-rankings-with-grafted-baseball-excerpt", (
        r"^UEFAランキング.{0,90}位クラブ",
        r"9年連続日本一をも制している",
        r"ヴェンゲルは17年連続でアーセナル",
    )),
    ("regional-dating-index-with-diet-diary-copy", (
        r"^不倫掲示板肉食系.{1,8}出会い",
        r"MEC食の割には多い",
        r"(?:島根県|鹿児島県)肉食系出会い",
    )),
    ("haircare-page-with-unrelated-keyword-list", (
        r"ケフトル",
        r"住宅ローン減税.{0,30}居住年",
        r"防草シート\s+砂利\s+効果",
    )),
    ("pillow-ad-with-semantic-rewrites", (
        r"昏々と眠れる枕",
        r"沈みんだけど固定実行されない",
        r"枕.{0,15}の卓越性",
    )),
    ("dating-profile-funnel-with-empty-region", (
        r"地域:\s*身長:\s*\d{3}",
        r"利用サイト:\s*MEET\s+出会うポイント",
        r"登録先の掲示板にて「ニックネーム」や「年齢」などで検索",
    )),
    ("regional-dating-profile-with-national-city-substitution", (
        r"^[^\s。]{1,12}市でセフレを探している熟女",
        r"大好きな全国の熟女が登録急増中",
        r"自分の近場である全国で相手探し",
    )),
    ("unrelated-news-pitch-inside-housing-copy", (
        r"北米系輸入住宅",
        r"Reutersをあなたに紹介致します。",
        r"ジョージアンスタイル.{0,55}チューダースタイル",
    )),
    ("office-equipment-copy-in-generated-product-index", (
        r"待ち順整理券発券機「Touch-me」",
        r"テンプレートで凡庸に作るのではなく",
        r"(?s:石工.{0,55}締め付け.{0,55}穴あけ.{0,55}電動工具)",
    )),
    ("translated-marketplace-query-with-unfilled-category", (
        r"^Alibaba\.comでは\d+個の.{0,35}製品",
        r"\[类目\d+比例\]",
        r"100%年のポリエステル",
    )),
    ("crab-shopping-copy-with-unrelated-parenthetical-definitions", (
        r"^蟹通販には多くの利点",
        r"店頭\(日本では、脳の死が人間としての死",
        r"詳しく調べたい方はこちら.{0,5}お歳暮に贈るハム",
    )),
    ("side-job-pitch-with-grafted-diary-snippets", (
        r"人気の副業アルバイトのメールレディ",
        r"みなさんこの木なんの木",
        r"洗濯物は増えるは洗濯で出来ない",
    )),
    ("spun-narrative-with-repeated-broken-opening", (
        r"^危険性を開けるとこっちには募集の当然",
        r"いやらしい写真が聞こえ始め",
        r"王様できないくらい機会が良い",
    )),
    ("finance-page-with-software-testing-excerpts", (
        r"バイナリーオプションとFXと株式投資を徹底比較",
        r"ベータテスターにベータ版スキルへのリンク",
        r"レバレッジを使うかについては",
    )),
    ("affiliate-pitch-with-grafted-personal-diary", (
        r"(?:発達障害改善マニュアル|ワンWEEK副業投資プログラム)",
        r"(?:インチキとか言われてたり|口コミって嘘)",
        r"(?:ドラマのビデオを友達に借りた|マカロニグラタン\s*を頂きました)",
    )),
    ("car-dealer-reviews-interleaved-with-municipality-index", (
        r"^販売を重視なので、整備は",
        r"三郷市\s*[•・]\s*久喜市",
        r"BIGMOTOR\s+埼玉県\s+のその他の店舗一覧",
    )),
    ("malformed-regional-hair-removal-pitch", (
        r"^Sパーツ無料お試しとかや",
        r"脱毛が完了させられましたうるさい宣伝",
        r"で安心・満足出来る脱毛サロン",
    )),
    ("skincare-spam-with-keywords-substituted-into-book-review", (
        r"出版社や作者の思うツボ",
        r"メイクでまず立ち読みする",
        r"ケアはドラマや映画の原作にもなりました",
    )),
    ("wallet-search-excerpts-joined-to-shopping-listing", (
        r"ラルフ\?ローレンっ。",
        r"高すぎるブランドバッグには手の届かない\s+大学生におすすめ",
        r"スモール\s+サイズラルフ\?ローレン",
    )),
    ("ramen-excerpts-interleaved-with-css-and-unrelated-travel-copy", (
        r"^-?\d+s;-webkit-animation-duration:",
        r"麺の種類",
        r"ワンメイクやジブの大会",
    )),
    ("rewritten-tea-ad-with-incoherent-keyword-insertions", (
        r"キャンデトの運動",
        r"クレジットカード誠実のキャンデト茶",
        r"紅茶を体外しました",
    )),
    ("relationship-excerpts-with-unrelated-review-fragments", (
        r"^それでテレビを捨ててみたんです」",
        r"「好き」にもlikeとloveがある",
        r"食べ始める頃にちょうど本編に入って",
    )),
    ("medical-answers-stitched-around-truncated-query", (
        r"^[a-z]{8,16}\s+病院のお医者さんって仕事大変だから論。",
        r"開業医はまず書かないでしょう",
        r"Kernel通信インタビュー",
    )),
    ("exterior-painting-page-with-caregiving-copy", (
        r"持ち家期間新たに発覚",
        r"外壁塗装相談センター無料見積り",
        r"介護量の軽減につながるように塗料代",
    )),
    ("nutrition-excerpts-with-tax-copy-and-unrelated-links", (
        r"^パエリアのカロリー",
        r"どか食いしても体が慣れていかないので、最低で[.]\s*消費税",
        r"Node Jsハイブリッドアプリ",
    )),
    ("dictionary-and-literature-excerpts-joined-to-medical-qa", (
        r"^✔\s*新明解国語辞典",
        r"パスカルの死後出版",
        r"自分は低血糖の症状がでるのだが",
    )),
    ("instrument-catalog-copy-in-mixed-goods-doorway", (
        r"^【送料無料】ボス BOSS ES-5",
        r"Effects Switching System【smtb-TK】\s*【送料無料】ボス BOSS ES-5",
        r"MOORING\s+ボート\s+カバー",
    )),
    ("rewritten-deodorant-ad-with-malformed-body-phrases", (
        r"腋下の体臭に思いつめる女性",
        r"臭う腋窩のを消滅するため",
        r"バラエティー豊かな品々を手に取る",
    )),
    ("rewritten-fiction-review-with-malformed-noun-substitutions", (
        r"^真夜中のビル",
        r"いるのはクレンジング員の己だけ",
        r"非常に良い図式が魅力的",
    )),
)
CORROBORATED_PAGE_TEMPLATES = tuple(
    (name, tuple(re.compile(pattern, re.I) for pattern in patterns))
    for name, patterns in CORROBORATED_PAGE_TEMPLATES
)



COLLAGE_MARKERS = re.compile(r"(?m)^[\U0001f300-\U0001faff✍✔⚑💬][ \t]+")
CSS_DECLARATIONS = re.compile(r"(?:-webkit-|-ms-|DXImageTransform|animation-duration\s*:)", re.I)
COLLAGE_SLOTS = re.compile(r"の(?:\(\d+年\))?にが|を促すに促|に指示するに促|開催されるの準備")
CHOPPED_SENTENCE = re.compile(r"(?m)(?:^[。]|(?<=[一-龯ぁ-ゖァ-ヺ])[ \t]+(?=[ぁ-ゖ][一-龯ぁ-ゖ])|"
                              r"(?<=[一-龯ぁ-ゖァ-ヺ])\n(?=[がをのにはも][一-龯ぁ-ゖァ-ヺ]))")
RETAIL_QUERY_ROUTE = re.compile(r"(?:/mall\.php|/(?:premium|saishin)/[\w.-]+|/id-\w{10,}\.cgi)$", re.I)
MIXED_STORE_CODE_ROUTE = re.compile(
    r"/(?=[a-z0-9_-]{17,}/?$)(?=(?:[a-z_-]*\d+[a-z_-]+){3})[a-z0-9_-]+/?$", re.I
)
STORE_COPY = re.compile(r"在庫.{0,12}(?:メーカー|場合)|発送予定|商品の?情報|お取り寄せ|"
                        r"ご注文|商品コード|販売価格|送料無料|別途送料|返品|納期|商品ページ|受付[：:]|ご購入|お届け")
STORE_TOPICS = tuple(re.compile(pattern) for pattern in (
    r"ジュエリー|ペンダント|真珠|ダイヤモンド|指輪",
    r"エクステリア|カーポート|外壁|住宅建材|三協アルミ",
    r"ウエア|ウェア|ショートパンツ|バックパック|リュックサック",
    r"取付板|カメラ|マウントプレート|手持ちジンバル|接続ケーブル",
    r"ギター|エフェクター|フットスイッチ|アナログ回路|バイオリン",
    r"ボート|クルーザー|船外機|船舶|係留",
    r"古民家|ツーリズム|地域づくり|体験農場|里山",
))
SALES_REVIEW = (
    re.compile(r"2ch|2ちゃんねる|購入した人|実践者"),
    re.compile(r"悪評|苦情|クレーム|インチキ|口コミって嘘|暴露|本当の評価"),
    re.compile(r"(?:買って|購入して|試して|やって|始めて)(?:みよう|みようか|みたい)|試せる"),
    re.compile(r"(?:マニュアル|プログラム|自動ツール|教材)"),
)
MONTAGE_DOMAINS = {
    "dentistry": re.compile(r"口腔|歯科助手|歯科診療|歯磨き|歯科健診|歯科保健|歯周病|歯科医療"),
    "snacks": re.compile(r"おやつ|クッキー|小麦粉|米粉|砂糖|保存料"),
    "medicine": re.compile(r"診断|処方|手術|多汗症|抗がん剤|服薬|子宮頸がん|療法|治療費|がん患者|交感神経|医療保険|"
                           r"飛蚊症|網膜剥離|散瞳眼底"),
    "property": re.compile(r"マンション|不動産|間取り|住宅ローン|物件|内覧|戸建|リフォーム"),
    "tax": re.compile(r"相続税|所得税|税金|控除|課税|相続人|税理士"),
    "market": re.compile(r"ナンピン|外貨預金|為替相場|取引手数料|元本割れ|手形割引|満期|運転資金|FX|ドル"),
    "school": re.compile(r"家庭教師|学習塾|高校受験|テスト対策|受講料|教育費|入試|指導|マンツーマン"),
    "hobby": re.compile(r"ボランティア|牧畜|アルバイト|農民|支援活動"),
    "beauty": re.compile(r"マニキュア|ネイル|まつ毛|ネイルサロン|美容液|スキンローション|保湿|目の下|エステサロン"),
    "equipment": re.compile(r"作業用品|作業工具|クランプ|交換用パッド|締め付け|本体寸法|品番"),
}
IRREGULAR_MONTAGE_CLAUSE = re.compile(
    r"[ぁ-ゖ一-龯][a-z][ぁ-ゖ一-龯]|[ァ-ヺ][ァ-ヺ][ァ-ヺ](?:ウン|エソ)(?=[一-龯])|"
    r"のになのに|〜[、,]|(?:[一-龯ぁ-ゖ])といってもその[ァ-ヶ]{3,}に?を|"
    r"\d他人|(?:生計|生活費)まずくない|(?<=[ぁ-ゖ])たるん(?=[一-龯])|"
    r"の約(?:割|%)(?=[をが])|[A-Za-z][ァ-ヶ]{2,}(?=エネルギー化)|"
    r"[、,]{2}|(?:損失|参照)されたりする|(?:癌|がん)かけ機"
)
SPORTS_GRAFTED_PROMOTION = re.compile(
    r"(?im)^.{0,30}(?:ユニフォーム|ジャージ)\s*(?:詳細については|をお買い求めの方は)"
    r"[^\n。]{0,100}(?:当社|当店|ウェブサイト|通販)"
)
SPORTS_ARTICLE_MARKERS = re.compile(
    r"得点|本拠地|主力|監督|J[1-3]リーグ|プロ入り|自陣|守備陣|パスワーク|期限付き移籍|獲得|順位"
)
ARTICLE_FOOTER_PITCH = re.compile(
    r"(?:の評判と(?:クチコミ|口コミ)|の最安値のクチコミ).{0,95}(?:を元にレビュー|を参考にレビュー)"
)
WITNESS_LEAD = re.compile(r"(?:2ch|2ちゃんねる|購入した人|購入者|実践者|体験談)")
DIARY_SWITCH = re.compile(r"(?m)^\s*(?:こんにちは|毎度です)[〜～♪!！ \t]*$")
PRODUCT_SKEPTICISM = re.compile(r"気になってきた|悩む|試してみ|本当に(?:いい|効果|できる)|"
                                r"効果あり[?？]|実際のところ|購入した人|インチキ")
DIARY_FILLER = re.compile(r"今日のお(?:ひる|昼)|昨日の晩ごはん|今日の現場|友達に借りた|"
                          r"突然ですが、この前|仕事が全然進んで|でもそう簡単には")
ADDRESS_PREFECTURE = re.compile(r"(?m)^([一-龯]{2,4}[都道府県])(?=[一-龯]{1,12}[市郡区町村])")
DESCRIPTION_PREFECTURE = re.compile(r"(?m)^(?P<name>[^\n。]{2,38}(?:寺|神社|宮)[^\n。]{0,10})"
                                    r"は、?(?P<pref>[一-龯]{2,4}[都道府県])[一-龯]{1,12}[市郡区町村]")
ENCODED_GEO_PATH = re.compile(r"^/[a-z]+_\d+/([A-Za-z0-9+]{8,60}={0,2})/?$")
REGIONAL_LEGAL_PITCH = re.compile(r"ヤミ金|闇金|キャッシング|借り換え|取り立て|法律事務所|分割払い|無料問い合わせ")
ROUTE_PRICE_CODES = re.compile(r"/[a-z0-9/_-]+_st_K\d{3}_ed_K\d{3}\.aspx$", re.I)
SHIPPING_QUOTE = re.compile(r"運搬|運送|引[っき]?越[しす]?|見積もり|料金|宅配|配送|相場")
HEAVY_KEYWORD_TAIL = re.compile(r"(?:[ぁ-ゖァ-ヺ一-龯]{2,11}[ \t]+){10,}")
SEO_QUERY_TITLE = re.compile(r"^(?P<seed>[^。！？?！\n]{8,45})(?:で一番|のおすすめ|の口コミ|とは|[?？])")
QUERY_SLOT_BREAKS = re.compile(r"と(?=業務|配管|名刺|印刷)|[、。][ぁ-ゖ]{1,2}に下手|の[、。]|"
                               r"[一-龯ぁ-ゖ]それぞれ[」』]|[ァ-ヶ]{2,}\)\s*\([ァ-ヶ]")
GAMBLING_DOORWAY = re.compile(r"/(?:casino|slots?|カジノ|スロット)/", re.I)
BETTING_KEYWORDS = re.compile(r"カジノ|パチンコ|ジャックポット|スポーツベット|ブックメーカー|仮想通貨|"
                              r"オンラインスロット|ボーナス")
MEDIA_CREDIT = re.compile(r"(?m)^.{0,32}(?:参加レポート|現場リポート|取材レポート)|"
                          r"検温|受け取り|イベント会場|開場")
DIARY_DATE_ROUTE = re.compile(r"^/(?:date|archives/date)/20\d{2}/\d{1,2}/\d{1,2}/?$")
DIARY_TEMPLATE_MARKS = re.compile(r"(?:ﾉ|ヾ|[☆★])|\([!-~ぁ-ゖァ-ヺ一-龯]{2,18}\)")
QUESTION_LEADS = re.compile(r"どう|教えて|連想|問題|クイズ|難しい|わか|正しい|ご存知")
STATION_DATING_SLOT = re.compile(r"^([一-龯々ァ-ヺー]{2,17}駅)出会い")
FLIRTY_REFERRAL = re.compile(r"出会い系アプリ|優良出会いコミュニティ|利用者数|おススメ|ハッピーメール|"
                             r"サクラ|登録無料|会員登録|安心")
TRANSLATED_SPORT_FAQ = re.compile(r"(?m)^(?:どの|誰|何|どちら|最も|最古|なぜ)[^\n。]{2,88}[?？]")
MALFORMED_SPORT_TERMS = re.compile(r"(?:クラブ|チーム|ユナイテッド).{0,24}(?:会議のうち|殴打され|面会する)|"
                                   r"リバプールか男\s*[uU]|サッカー.{0,12}取り巻いています")
SUSPECT_CATALOG_ROUTE = re.compile(r"^/[a-z]{4,25}/[a-z]{6,28}\d{5,10}\.s?html?$", re.I)
CATALOG_SPECS = re.compile(r"ウエスト|ウェスト|胸囲|着丈|袖丈|幅|素材|カラー|新品|対応サイズ|使用時|内容量|質量|おやつ")
CATALOG_UNITS = re.compile(r"\d+(?:\.\d+)?\s*(?:cm|mm|ml|kg|枚|号)", re.I)
AFFILIATE_CATALOG_ROUTE = re.compile(r"^/cate_[a-z0-9]{5,}/cont_[a-z0-9]{5,}/?$", re.I)
RETAIL_PUBLISH_MARKER = re.compile(r"(?m)^\s*(?:发布时间|發佈時間|發布時間)\s*[:：]")
INSERTED_CHINESE_LOCATION = re.compile(
    r"(?<=[ぁ-ゖァ-ヺ])("
    r"丹[東东]|平[涼凉]|柳州|潮州|自[貢贡]|河源|[陽阳]江|[德徳][陽阳]|澄海|[張张]掖|[廣广]安|"
    r"[鷹鹰]潭|肇[慶庆]|固原|江[陰阴]|唐山|保定|定西|林芝|[瓊琼]海|[雲云]浮|新竹|安康|"
    r"[馬马][爾尔]康|[馬马]鞍山|南[寧宁]|昆明|[蘇苏]州|武[漢汉]|新[鄉郷乡]|[寧宁]波|[懷怀]柔|"
    r"通州|[濰潍]坊|秦皇[島岛]|伊春|白城|西青|河北|株洲|喀什|邯[鄲郸]|桂林|[樂乐]山|"
    r"臨[滄沧]|北碚|合川|[鹽盐]城|[豐丰][臺台]|[盧卢][灣湾]|阿[圖图]什"
    r")(?=[ぁ-ゖァ-ヺ])"
)
INCOME_PITCH = re.compile(r"副業|副収入|求人情報|稼げる|高収入|アルバイト|収益|月収|登録|金儲け")
DIARY_ISLAND = re.compile(r"久しぶりに|ところで|昨日の[一-龯ぁ-ゖ]{2,8}|梅雨明け|今日の[一-龯ぁ-ゖ]{2,8}|"
                          r"しちゃった|この木なんの木|ホッとしてい|先日|[（(][^()（）\n]{0,7}[;^][^()（）\n]{0,7}[）)]")
COMMERCIAL_CARE = re.compile(r"クリーム|サプリ|メーカー|容量|クリニック|美容液|定期|口コミ|脂肪|税込|"
                             r"ベルト|成分|お肌|運動|定価|効果|初回")
SYNONYM_COLLISIONS = re.compile(r"(?:\d{2}(?:費用|経費|日時)半ば|(?:微妙|デリケイト)(?:ゾーン|箇所|地点)|"
                               r"定期(?:堅持|貫徹|保存)|(?:権利|用例)ですので.{0,20}予約|"
                               r"一(?:個|本)の石で二[羽匹]|石で二羽の鳥|"
                               r"(?:年代|年数)より老けて|(?:契約|登録)なミネラル|"
                               r"(?:契約|挙式)を話題する|(?:時間|瞬間)の昔や)")
REPEATED_SLOT_HEAD = re.compile(r"(?m)^.{0,15}の(?P<phrase>[一-龯ぁ-ゖァ-ヺー]{8,21})(?:伝説|方法|コツ)\d+.{0,12}$")
UPLOADED_NUMBERED_PAGE = re.compile(r"^/(?:[a-z][a-z0-9_-]{2,25}/){1,3}\d{10,16}\.html?$", re.I)
MANGLED_PRICE_FIELD = re.compile(r"(?<![\w_])__\d{1,3},\d{3,6}\b")
EMPTY_CITATION_SLOT = re.compile(r"「[ \t]*」|『[ \t]*』|(?:^|[。\n])\s*[、,]{2,}|(?:と呼び|と称し)、と")
QUESTION_BOUNDARY = re.compile(r"(?m)^[ \t]*[>＞↓]+\s*(?=[^\n。]{12,100})")
QUESTION_AUTHOR = re.compile(r"質問者[様さまさん]*|質問の意図|回答リクエスト|補足(?:回答|します|ですが|について)")
MISSING_PROFILE_FIELD = re.compile(r"(?m)^(?:地域|住所|年齢|名前)[：:][ \t]*$")
PROFILE_FIELDS = re.compile(r"(?m)^(?:身長|年齢|希望|性格|地域|住所|利用サイト|目的)[：:]")
PROFILE_OUTLINK = re.compile(r"無料登録|今すぐ(?:出会う|登録)|利用しているサービス|退会している場合|お相手を検索")
BROKEN_PROFILE_HEADING = re.compile(r"(?m)^の(?:その他|ほか)の(?:女性|男性|会員)|^(?:に|には)もっと.{2,35}(?:会員|女性|男性)")
SCRIPTED_TESTIMONIAL_CUES = (
    re.compile(r"買(?:っちゃ|っては)ダメ|詐欺なの|本当に(?:大丈夫|効果がある)"),
    re.compile(r"アマゾン|Amazon|ランキング|[Ww]iki"),
    re.compile(r"いろいろな(?:番組|雑誌|メディア)でも人気|口コミで話していた|[^\n]{2,20}さんって.{0,40}人気"),
    re.compile(r"(?m)^[⇒→]\s*(?:感想|口コミ|購入|詳細|レビュー)"),
    re.compile(r"私でも.{0,15}(?:挑戦|試し|使え|実践|でき)"),
)
SPLICED_LISTING_FIELDS = re.compile(r"新品|未使用|自宅保管|発送致します|出品しました|目立った傷|梱包|写真[1-9]枚目")
DISLOCATED_FRAGMENT = re.compile(r"(?m)^(?:名前を隠して|[^「\n]{2,20}みたいな話なのか|すまんな|ということではなく)\s*")
CATALOG_SCRAPE_HEADER = re.compile(r"(?i)\b(?:ISBN|JAN|SKU|[a-z]+books\s+online)\b|商品番号|型番|品番|[|｜]\s*\d{13}\s*[|｜]")
CATALOG_REVIEW_VOICE = re.compile(r"好きです|個人的|評価が分かれ|を楽しみに|気に入り|購入しました")
REMOTE_RETAIL_ROUTE = re.compile(r"^/[a-z]{4,24}/(?=[a-z0-9]*[a-z])[a-z0-9]{6,40}\d{5,}(?:\.html?)?/?$", re.I)
OLDER_BLOG_ALIAS = re.compile(r"__(?:\w+\s+){4,}|(?m:^[^\n]{2,16}\n(?:っていうのは|については|はいろいろな))")
SALES_FOOTER_OUTLINE = re.compile(r"リンク集|口コミサイト|人気ランキング|比較サイト|おすすめ商品")
TEXT_JOIN_FIELDS = re.compile(r"(?m)^(?:目次|キャスト|登場人物|記事一覧|そのほかの記事|最新情報|公式サイト)")
MALFORMED_MEDIA_ACTION = re.compile(
    r"(?:[ァ-ヴー]{2,18}|[一-龯]{3,10})を[一-龯]{3,9}した[・…]|"
    r"(?:公式サイト|ニュース|公開日|放送開始)して(?:る|いる|いた)|"
    r"[一-龯]{3,9}を[一-龯]{2,8}して[ァ-ヴー]{2,8}して(?:み|いる|いた)"
)
PROFILE_CARD = re.compile(r"(?m)^(?:登録エリア|名前|職業|誰似|利用目的|身長|バストサイズ|スリーサイズ|生年月日)[:：]")
AGE_GATE_PITCH = re.compile(r"年齢認証|年齢確認|登録後|利用するには|登録したら|登録してから")
EMPTY_BIRTH_DATE = re.compile(r"(?:\d{4}年)?(?:0月\d{1,2}日|\d{1,2}月0日)")
CATALOG_PROFILE_IDS = re.compile(r"\b[A-Z]{2,9}[-_]\d{2,6}\b")
PITCH_CONTAMINATION = re.compile(
    r"(?:[。！？!]|^)(?:\s*)は[一-龯]|(?:母性|父性|愛情)の配る|"
    r"に従ってで|(?:世紀|日付|月日)に起源します|(?<=[ぁ-ゖ])ことはでき\(ありえ\)ない|"
    r"(?:心|季節|春風)で暖かい.{0,12}月を送[るっ]|(?:商品|料理|食材)を見本寸法"
)
SEARCH_RESULTS_BOUNDARY = re.compile(r"(?m)^[ \t]*\.{3,6}\s*[^\n]{7,}")
SNIPPET_TIMESTAMPS = re.compile(r"(?:19|20)\d{2}年\d{1,2}月\d{1,2}日\s*(?:\.{2,}|…)")
WELLNESS_PITCH_STUMBLE = re.compile(
    r"[。！？](?:[ \t\n]*)(?:日|月|火|水|木|金|土)曜日は(?!(?:営業|休診|定休|診療|開店|受付|営業時間))|"
    r"(?:清潔感|印象)も.{0,20}(?:良く|よく)なります(?:良く|よく)|"
    r"ができ?多いかもしれません|しく?なかったに疑問|(?:原因|理由|効果を)お願いしましょう"
)
GENERATED_LISTING_PATH = re.compile(r"^/(?=[^/]{17,62}/?$)(?=[^/]*[a-z])(?=[^/]*\d)[a-z\d_-]+/?$", re.I)
PURCHASE_DELIVERY_BOILERPLATE = re.compile(r"ログインすると|お届け先|最安送料|注文確認画面|配送方法|送料が表示")
IRREGULAR_KEY_SEGMENT = re.compile(r"[a-z]{12,}\d{2,}[a-z]{7,}|[a-z]{6,}\d{2,}[a-z]{6,}\d{2,}[a-z]{6,}")
TOPIC_COLLAGE_SECTIONS = (
    re.compile(r"肌|スキンケア|美容液|目元|シワ|セルライト"),
    re.compile(r"投資|資産運用|キャッシング|仮想通貨|相場|株式"),
    re.compile(r"ウォーターサーバー|浄水|給水|水道水|ボトル"),
    re.compile(r"中学受験|高校受験|家庭教師|学習塾|志望校"),
    re.compile(r"アルコール|二日酔い|飲み会|焼酎|ビール"),
    re.compile(r"歯並び|歯が白|ホワイトニング|インプラント|歯科"),
)
ARTICLE_VOICE_LIST = re.compile(r"(?m)^\s*[-・]\s*[一-龯ぁ-ゖァ-ヺー]{2,8}さん[:：]")
SLOT_GAMBLING = re.compile(r"パチスロ|リール|賭け金|ボーナスゲーム|スロットマシン|パチンコホール")
SPORTS_COMPETITION = re.compile(r"プレミアリーグ|日本代表[MＦFＤD]|シーズン|選手賞|開幕戦|最多ゴール")
TRACKBACK_SHELL = re.compile(r"(?m)^.*(?:トラックバックする|TrackBack URL|トラックバックURL).*$", re.I)
TRACKBACK_CONTENT = re.compile(r"(?m)^.{25,180}(?:\.\.\.|…)[ \t]*$")
TOOL_LOOKUP = re.compile(r"検索|検索条件|キーワード|値を表示|結果|入力|パレット|一覧|データ")
ALTERNATING_QA_VOICES = re.compile(r"回答リクエスト|上の回答|ご質問に|質問者[様さん]*|補足回答|質問内容|ベストアンサー")
QUERY_DATA_CREDIT = re.compile(r"(?im)^\s*(?:Web Services by|Powered by(?: Web)?(?: API)?)\b")
CATALOG_REVIEW_TIME = re.compile(r"(?m)^20\d{2}-\d\d-\d\d[ \t](\d\d:\d\d):\d\d[ \t]*$")
CATALOG_REVIEW_DISTORTIONS = re.compile(r"年会のギフト|最後の歯の賞品|冷白を|高級[、,]大気|高級[、,]人に送"
                                         r"|会社のお礼儀|ギフト液|会社が年に買い入れ|精致|彼の家にいました")
DIVERGENT_PRODUCTS = (
    re.compile(r"プラセンタ|内容量|採取量|摂取上の注意|消費者庁|有効成分"),
    re.compile(r"ワンピース|フェミニン|コーデ|スカート|着こなし|ニット"),
    re.compile(r"MP3|アンプ|スピーカー|プレイヤー|キャリングケース|ケーブル"),
)
PROFILE_EMPTY_SLOT = re.compile(
    r"(?:へので|ので)\s+のため|する人は、(?:と|。)|(?:気づいたこと|ために、)・?\s*悩|"
    r"201\d年に\s*へ入社|いただき\s*しています|で、をする|づいたに請け負"
)
MOVING_RECOUNT = re.compile(r"引[っき]?越[しす]?|作業員|転居|旧居|新居|業者|見積もり|[0-9,]+万円|[0-9,]{4,}円")
TRADING_REFERRAL_SECTION = re.compile(r"(?m)^(?:これらで負けていませんか[？?]|トレードで結果が出ない方へ|"
                                      r"こんな取引で負けていませんか[？?])[^\n]{0,115}")
REFERRAL_PITCH = re.compile(r"求人サイト|お祝い金|一括検索|一括査定|無料会員|成果報酬|報酬アップ")
DATED_DIARY_START = re.compile(r"(?m)^\s*(?:今日|本日)の(?:天気|天候)は[^\n]{2,25}[。！!]")
MUNDANE_DIARY = re.compile(r"午前中は|昼ごはんは|お昼は|夕食は|歯を磨いて|読書タイム|今日の本は|明日はどんな")
APPRAISAL_PITCH = re.compile(r"下取り|一括査定|買取(?:業者|価格)|買取(?:専門|会社)|値引き")
PROMOTIONAL_TANGENTS = (
    re.compile(r"(?:ロッド|釣り道具)(?:買取|.{0,12}買い取)|中古の釣り道具|オークション"),
    re.compile(r"水漏れ|給湯器交換|蛇口|水道修理"),
    re.compile(r"カラコン通販|コンタクトレンズ通販|カラコン.{0,6}円|レンズ(?:の|を)通販"),
    re.compile(r"火災保険|保険の見直し|家財保険"),
    re.compile(r"なんでも屋|不用品回収|遺品整理"),
)


def variant_campaign_findings(text, url):
    """Corroborate reusable spam layouts without matching article titles or hostnames."""
    try:
        address = urlsplit(url)
        path = unquote(address.path)
    except ValueError:
        return ()
    head, tail = text[:min(500, len(text) // 2)], text[max(-880, -len(text) // 2):]
    reasons = []
    if NUMBERED_SNIPPET_ROUTE.fullmatch(path):
        numbers = set(DETACHED_SENTENCE_NUMBER.findall(text))
        markers = set(COLLAGE_MARKERS.findall(text))
        if (len(numbers) >= 4 and (len(markers) >= 3 or COLLAGE_SLOTS.search(text))
                or len(numbers) >= 2 and len(CSS_DECLARATIONS.findall(text)) >= 3
                or len(numbers) >= 5 and len(text) >= 650
                and not re.search(r"参考文献|<sup>|\[編集\]", text)):
            reasons.append("generated-snippet-collage-with-layout-debris")

    # This captures query slugs from unrelated mirrors, corroborated by broken seams or repeated prose.
    if ("-" in path and len(re.findall(r"[一-龯ぁ-ゖァ-ヺ]", path)) >= 13
            and re.fullmatch(r"(?:www\.)?[a-z]{6,12}\.icu", address.hostname or "")):
        sections = [p.strip() for p in re.split(r"[。!！?？\n]", text) if len(p.strip()) >= 26]
        if len(CHOPPED_SENTENCE.findall(text)) >= 3 or len(sections) - len(set(sections)) >= 1:
            reasons.append("query-slug-with-stitched-japanese-excerpts")

    if (RETAIL_QUERY_ROUTE.search(path) or MIXED_STORE_CODE_ROUTE.search(path)) and distinct(STORE_COPY, text) >= 2:
        front_topics = {i for i, p in enumerate(STORE_TOPICS) if distinct(p, head) >= 2}
        back_topics = {i for i, p in enumerate(STORE_TOPICS) if distinct(p, tail) >= 2}
        if (front_topics and back_topics - front_topics
                or path.endswith(".cgi") and len(re.findall(r"(?m)^\|[^|\n]{4,30}\|", head)) >= 2
                and re.search(r"変更\s+[^\n]{0,45}アウトドア", tail)
                or len(re.findall(r"(?m)^\|(?:特長|用途|仕様(?:\d+)?|材質_仕上)\|", text)) >= 4
                and back_topics or "無断で使用" in head and "他にも多くの会社に偽サイト" in text
                or len(re.findall(r"(?m)[【\[]送料無料[】\]]", tail)) >= 2 and len(back_topics) >= 2):
            reasons.append("mixed-retail-categories-on-generated-catalog-route")

    if len(text) <= 1900 and all(pattern.search(text) for pattern in SALES_REVIEW):
        has_short_lines = sum(0 < len(line.strip()) <= 36 for line in text.splitlines()) >= 7
        if has_short_lines and re.search(r"(?:さんの|流).{0,26}(?:マニュアル|プログラム|教材)", text):
            reasons.append("affiliate-testimonial-with-scripted-skepticism")

    for match in REPEATED_SLOT_HEAD.finditer(text):
        phrase = match["phrase"]
        if len(set(re.findall(re.escape(phrase) + r"[がをのには、]", text))) >= 3 and text.count(phrase) >= 5:
            reasons.append("repeated-query-in-incompatible-grammar-slots")
            break

    article_path = re.search(r"/(?:archives|article|category-\d+)/|/[^/]*[a-z]{3,}\d{4,}\.(?:html?|cgi)$", path)
    if 550 <= len(text) <= 16000:
        front = {name for name, pattern in MONTAGE_DOMAINS.items() if distinct(pattern, head) >= 3}
        back = {name for name, pattern in MONTAGE_DOMAINS.items() if distinct(pattern, tail) >= 3}
        full = {name for name, pattern in MONTAGE_DOMAINS.items() if distinct(pattern, text) >= 3}
        if ((len(full) >= 3 and len(IRREGULAR_MONTAGE_CLAUSE.findall(text)) >= 2)
                or (front and back and front.isdisjoint(back) and (
                    article_path and len(IRREGULAR_MONTAGE_CLAUSE.findall(text)) >= 2
                    or re.fullmatch(r"/[A-Za-z]+/[a-z]+\d{5,}\.html?", path)
                    and ("dentistry" in back or "equipment" in front)))
                or address.hostname and not path.strip("/") and {"medicine", "market", "school"} <= full
                or address.hostname and not path.strip("/") and "tax" in full
                and sum(len(MONTAGE_DOMAINS[kind].findall(text)) >= 4
                        for kind in ("medicine", "property", "beauty")) == 3):
            reasons.append("independent-technical-prose-islands-with-collage-evidence")
    non_punctuation_errors = {v for v in IRREGULAR_MONTAGE_CLAUSE.findall(text)
                              if re.search(r"[一-龯ぁ-ゖァ-ヺA-Za-z]", v)}
    if re.search(r"[一-龯ぁ-ゖァ-ヺ]", path) and len(non_punctuation_errors) >= 3:
        if re.search(r"エステ|化粧|ダイエット|筋トレ|体質|頭皮|美容", path + head):
            reasons.append("rewritten-wellness-article-with-multiple-malformed-clauses")
    if (SPORTS_GRAFTED_PROMOTION.search(tail) and distinct(SPORTS_ARTICLE_MARKERS, text) >= 5
            and (len(re.findall(r"(?m)^【[^\n]{3,32}】", text)) >= 2
                 or len(re.findall(r"(?m)^\d{1,2}分、", text)) >= 1)):
        reasons.append("sports-report-with-unrelated-storefront-footer")

    if (ARTICLE_FOOTER_PITCH.search(tail) and "公式サイト" in tail
            and len(re.findall(r"の(?:評判と(?:クチコミ|口コミ)|最安値のクチコミ)", text)) >= 3):
        reasons.append("affiliate-review-with-repeated-product-query-outline")
    if len(text) <= 2200 and (switch := DIARY_SWITCH.search(text)) and switch.start() >= 140:
        pitch = text[:switch.start()]
        if (WITNESS_LEAD.search(pitch) and distinct(PRODUCT_SKEPTICISM, pitch) >= 2
                and DIARY_FILLER.search(text[switch.end():]) and "購入" in pitch):
            reasons.append("affiliate-pitch-padded-with-unrelated-diary")

    if (place_token := ENCODED_GEO_PATH.fullmatch(path)) and distinct(REGIONAL_LEGAL_PITCH, head) >= 4:
        try:
            token = place_token[1]
            place = b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (InvalidBase64, UnicodeDecodeError):
            place = ""
        if (re.fullmatch(r"[一-龯々ヶ]{2,17}(?:市|町|村|区)", place) and head.count(place) >= 2
                and "警察は相手にしてくれません" in head and "法律事務所" in text):
            reasons.append("encoded-municipality-with-reused-loan-referral")
    if ENCODED_GEO_PATH.fullmatch(path):
        page_header = text.split("\n", 1)[0]
        appraisal = re.compile(r"一括査定|在庫状況|得意分野|顧客の客層|複数の業[社者](?:が|で)|"
                               r"売却値段を競る|無料で査定|十数万円も差|業社の登録数|"
                               r"買取り店を一軒ずつ|業社が競って|査定額を比較")
        if (bool(re.search(r"(?:廃品回収|不用品回収|リサイクル).{0,30}(?:お探し|情報|こちら)", page_header))
                and distinct(appraisal, text) >= 5 and text.count("一括査定") >= 4
                and not re.search(r"市役所|ごみ処理券|粗大ごみ受付|自治体の回収|収集日程|集積所", text)):
            reasons.append("encoded-locality-page-with-reused-appraisal-copy")
    if (path.endswith((".asp", ".cgi", ".shtm")) and re.search(r"熱い販売|激安価格で通販", head)
            and "公式サイトへようこそ" in head and re.search(r"楽天最安値|送料無料", head)
            and len(re.findall(r"[。 ](?:は|の|に)(?:\d+|で|に|と|すると)|(?:の|を)となって|のとしてを", text)) >= 3):
        reasons.append("machine-generated-storefront-grafted-onto-damaged-prose")

    if (ROUTE_PRICE_CODES.fullmatch(path) and distinct(SHIPPING_QUOTE, head) >= 4
            and HEAVY_KEYWORD_TAIL.search(tail)
            and len(re.findall(r"[一-龯]{2,10}(?:県|府|都|海道)(?:から|まで|へ)", head)) >= 4):
        reasons.append("regional-shipping-quote-template-with-search-keyword-tail")
    if (NUMBERED_SNIPPET_ROUTE.fullmatch(path) and len(re.findall(r"[•►♦]", text)) >= 5
            and len(set(DETACHED_SENTENCE_NUMBER.findall(text))) >= 3):
        reasons.append("generated-numbered-search-collage-with-list-debris")
    if match := SEO_QUERY_TITLE.match(head):
        query = match["seed"]
        if (len(query) >= 12 and text.count(query) >= 4
                and len(QUERY_SLOT_BREAKS.findall(text)) >= 3
                and re.search(r"\.(?:html?|php)$", path)):
            reasons.append("search-query-inserted-repeatedly-into-malformed-prose")
    if (GAMBLING_DOORWAY.search(path) and distinct(BETTING_KEYWORDS, head[:210]) >= 4
            and len(BETTING_KEYWORDS.findall(text[250:])) <= 2 and distinct(MEDIA_CREDIT, text) >= 2):
        reasons.append("gambling-keywords-grafted-onto-event-report")

    if DIARY_DATE_ROUTE.fullmatch(path) and DIARY_TEMPLATE_MARKS.search(head[:110]):
        questions = [line for line in text.splitlines() if 8 <= len(line) <= 70 and line.endswith(("?", "？"))]
        if (len(questions) >= 6 and distinct(QUESTION_LEADS, "\n".join(questions)) >= 4
                and len(text) <= 2200 and sum(line.endswith(("。", "!", "？", "?")) for line in text.splitlines()) >= 13):
            reasons.append("dated-faux-diary-with-unrelated-question-chain")
    if (slot := STATION_DATING_SLOT.match(text)) and slot[0] in path and text.count(slot[0]) >= 4:
        if distinct(FLIRTY_REFERRAL, text) >= 3 and re.search(re.escape(slot[0]) + r"(?:の仲介|で悩|の気持ち|系アプリ)", text):
            reasons.append("station-query-pasted-into-generic-dating-copy")
    if (NUMBERED_SNIPPET_ROUTE.fullmatch(path) and len(TRANSLATED_SPORT_FAQ.findall(text)) >= 3
            and len(MALFORMED_SPORT_TERMS.findall(text)) >= 2):
        reasons.append("generated-sports-faq-assembled-from-broken-translations")
    if (SUSPECT_CATALOG_ROUTE.fullmatch(path) and distinct(CATALOG_SPECS, text) >= 5
            and len(CATALOG_UNITS.findall(text)) >= 7 and "■サイズ" in text):
        reasons.append("retail-catalog-copy-under-generated-file-route")

    if (AFFILIATE_CATALOG_ROUTE.fullmatch(path) and len(INCOME_PITCH.findall(head)) >= 7
            and distinct(DIARY_ISLAND, tail) >= 2):
        reasons.append("generated-income-pitch-padded-with-diary-fragments")
    if distinct(COMMERCIAL_CARE, head) >= 3 and distinct(SYNONYM_COLLISIONS, text) >= 2:
        reasons.append("wellness-product-pitch-with-multiple-semantic-substitutions")
    if (UPLOADED_NUMBERED_PAGE.fullmatch(path) and len(MANGLED_PRICE_FIELD.findall(head)) >= 3
            and tail.count("「") >= 3 and not MANGLED_PRICE_FIELD.search(tail)
            and (tail.count("。」") >= 2 or "《" in text[500:])):
        reasons.append("corrupted-price-list-grafted-onto-dialogue")
    if (re.fullmatch(r"/[a-z]{2,20}\d{3,10}\.html?", path)
            and len(EMPTY_CITATION_SLOT.findall(text)) >= 3
            and len(set(DETACHED_SENTENCE_NUMBER.findall(text))) >= 4):
        reasons.append("encyclopedic-collage-with-erased-citation-fields")
    if (re.fullmatch(r"/\d{3,9}/?", path) and len(text) >= 640
            and QUESTION_BOUNDARY.search(text)
            and len(QUESTION_AUTHOR.findall(text)) >= 2
            and len(re.findall(r"20\d{2}/\d{1,2}/\d{1,2}\s+\d{1,2}:\d{2}", text)) >= 4):
        reasons.append("unlabelled-question-and-answer-scrape-with-thread-seams")
    if (MISSING_PROFILE_FIELD.search(head) and distinct(PROFILE_FIELDS, head) >= 3
            and distinct(PROFILE_OUTLINK, text) >= 4
            and (BROKEN_PROFILE_HEADING.search(text)
                 or len(re.findall(r"(?m)^.{2,50}(?:です|ます|ない)[かのよ]?[?？♪][ \t]*$", tail)) >= 4)):
        reasons.append("empty-profile-fields-with-multiple-unattributed-voices")
    if (len(text) < 1400 and all(pattern.search(text) for pattern in SCRIPTED_TESTIMONIAL_CUES)
            and re.search(r"(?:^|&)p=\d+(?:&|$)", address.query)):
        reasons.append("manufactured-testimonial-with-search-keywords-and-scripted-objection")
    if (distinct(SPLICED_LISTING_FIELDS, head) >= 4 and not SPLICED_LISTING_FIELDS.search(tail)
            and len(DISLOCATED_FRAGMENT.findall(tail)) >= 2 and len(text) <= 1700):
        reasons.append("resale-listing-grafted-onto-unrelated-fragments")
    if (re.fullmatch(r"/[a-z]{2,30}\d{3,10}\.html?", path, re.I)
            and distinct(COLLAGE_MARKERS, text) >= 4
            and len(set(DETACHED_SENTENCE_NUMBER.findall(text))) >= 3):
        reasons.append("numbered-excerpts-with-unrelated-editorial-markup")
    if (REMOTE_RETAIL_ROUTE.fullmatch(path) and len(text) <= 2700
            and CATALOG_SCRAPE_HEADER.search(head[:200])
            and distinct(CATALOG_REVIEW_VOICE, tail) >= 3
            and re.search(r"(?im)^(?:[0-9]{1,2}\s+[a-z][a-z -]{3,30}|[^\n|]{2,30}[|｜][^\n|]{2,30}[|｜])", text)):
        reasons.append("retail-record-on-generated-route-with-pasted-review")
    if (re.search(r"/(?:blog-)?entry-\d+\.html?$", path) and len(text) <= 1200
            and distinct(SALES_FOOTER_OUTLINE, tail) >= 2
            and len(OLDER_BLOG_ALIAS.findall(text)) >= 2):
        reasons.append("commercial-keyword-split-over-repeated-blog-template-fields")
    if (400 <= len(text) <= 20000 and TEXT_JOIN_FIELDS.search(text)
            and distinct(MALFORMED_MEDIA_ACTION, text) >= 3
            and len(re.findall(r"(?:無料|公式サイト|放送|ドラマ|テレビ|出演|主題歌)", text)) >= 15):
        reasons.append("media-graft-with-names-and-metadata-rewritten-as-verbs")
    if (distinct(PROFILE_CARD, head) >= 5 and distinct(AGE_GATE_PITCH, tail) >= 3
            and len(re.findall(r"(?m)^\s*[↓→]{3,}", head)) >= 1
            and re.search(r"\d{4,9}/?$", path)):
        reasons.append("bulk-profile-card-with-repeated-signup-instructions")
    if (EMPTY_BIRTH_DATE.search(head) and len(set(CATALOG_PROFILE_IDS.findall(text))) >= 3
            and len(re.findall(r"(?:作品ページ|作品紹介|商品ページ|主演|出演作品)", text)) >= 3
            and len(re.findall(r"(?:さん|ちゃん)(?:の|が|を)", text)) >= 4):
        reasons.append("incomplete-profile-with-grafted-product-blurbs")
    if (re.search(r"/[a-z][a-z0-9]{3,20}/[a-z]+(?:id[-_]?|-)\d{3,9}/?$", path, re.I)
            and distinct(PITCH_CONTAMINATION, text) >= 3):
        reasons.append("generated-article-with-repeated-semantic-and-grammar-breaks")
    if (re.search(r"\.(?:cgi|php|html?)$", path) and text.count("...") >= 7
            and len(SNIPPET_TIMESTAMPS.findall(text)) >= 3
            and len(SEARCH_RESULTS_BOUNDARY.findall(text)) >= 3):
        reasons.append("clipped-search-snippets-pasted-into-article-slot")
    if (len(text) <= 3900 and distinct(WELLNESS_PITCH_STUMBLE, text) >= 3
            and distinct(COMMERCIAL_CARE, text) >= 3
            and re.search(r"<a\s+href|(?:公式サイト|相談|クリニック).{0,12}こちら", tail)):
        reasons.append("wellness-promotion-with-repeated-grammatical-slot-errors")
    if (GENERATED_LISTING_PATH.fullmatch(path) and len(re.findall(r"\d{3,}", path)) >= 2
            and len(re.findall(r"(?m)^\|[^\n|]{2,16}\|\|", text)) >= 4
            and distinct(PURCHASE_DELIVERY_BOILERPLATE, tail) >= 3):
        reasons.append("marketplace-record-and-checkout-boilerplate-on-generated-permalink")
    if (IRREGULAR_KEY_SEGMENT.search(path) and re.search(r"/20\d{2}/\d{2}/\d{2}/", path)
            and len(path) >= 60 and len(text) < 2300
            and len(re.findall(r"[一-龯]{2,10}\([ぁ-ゖァ-ヺA-Za-z]{2,28}\)", text)) >= 4
            and len(re.findall(r"(?m)^(?:一般に|現在|すなわち|また、|つまり|このような)", text)) >= 2):
        reasons.append("encyclopedic-extract-on-generated-dated-route")
    if (not path.strip("/") and 650 <= len(text) <= 5800
            and sum(distinct(topic, text) >= 2 for topic in TOPIC_COLLAGE_SECTIONS) >= 5
            and sum(len(line) >= 190 for line in text.splitlines()) <= 1
            and not re.search(r"(?m)^(?:新着|更新情報|ブログ一覧|ニュース一覧|関連記事)|\b20\d{2}[/-]\d{1,2}[/-]\d{1,2}\b", text)):
        reasons.append("headingless-homepage-collage-of-unrelated-commercial-copy")
    if (re.search(r"(?:^|&)(?:keyword|query|searchword)=", address.query)
            and len(re.findall(r"(?:…|\.{3})\s*more\b", text, re.I)) >= 2
            and len(re.findall(r"[。！？]\s*(?:20\d{2}年|\S{2,12}によると)", text)) >= 3):
        reasons.append("search-keyword-page-with-detached-copied-news-passages")
    if (distinct(SLOT_GAMBLING, head) >= 3 and distinct(SPORTS_COMPETITION, text[500:]) >= 4
            and len(ARTICLE_VOICE_LIST.findall(tail)) >= 3 and not SPORTS_COMPETITION.search(head[:230])):
        reasons.append("unrelated-sports-report-in-scripted-gambling-testimonials")
    if (len(text) <= 1400 and (shell := TRACKBACK_SHELL.search(head))
            and "コメントの投稿" in head[:shell.start()] and head[:shell.start()].count("。") <= 2
            and re.search(r"(?im)^\s*\|?\s*HOME\s*\|?\s*$", tail)
            and TRACKBACK_CONTENT.search(text[shell.end():])):
        reasons.append("empty-blog-entry-with-external-trackback-snippet")
    if (address.query and re.search(r"\.(?:php|cgi|aspx?)$", path) and 1200 <= len(text) <= 9000
            and distinct(TOOL_LOOKUP, head[:350]) >= 3 and QUERY_DATA_CREDIT.search(tail)
            and len(ALTERNATING_QA_VOICES.findall(text[500:])) >= 3
            and len(re.findall(r"(?m)^.{10,120}[?？]\s*$", text[500:])) >= 3):
        reasons.append("data-lookup-shell-with-unattributed-question-excerpts")
    if (500 <= len(text) <= 3800 and (start := DATED_DIARY_START.search(text))
            and 180 <= start.start() <= 1300
            and distinct(REFERRAL_PITCH, text[:start.start()]) >= 3
            and distinct(MUNDANE_DIARY, text[start.end():]) >= 4
            and not REFERRAL_PITCH.search(text[start.end():])):
        reasons.append("referral-pitch-before-unrelated-first-person-diary")
    if (len(text) >= 1200 and distinct(APPRAISAL_PITCH, head) >= 3
            and distinct(APPRAISAL_PITCH, tail) >= 3
            and any(line in tail for line in head.splitlines()[:4]
                    if 16 <= len(line) <= 110 and "一括査定" in line)
            and re.search(r"(?m)^引用\s*[:：]\s*https?://", text[350:-350])):
        reasons.append("repeated-appraisal-doorway-around-attributed-compilation")
    if (re.search(r"^/(?:category|tag|topics?)/[^/]+/?$", path) and 900 <= len(text) <= 7500
            and sum(bool(pattern.search(text)) for pattern in PROMOTIONAL_TANGENTS) >= 4
            and len(re.findall(r"(?m)^.{5,60}[。！？!]$", text)) >= 14
            and not re.search(r"(?m)^(?:新着|更新情報|ブログ一覧|ニュース一覧|関連記事)|\b20\d{2}[/-]\d{1,2}[/-]\d{1,2}\b", text)):
        reasons.append("commercial-tangents-in-headingless-topic-archive")
    dated_archive = re.search(r"(?:^|&)(?:m|date|day)=20\d{6}(?:&|$)", address.query)
    if (dated_archive
            and len(text) >= 1500 and distinct(re.compile(r"成分|配合|美容液|スキンケア|サプリメント"), text) >= 4
            and distinct(re.compile(r"即日支給|バイト代|副業|面接なし|お仕事情報|エージェントサービス"), text) >= 4
            and len(re.findall(r"(?m)^(?:[・▼]|.{0,45}(?:税込|送料無料|お試しください))[^\n]*$", text)) >= 6
            and not re.search(r"(?m)^(?:広告について|掲載広告のご案内|メディア掲載|ニュース一覧)", head)):
        reasons.append("dated-archive-interleaving-unrelated-commercial-campaigns")
    if (dated_archive and 1300 <= len(text) <= 10000
            and all(distinct(category, text) >= 4 for category in DIVERGENT_PRODUCTS)
            and len(re.findall(r"(?m)^(?:価格\s*[:：]|■内容量|税込[0-9,]+円)", text)) >= 5
            and not re.search(r"(?m)^(?:カタログ|ギフトカタログ|掲載商品|まとめ記事|総合通販)", head)):
        reasons.append("dated-archive-interleaving-incompatible-retail-categories")
    if (re.search(r"/(?:detail|item|products?)/[^/]+", path) and 550 <= len(text) <= 6500
            and max(Counter(CATALOG_REVIEW_TIME.findall(text)).values(), default=0) >= 3
            and distinct(CATALOG_REVIEW_DISTORTIONS, text) >= 3
            and distinct(re.compile(r"価格|デザイン|送料|物流|配送|実用品|材質|取引先|注文"), text) >= 5):
        reasons.append("distorted-product-review-burst")
    if (re.fullmatch(r"/[^/]{4,30}/[A-Za-z]{4,24}\d{5,12}\.html?", path)
            and re.search(r"(?im)^https?://[^ \n]+/(?:wp-content|uploads)/[^ \n]+(?:logo|header)[^ \n]*\b", head)
            and distinct(re.compile(r"祝[！!]|タイムリー|逆転|本塁打|試合|優勝|選手"), head[:250]) >= 3
            and distinct(re.compile(r"商品説明|製品です|ブランド|ミリリットル|観葉植物|仕様|ご使用"), text[130:]) >= 4):
        reasons.append("unrelated-brand-assets-on-generated-product-route")
    if (re.search(r"/[A-Za-z0-9-]+\.(?:com|net|org|jp|info)/20\d{2}/\d{2}/\d{2}/\d{6}/?$", path)
            and re.search(r"(?:coreserver\.jp|xrea\.(?:jp|com)|[A-Za-z0-9-]+\.host\.)$", address.hostname or "")
            and len(text) <= 1700 and distinct(re.compile(r"使用後|置き換え|美容成分|減量|継続中|購入して|モデルさん|ダウン"), text) >= 4
            and re.search(r"\d[日週間].{0,14}\d[キｋk]|[0-9]\s*キロ", text)):
        reasons.append("stitched-testimonials-on-nested-expired-domain-route")
    if (re.fullmatch(r"/(?:place|places|spot|spots)/\d+/?", path) and 260 <= len(text) <= 1900
            and sum(len(line) >= 28 for line in text.splitlines()) >= 6
            and distinct(re.compile(r"カフェ|パン屋|レストラン|焼きそば|ランチ|蕎麦屋|中国料理|料理|ステーキ|カレー|"
                                    r"コースメニュー|薬膳|プレートメニュー|やきとん|おでん|居酒屋|トンカツ|コーヒー"), text) >= 4
            and re.search(r"散髪台|美容院|社交ダンス|車検整備|ピアノ教室|運転免許|物件探しで|クラシックバレエ|マッサージやフェイシャル", text)
            and not re.search(r"営業時間|電話番号|住所[：:]|最寄り駅|アクセス[：:]|掲載店舗", text)):
        reasons.append("anonymous-business-blurbs-mixed-on-single-place-id")
    if (re.search(r"^/【(?:社会|経済|政治|速報|国際|国内)】", path)
            and re.search(r"(?m)[。！][(（][一-龯々]{3,7}[)）][ \t]*$", text[:2600])
            and re.search(r"(?m)^<[^>\n]{3,30}>.{45,220}$", text)
            and sum(3 <= len(line) <= 46 for line in text.splitlines()[-18:]) >= 10
            and not re.search(r"\b(?:引用元|配信元|記事提供|共同通信|転載許可|写真提供)\b|提供[:：]", text)):
        reasons.append("unattributed-reprinted-report-with-detached-forum-replies")
    if (re.fullmatch(r"/(?:archives/)?\d{3,8}/?", path) and 350 <= len(text) <= 2000
            and re.search(r"^.{0,22}(?:こんにちは|こんばん[はわ])[^。\n]{0,14}\n", head)
            and len(re.findall(r"(?m)^.{6,85}(?:ですか|でしたっけ|ましたっけ|ますか|だろう)[?？。]$", text)) >= 5
            and distinct(re.compile(r"買って|出演を依頼|列車|乗りっぱなし|コラムニスト|出題|制限時間|チェーンメール"), text) >= 4
            and not re.search(r"質問[：:]|回答[：:]|Q\s*[1-9][.：:]|面接試験", text)):
        reasons.append("unrelated-question-sequence-in-pseudo-diary")
    if (re.search(r"/(?:article|news)/(?:20\d{6}[-_]?)?\d{4,10}/?$", path)
            and len(text) >= 440 and sum(bool(re.fullmatch(
                r"[\w 　]{3,45}(?:パチンコ|スロット|カジノ|かじの)[\w 　]{0,45}", line))
                for line in text.splitlines()) >= 2
            and distinct(re.compile(r"原作による|声優|追加キャスト|役で|アフレコ|放送されて|製作委員会"), text) >= 4
            and not re.search(r"タイアップ|コラボ|機種化|パチスロ版|パチンコ化", text)):
        reasons.append("standalone-gambling-keywords-in-republished-entertainment-news")
    if (re.search(r"/(?:search|query)/[^/]*\+[^/]+", path, re.I)
            and not re.search(r"(?m)^(?:検索結果|検索条件|関連動画|記事一覧|カテゴリー|結果を表示)", head)
            and len(text.splitlines()) >= 14
            and sum(22 <= len(line) <= 135 for line in text.splitlines()) * 5 >= len(text.splitlines()) * 4
            and sum(len(line) >= 145 for line in text.splitlines()) <= 1
            and distinct(re.compile(r"シーン|出演|主演|レビュー|サンプル|動画|ダウンロード|マッサージ|"
                                    r"水着|女優|全裸|エロ|フェラ|口説"), text) >= 4):
        reasons.append("unlabeled-snippet-only-search-doorway")
    if (re.search(r"/(?:e/)?[0-9a-f]{24,}/?$", path, re.I)
            and re.match(r"【[^】\n]{2,14}=[一-龯々]{3,7}】", head)
            and 850 <= len(text) <= 8000
            and len(re.findall(r"(?m)^[^。\n]{7,42}$", text[300:])) >= 2
            and re.search(r"(?:の取材に応え|に応じた取材|の記事は続)", text[350:])
            and not re.search(r"(?m)^(?:引用|参考|転載|一部抜粋|以下の記事|出典)|^\s*https?://", text)):
        reasons.append("distinct-unattributed-news-voices-under-one-blog-entry")
    if (re.search(r"/(?:profile|writer-profile|about-author|about-us)/?$", path, re.I)
            and len(text) <= 2400 and "自己紹介" in text
            and distinct(re.compile(r"運営者|年齢|得意分野|依頼数|ご依頼|アドバイス"), text) >= 4
            and distinct(PROFILE_EMPTY_SLOT, text) >= 3):
        reasons.append("writer-profile-with-multiple-erased-grammar-slots")
    if (re.search(r"(?m)^アクセスキーワードコンテンツ[ \t]*$", head)
            and re.search(r"(?m)^オフィシャルサイト[ \t]*$", head)
            and len(re.findall(r"(?im)^.{2,25}\s+[\d,]+\s+view[ \t]*$", tail)) >= 4
            and re.search(r"もっとランキングを見る|RSSリーダーで購読", tail)):
        reasons.append("keyword-ranking-doorway-with-generic-content")
    if (re.search(r"[A-Za-z]{2,}\d{3,}[A-Za-z0-9-]{0,10}\d{3,}", path)
            and distinct(re.compile(r"在庫|材質|販売価格|商品番号|製造年|タイヤサイズ|外寸|完成品|受注生産|代金引換|銀行振込"), text[:600]) >= 4
            and (len(re.findall(r"(?m)^\s*※[^。\n]{2,35}は\s*【\s*】", text)) >= 2
                 or (distinct(re.compile(r"標準使用|サロンで|ヘアエステ|ヘアアイロン|ヘアドライヤー|髪のダメージ"), tail) >= 3
                     and not re.search(r"サロン|美容室|ヘア", head[:300])))):
        reasons.append("generated-catalog-route-with-empty-fields-or-unrelated-storefront")
    if (path.lower() in {"", "/", "/index.html", "/index.htm"} and 850 <= len(text) <= 5000
            and (switch := re.search(r"(?m)^.{1,22}(?:引っ?越し|転居).{2,26}\d{1,2}年前\s*$", text))
            and distinct(MOVING_RECOUNT, text[:switch.start()]) >= 3
            and distinct(MOVING_RECOUNT, text[switch.end():]) >= 3
            and len(set(re.findall(r"[一-龯々ヶ]{2,6}[県市]", text))) >= 5
            and not re.search(r"(?m)^(?:お客様の声|体験談一覧|回答|レビュー|寄稿者|関連する記事)", head)):
        reasons.append("unattributed-moving-testimonial-collage-on-homepage")
    if (re.search(r"/(?:yougoshu|yogoshu|glossary)/[a-z][a-z-]{6,}/?$", path, re.I)
            and re.search(r"(?:museum|bahn|railway|terrarium|ornitholog|zoolog)", address.hostname or "", re.I)
            and distinct(re.compile(r"通貨|ドル安|資源国|商品市況|為替|新興国|株価|国債"), text) >= 5
            and len(re.findall(r"どうように、|というのも背景にあります|(?:一般的|当たり前|言葉|側面)になります|から明白になります", text)) >= 3):
        reasons.append("rewritten-finance-glossary-on-unrelated-venue-domain")
    if (re.search(r"/(?:remembering|in-memory-of|tribute-to)-[a-z-]{7,}/?$", path, re.I)
            and len(text) <= 3800 and distinct(re.compile(r"コミュニティ|責任者|お悔やみ|お見舞い|亡くなりました|死亡記事"), text) >= 5
            and distinct(re.compile(r"(?<![A-Za-z])[A-Z][a-zA-Z]{4,}(?![A-Za-z])"), text) >= 4
            and distinct(re.compile(r"私たち自身の[一1]人|ザ・ [A-Za-z]|我々のパーツ|私たちのパーツ|証拠の連祷|機会をつかみ提供"), text) >= 2
            and not re.search(r"(?m)^(?:翻訳|掲載元|転載元|引用|出典)", text)):
        reasons.append("garbled-corporate-obituary-without-translation-credit")
    if (re.search(r"^/(?:offers|recruit|jobs|kyujin|shops)/(?:[a-z-]+/){1,3}[a-z-]+/?$", path, re.I)
            and re.search(r"(?m)^(?:該当(?:する)?求人情報|条件に合う求人|該当する案件|該当企業)(?:は|が)見つかりませんでした[。.\s]", head[:200])
            and 230 <= len(text) <= 3300
            and distinct(re.compile(r"特産[品物]|名所|人口|自治体|平方キロメートル|伝統工芸|文化財|"
                                    r"市政|地ビール|農産品|市営|鉄道|新市|ご当地|古墳|遺跡|特産品"), text) >= 3
            and not re.search(r"(?m)^(?:募集要項|採用条件|こんな求人|別の求人|求人タイトル|応募する|[|｜]職種)", text)):
        reasons.append("empty-regional-job-results-padded-with-tourism-copy")
    if (re.fullmatch(r"/shops/(?:[a-z-]+/){1,3}[a-z-]+/?", path, re.I)
            and re.match(r"ダウンロード\s*ダウンロードダウンロード\s*【検索条件】\s*"
                         r"(?:業種[:：][^\n]{2,40}\n)?該当企業は見つかりませんでした。", text)
            and distinct(re.compile(r"名所|景勝|観光|文化財|史跡|公園|寺院|博物館"), text) >= 2
            and distinct(re.compile(r"職人|工事|作業主任者|技能士|土工|建設会社|住宅設備|建築板金"), text) >= 2):
        reasons.append("empty-contractor-search-with-repeated-download-and-generic-city-text")
    if (re.search(r"/[^/]{1,12}/ASIN\.[A-Z0-9]{8,14}\.[A-Z]{1,5}\.[A-Za-z0-9-]{2,8}$", path, re.I)
            and distinct(re.compile(r"独立した規約|データ収集規定|いかなる義務や責任|パスワードや登録情報|オンライン接続"), head) >= 4
            and re.search(r"(?m)^[^\n]{0,16}日記[ \t]*$", text[120:])
            and not re.search(r"著者[:：]|商品説明|カスタマーレビュー|出版社[:：]", text)):
        reasons.append("catalog-suffix-route-with-detached-legal-and-diary-copy")
    if (re.search(r"^/(?=[a-z\d]{7,16}/)(?=[^/]*[a-z])(?=[^/]*\d)[a-z\d]+/20\d{2}/\d\d/\d\d/[^/]+-\d{1,3}/?$", path)
            and 650 <= len(text) <= 4500
            and len(re.findall(r"[一-龯々]{2,14}\s*\([ぁ-ゖァ-ヺ]{2,18}\)", text)) >= 5
            and len(re.findall(r"(?m)^\s*[・.]\s*$", tail)) >= 4
            and not re.search(r"(?m)^(?:出典|参考文献|関連する論文|執筆者)", text)):
        reasons.append("opaque-dated-glossary-with-duplicated-paraphrase-layout")
    if ((address.hostname or "").startswith("ja.")
            and re.fullmatch(r"/\d{1,6}-(?:[a-z0-9]+-){3,16}[a-z0-9]+(?:\.html?)?/?", path, re.I)
            and 700 <= len(text) <= 11000
            and not re.search(r"(?m)^(?:翻訳|著者|執筆|校閲|出典|原文|公式ドキュメント)", head)):
        imported_prose_damage = (
            re.compile(r"枯れた(?:場所|ところ)|血液注入|ヒ素の血|大型車の祖先|鋼の子孫|現代の武器祖先"),
            re.compile(r"押して(?:Ctrl|Alt|Shift|Windows)|を更新してを参照|(?<![A-Za-z])s0を実行|"
                       r"マネージャ(?:ー)?そこから|プロセスが.?完了される|してくださいして"),
            re.compile(r"オフロードした|インデックスが重い|遅れの中に立って|ペースにアクセスする|ローカルインデックス"),
        )
        if any(distinct(pattern, text) >= 3 for pattern in imported_prose_damage):
            reasons.append("localized-import-with-repeated-semantic-translation-breaks")
    if (re.fullmatch(r"/(?:archives/)?\d{2,9}\.html?", path)
            and (switch := re.search(r"(?m)^[^\n]{5,40}(?:生活シーンを変えるかも|あなたの暮らしを変える)[♪！!]?[ \t]*$", text))
            and 300 <= switch.start() <= 3200
            and distinct(re.compile(r"ヨガ|瞑想|観光|民宿|レンタカー|ご宿泊|送迎"), text[:switch.start()]) >= 4
            and distinct(re.compile(r"調教師|帰厩|牝馬|牡馬|競馬|坂路|ハロン"), text[switch.end():]) >= 5
            and re.search(r"(?m)^(?:どうもこんばんは|皆さんこんばんは|おはようございます)[！!\s]*$", text[switch.end():])):
        reasons.append("travel-diary-spliced-to-racing-report-at-keyword-boundary")
    return reasons


def directory_location_conflict(raw, url):
    """Keep the directory listing and mark only a description that contradicts its address."""
    if "/otera/" not in url:
        return None
    try:
        path = unquote(urlsplit(url).path)
    except ValueError:
        return None
    if not TEMPLE_DIRECTORY_ROUTE.fullmatch(path):
        return None
    footer = DIRECTORY_FOOTER.search(raw)
    listing = TEMPLE_LISTING.search(raw)
    if not listing and not footer:
        return None
    from spam_regional_specialist import prefectures

    known = prefectures()
    actual = {match[1] for match in ADDRESS_PREFECTURE.finditer(listing[0]) if match[1] in known} if listing else set()
    if footer and re.search(r"(?m)^[|｜]交通アクセス", raw[:footer.start()]):
        desc = raw[footer.end():]
        title = raw.splitlines()[0].removesuffix("について").strip()
        if 3 <= len(title) <= 40 and title in desc[:100]:
            named_pref = re.search(re.escape(title) + r"は、?([一-龯]{2,4}[都道府県])[一-龯]{1,12}[市郡区町村]", desc)
            if ((len(actual) == 1 and named_pref and named_pref[1] in known - actual)
                    or (len(desc) >= 150 and desc.count(title) >= 2 and distinct(TEMPLE_FILLER, desc) >= 3)):
                return footer.end(), len(raw)
    if not listing:
        return None
    descriptions = list(DESCRIPTION_PREFECTURE.finditer(raw, listing.end()))
    claimed = {match["pref"] for match in descriptions if match["pref"] in known}
    if len(actual) == 1 and claimed and actual.isdisjoint(claimed):
        return next(match.start() for match in descriptions if match["pref"] in claimed), len(raw)
    return None

def distinct(pattern, text):
    return len(set(pattern.findall(text)))


def lexical_template_findings(raw, url="", *, normalized=None):
    """Return blocking spans for corroborated lexical campaigns and review footers."""
    text = normalize(raw) if normalized is None else normalized
    head = text[:600]
    findings = {}
    campaigns = (
        ("rewritten-used-car-appraisal-campaign", "一括査定" in text and text.count("査定") >= 4,
         APPRAISAL_CAMPAIGN),
        ("rewritten-water-delivery-campaign", "ウォーターサーバー" in text, WATER_DELIVERY_CAMPAIGN),
        ("rewritten-matchmaking-campaign", "結婚紹介所" in text, MATCHMAKING_CAMPAIGN),
    )
    for name, has_topic, signatures in campaigns:
        if has_topic and sum(bool(pattern.search(text)) for pattern in signatures) >= 3:
            findings[name] = [(0, len(raw))]
    if ("で看護師の転職をお考えの方、看護師求人情報の基礎知識を紹介します。" in head
            and text.rstrip().endswith("看護師求人登録サイト・転職ホームページの紹介でした。")):
        findings["municipality-nurse-recruitment-doorway"] = [(0, len(raw))]
    if ("で外壁塗装工事・外壁改修を検討している方に外壁塗装・屋根塗装の優良業者紹介サービスを紹介します。" in head
            and "ネットで簡単に概算見積もりが複数の買取会社から取れる" in head):
        findings["municipality-exterior-painting-doorway"] = [(0, len(raw))]
    if "主観的なご" in raw:
        spans = [match.span() for match in REVIEW_ATTRIBUTION_FOOTER.finditer(raw)
                 if match.start() >= max(0, len(raw) - 1600)]
        if spans:
            findings["review-platform-attribution-boilerplate"] = spans
    for name, context, template in REPEATED_PAGE_BOILERPLATE:
        if context in raw:
            spans = [match.span() for match in template.finditer(raw)]
            if spans:
                findings[name] = spans
    for name, patterns in CORROBORATED_PAGE_TEMPLATES:
        if all(pattern.search(text) for pattern in patterns):
            findings[name] = [(0, len(raw))]
    if (re.match(r"(?:無理な髪を洗うこと|無茶苦茶な洗髪|強引な頭皮を洗うこと)", head)
            and re.search(r"(?:対策|対応)に.{0,30}動き出せない|対応に開始しようと決定", text)
            and re.search(r"(?:薬の処方箋|薬のレシピ|ドラッグのレシピ)を(?:手渡|渡)", text)):
        findings["rewritten-regional-hair-loss-campaign"] = [(0, len(raw))]
    if (re.search(r"(?:%20|\s)20\d{2}/?$", re.split(r"[?#]", url, maxsplit=1)[0])
            and re.search(r"(?m)^sitemap 0\s+sitemap 1\s+sitemap 2\s+sitemap 3\s+sitemap 4", text[-350:])
            and re.search(r"(?m)^sitemap 11\s+sitemap 12\s+sitemap 13\s*\Z", text[-350:])):
        findings["generated-year-slug-with-numbered-sitemap-farm"] = [(0, len(raw))]
    no_results = "No results were found that match your search criteria."
    if "Search results " in head or no_results in head:
        try:
            address = urlsplit(url)
        except ValueError:
            address = None
        if address and address.path.rstrip("/") == "/search" and (
                address.hostname in {"contents.fc2.com", "adult.contents.fc2.com"}
                and no_results in head and len(text.partition(no_results)[2].strip()) >= 400
                or address.hostname == "adult.contents.fc2.com"
                and re.search(r"侍ジャパン全勝で決勝へ.{0,50}特別販売", head)):
            findings["empty-search-shell-with-scraped-articles"] = [(0, len(raw))]
    if (re.match(r"Rated\s+\d/5 based on\s+\d+ customer reviews", head, re.I)
            and re.search(r"©[^\n]{1,65}\.somee\.com\s*\|\s*SiteMap", text[-240:], re.I)):
        findings["synthetic-video-index-with-fake-ratings"] = [(0, len(raw))]
    if "■該当件数1件" in head:
        try:
            address = urlsplit(url)
        except ValueError:
            address = None
        if (address and re.fullmatch(r"/category/organizations-[a-z0-9-]+\.html", address.path)
                and re.search(r"■該当件数1件\s*(?:\|\s*)?1", head)
                and "加圧トレーニング" in text and "船橋競馬場駅" in text):
            findings["generated-business-directory-copy"] = [(0, len(raw))]
    for name in variant_campaign_findings(text, url):
        findings[name] = [(0, len(raw))]
    if promotion := TRADING_REFERRAL_SECTION.search(raw):
        suffix = normalize(raw[promotion.start():])
        if (160 <= len(suffix) <= 1000 and "年間利回り" in suffix
                and len(re.findall(r"[0-9]{2,3}%", suffix)) >= 2
                and "売買の完全自動化" in suffix and re.search(r"挑戦するタイミング|ご案内しています", suffix)):
            findings["reused-automated-trading-pitch-with-return-claims"] = [(promotion.start(), len(raw))]
    if span := directory_location_conflict(raw, url):
        findings["directory-listing-and-generated-description-disagree"] = [span]
    return findings


def page_findings(raw, url):
    """Return pattern IDs with raw offsets. Signals can coexist on one page."""
    text = normalize(raw)
    head = text[:600]
    try:
        address = urlsplit(url)
        path = unquote(address.path)
        host = address.hostname or ""
    except ValueError:
        path, host = "", ""
    bulk_search = host.endswith((".web.app", ".firebaseapp.com", ".somee.com"))
    field_count = distinct(FIELD, text)
    search_count = len(SEARCH_JOIN.findall(text))
    notices = distinct(gate.PROMOTION, text)
    paragraphs = [p.strip() for p in gate.BOUNDARY.split(text) if len(p.strip()) >= 16]
    topics = sum(len(p.findall(text)) >= 3 for p in TOPIC_CLUES)
    findings = lexical_template_findings(raw, url, normalized=text)

    def page(pattern, condition):
        if condition:
            findings[pattern] = [(0, len(raw))]

    page("short-keyword-landing-with-translated-word-salad", composition.short_keyword_word_salad(text, path))
    page("gossip-query-with-mechanically-rejoined-claims", composition.garbled_gossip_query(text, path))
    page("localized-video-with-duplicated-game-prose",
         composition.localized_video_with_duplicated_game_prose(text, path))
    for pattern in composition.composition_findings(text):
        page(pattern, True)
    for pattern in slots.slot_structure_findings(text):
        page(pattern, True)
    relay = relays.relay_pattern(text, path)
    if relay:
        page(relay, True)
    page("unlabelled-neighbouring-venue-cards", venue_structure.mixed_venue_descriptions(text, path))
    page("link-in-word", INLINE_LINK.search(text))
    if 130 <= len(text) <= 850:
        if re.fullmatch(r"/([a-z]{3,22})/\1_\d{1,4}/?", path, re.I):
            locality = re.search(r"(?:^|\n)当サイトでは([^\n。]{2,26}[市区町村])の保育園の", head)
            page("local-nursery-job-landing-with-stitched-search-queries",
                 locality and text.count(locality[1] + "の保育園の") >= 3
                 and "人気の非公開求人を探す" in text
                 and distinct(re.compile(r"求人(?:愛媛|パート名古屋)|"
                                         r"採用情報を検索の情報|もよく検索されています|"
                                         r"その他にも保育士と幼稚園教諭の給料"), text) >= 2)
        if host and path in {"", "/"} and re.fullmatch(r"m=20\d{4}", address.query):
            page("calendar-archive-with-spun-cholesterol-snippets-under-other-topic",
                 bool(re.match(r"妊婦服[^\n]*\n[^\n]*妊婦服", text))
                 and len(re.findall(r"(?m)^20\d{2}/\d{1,2}/\d{1,2}\n未分類$", text)) >= 3
                 and bool(re.search(r"医者に行った時によく耳に入る[「『]コレステロール", text))
                 and bool(re.search(r"医療機関などでよく耳に入ってくる[「『]コレステロール", text))
                 and "記事を読む" in text and text.count("...") >= 3)
    if 90 <= len(text) <= 700 and re.fullmatch(r"/[a-z]{4,10}/\d{3,8}\.html?", path, re.I):
        page("mixed-script-keyword-list-on-anonymous-short-code-route",
             text.rstrip().endswith("评论已关闭!") and text.count("。") <= 1
             and len(re.findall(r"[,、]", text)) >= 9
             and distinct(re.compile(r"中文字|在线|永久|电视|电影"), text) >= 3
             and len(re.findall(r"[ぁ-ゖァ-ヺ]", text)) >= 12 and len(text.splitlines()) <= 8)
    if 450 <= len(text) <= 2300 and re.fullmatch(r"/entry/20\d{2}/\d\d/\d\d/\d{6}/?", path):
        page("housing-promotions-spliced-into-rotating-stock-diary",
             len(text.splitlines()) >= 8
             and sum(bool(re.search(topic, text)) for topic in (
                 r"住宅ローン|展示場|ペットと暮らせる住宅", r"今朝|昨日|今日|昨晩",
                 r"トイプードル|うちの犬|食器洗い乾燥機|リビングに置いているソファ")) == 3
             and ("リビングに置いているソファの買い替えを最近よく考える" in text
                  or distinct(re.compile(r"冷やかしだけど|35年間もこの低金利で固定|"
                                         r"文明の力って言うか、それらを利用すれば|"
                                         r"家で待機していたい気分だよ|住友林業の木達をご存知"), text) >= 3))
    if 230 <= len(text) <= 2400 and re.fullmatch(r"/tag/[A-Za-z](?:\([ぁ-ゖァ-ヺ一-龯가-힣]{1,14}\))?/?", normalize(path)):
        page("short-name-tag-filled-by-an-unrelated-alphabet-entry",
             bool(re.match(r"友達と共有する\n([A-Za-z])は、ラテン文字.{0,22}の\d{1,2}番目の文字", text))
             and "出典:Wikipedia" in text and "新バージョンのまとめ集もCHECK!" in text
             and "の関連商品をチェックする" in text and "のまとめ集が気に入ったら" in text)
    if 180 <= len(text) <= 1000 and re.fullmatch(r"/[^/]{14,120}/?", path):
        renewed_pitch = re.match(r"([^\n]{8,76}?) +の(?:体験者の|評判の)(?:クチコミ|口コミ)に(?:関連して|関する)", text)
        page("rotating-course-review-with-unsupported-stock-endorsement",
             renewed_pitch and text.count(renewed_pitch[1]) >= 3
             and distinct(re.compile(r"期待を裏切らない内容だと確信|著しく噂の的|客観的に見た見解|"
                                     r"最短で解決できる手段なのは当然|これ以上ない道しるべ|"
                                     r"認められている秘密|全体を通したインプレッション|悩みなんて一発解消|"
                                     r"今すぐ行動すべき内容と明言"), text) >= 3
             and bool(re.search(r"知恵袋|教えてgoo|仕事の合間に[^。\n]{2,35}を検索したことで伝えたい", text)))
    if 390 <= len(text) <= 2600 and re.fullmatch(r"/post-\d{2,6}/(?:attachment/\d{2,6}|[a-z]\d{4,8})/?", path):
        page("attachment-page-filled-with-unlabelled-clipped-story-and-quote-fragments",
             bool(re.search(r"(?m)^公開日:\n20\d{2}/\d\d/\d\d\n:\n[\s\S]{16,165}\n記事を読む$", head))
             and text.count("あなたに贈る【感動する話") >= 2
             and "WordPress-Theme STINGER3" in text[-220:]
             and "→もっと見る" in text[-280:]
             and distinct(re.compile(r"余命幾ばくも無い母|夫婦喧嘩の仲直り方法|妻と2 つの約束|"
                                     r"スマホにはお互いに秘密の闇|結婚式に参列していた小さな男の子"), text) >= 3)
    if 130 <= len(text) <= 1100 and re.fullmatch(r"/[^/]{12,140}\.html?", path):
        page("literal-localization-with-broken-content-and-an-unlabelled-download-gateway",
             bool(re.search(r"(?im)^Download Links / リンクをダウンロード\nhttps?://[^/\s]+/file/[^\s]+\.(?:rar|zip)$", text))
             and distinct(re.compile(r"今まで来て:|女の子が[^。\n]{1,15}彼をドラッグ|重さは彼の顔にある間|"
                                     r"古フランス語トイレ|彼のmouning|重さの下で"), text) >= 3)
    if 220 <= len(text) <= 2400 and re.fullmatch(r"/[a-z]{3,12}\d{2,6}/\d{3,7}[a-z]{3,12}\d{8,15}\.html?", path, re.I):
        page("coded-retail-page-with-corrupted-vacuum-product-copy",
             len(re.findall(r"\d+\?(?:mm|in)\b", text)) >= 2
             and distinct(re.compile(r"真空を書いた|吸気ペット|ジュエリーボックスをオン|"
                                     r"チェックアウト真空ホース|ブラシクリーナーを使用.{0,25}真空"), text) >= 2)
    if 320 <= len(text) <= 4200 and path == "/xx/" and re.fullmatch(r"a=/a/20[0-9]{12}\.html", address.query):
        page("search-snippets-glued-to-source-headlines-in-dated-result-page",
             text.startswith("報道によると\n") and "関連画像" in text and "関連情報" in text
             and "関連したネットの声" in text[-200:]
             and len(re.findall(r"(?m)^\d{1,3} 時間前 \.\.\.\s*$", text)) >= 2
             and len(re.findall(r"(?m)^.{6,90} - [^\n]{2,28}$", head)) >= 3)
    if 260 <= len(text) <= 3800 and re.fullmatch(r"/[^/]{8,80}\.html?", path):
        watch_copy_stumbles = re.compile(r"本当に力(?:を振り返る時|に新しい|クロノメーター)|"
                                         r"タブ(?:工場|業の歴史)|(?:製造|海軍|空軍)[^。\n]{0,9}[选军]|"
                                         r"パイロットもさせないケース|鉄栓の指示|600件の機械部品|"
                                         r"幼いころから[^。\n]{1,20}の身柄を手に入れ|"
                                         r"王公貴族に嘆いて")
        page("uncredited-watch-article-with-multiple-literal-translation-errors",
             distinct(watch_copy_stumbles, text) >= 3
             and distinct(re.compile(r"クロノメーター|時計工場|軍用|機械部品|時計と座鐘|腕時計|ゼニス|視認性"), text) >= 3
             and not re.search(r"(?m)^(?:翻訳|訳者|出典|原文|引用元)[:：]", text))
    if 580 <= len(text) <= 4600 and re.fullmatch(r"/ho_[a-z]{3,24}/[a-z]{3,38}/\d{1,5}\.html", path, re.I):
        missing_profile = re.findall(r"(?m)^.{3,55}さんの紹介文はまだありません。\s*$", head)
        page("regional-insurance-directory-empty-profile-filled-with-unrelated-search-copy",
             len(missing_profile) >= 2 and "ネットで独自調査" in text
             and "保険屋リスト事務局" in text[-200:]
             and distinct(re.compile(r"製薬工業|企業経営広報|航空会社取締役|数学の役割|"
                                     r"マイクロエレクトロニクス|株式取引所|【目次】"), text) >= 3)
    if (550 <= len(text) <= 6200 and not host.endswith((".ac.jp", ".edu", ".go.jp", ".lg.jp"))
            and re.fullmatch(r"/news/all/20[0-9]{6}-[0-9]{4,7}/?", path)):
        page("university-press-release-copied-with-script-conversion-and-source-chrome",
             bool(re.match(r"トピックス詳細\(プレスリリース\)\n", text))
             and distinct(re.compile(r"大學|學部|學長|研究結菓|學會|企畫|橫浜市|都筑區|淺層地下水|"
                                     r"社會的貢獻|化學組成|數億年前|取材申し込み\?"), text) >= 6
             and bool(re.search(r"(?m)^用語解説\n用語解説$|^研究の背景\n研究の背景$|^研究成果\n研究成果$", text))
             and "お問い合わせ先" in text[-240:])
    if 450 <= len(text) <= 4500 and re.fullmatch(r"/archives/date/20\d{2}/\d{2}/?", path):
        page("dating-service-archive-with-iterated-profile-fragments",
             len(re.findall(r"\b(?:PCMAX|Jメール|ハッピーメール|わくわくメール)", text)) >= 5
             and bool(re.search(r"(?P<fragment>「(?:裏プロフィール|年齢確認|自己紹介)」や[^。\n]{2,25})(?P=fragment){2,}", text))
             and distinct(re.compile(r"写真を選択したら写真を選択|ポイントがなくな|年齢確認|退会|"
                                     r"書き込みをしておきましょう"), text) >= 4)
    if 310 <= len(text) <= 3200 and re.fullmatch(r"/archives/\d{3,7}/?", path):
        page("standalone-product-specifications-wrapped-around-foreign-exchange-splice",
             all(field in head[:150] for field in ("規格サイズ", "規格色", "重量", "メーカー名"))
             and "規格サイズ" in text[-150:]
             and distinct(re.compile(r"通貨ペア|ポジションをキープ|外国為替|利食い|外為法|大陰線|大陽線"), text) >= 4
             and bool(re.search(r"FX[ \t]*(?:自動売買|システムトレード)[買売]|"
                                r"FX[ \t]*自動売買[ \t]+[A-Z]{2}\d+", text)))
    if 1200 <= len(text) <= 9000 and re.fullmatch(r"/content/\d{4,7}/?", path):
        dated_excerpt = r"(?m)^20\d{2}/\d{2}/\d{2} \d{2}:\d{2}[ \t]*$"
        posts = [post.strip() for post in re.split(dated_excerpt, text) if post.strip()]
        page("numbered-story-page-made-entirely-of-fixed-length-truncated-excerpts",
             bool(re.match(dated_excerpt, text)) and len(posts) >= 8
             and sum(200 <= len(post) <= 320 and post.endswith(("…", "...")) for post in posts) >= len(posts) - 1
             and max(map(len, posts)) < 380
             and not re.search(r"(?m)^(?:検索結果|まとめ記事|小説一覧|カテゴリー|関連記事|投稿リスト|出典[:：])", text))
    if 380 <= len(text) <= 5200 and re.fullmatch(r"/dmm(?:ebk|e?book)-[a-z-]{3,35}\d{4,8}/?", path):
        page("unrelated-featured-video-stamped-on-generated-comics-cards",
             text.startswith("本日のおすすめ動画マンガ『") and "おすすめ電子コミック作品" in head
             and len(re.findall(r"(?m)^\|[^|\n]{3,95}$", text)) >= 3
             and "コミックコミック" in text[-430:] and "立ち読み機能で中身がチェックできます" in text[-200:])
    if 300 <= len(text) <= 2200 and re.fullmatch(r"/[A-Za-z0-9_-]{11}\.html", path):
        voices = re.findall(r"(?m)^■([^\n]{8,125}) - by [^\n]{1,40}$", text)
        page("video-page-with-manufactured-local-voices",
             "動画コメント:" in head and "作成日:" in head and "チャンネル:" in head
             and "動画に関係ないものが表示される場合があります" in head
             and len(voices) >= 4 and sum(bool(re.search(
                 r"(?:学習|学ぶ|調べ|検索).{0,28}(?:結果は|結果が|どうなる|気になる)", voice
             )) for voice in voices) >= 3)
    if 300 <= len(text) <= 1200 and re.fullmatch(r"/date/20\d{2}/\d{2}/\d{2}/?", path):
        stock_answers = re.compile(r"色で例えるには無理|どこかの動物園で見ることはできました|"
                                   r"どこに行けばいいのか教えてもらえると嬉しい|"
                                   r"何かありますか\?|どこにいったら会えるのでしょうか|"
                                   r"アドバイスしようか|何か有名なことがありましたっけ")
        page("daily-archive-with-canned-off-topic-question-and-answer-pairs",
             len(re.findall(r"(?m)^.{8,90}\?$", text)) >= 6
             and distinct(stock_answers, text) >= 2
             and not re.search(r"(?m)^(?:Q\d|Q[.:：]|質問[:：]|寄稿|読者からの質問)", text))
    if 360 <= len(text) <= 3400 and re.fullmatch(r"/t[0-9]{19}/?", path):
        pitch = r"受講者数[\d,]+名を超える業界最高峰のアフィリエイト教材\n[^\n]{10,45}\n「アンリミテッドアフィリエイト[^\n]{0,25}」"
        page("unrelated-affiliate-pitch-bracketing-social-results",
             len(re.findall(pitch, text)) >= 2 and len(text.splitlines()) >= 15)
    if 400 <= len(text) <= 4800 and re.search(r"(?:シェイプアップ|ダイエット|減量)", head):
        rewritten_weight = re.compile(r"\d{2}kgテーブル|\d+kg洗い流す|結果が出たときの潤い|"
                                      r"ウエイト規定をしっかりする|シェイプアップ[^。\n]{2,22}遊戯")
        page("spun-weight-loss-diary-with-unrelated-supplement-affiliate-tail",
             distinct(rewritten_weight, text.lower()) >= 2
             and re.search(r"(?:アスミール|セノビック|ノビルン).{0,45}(?:楽天|セール|通販|購入)", text[-190:]))
    page("exam-code-in-word", any(exam_code(m[1]) for m in INLINE_EXAM.finditer(text)))
    page("exam-ad-in-story", NARRATIVE.search(text) and (
        EXAM_LINK.search(text) or any(exam_code(m[1]) for m in EXAM_AD.finditer(text))
        or re.search(r"\b(?:Exam Dumps|Dumps Questions)\b", text, re.I)))
    page("place-in-katakana", field_count >= 2 and len(gate.SPLIT_KATAKANA.findall(text)) >= 4)
    page("catalog-in-news", distinct(FIELD, head) >= 3 and len(EDITORIAL.findall(text)) >= 4
         and (len(gate.INLINE_PRODUCT.findall(text)) >= 2 or len(gate.MIXED_PRODUCT_CODE.findall(text)) >= 2))
    page("multilingual-brand-query-in-prose", structural.inline_foreign_query_leads(raw))
    page("unrelated-topic-montage", (
        topics >= 3 and (search_count >= 3 or field_count >= 2)
        or len(LOANS.findall(text)) >= 6 and len(LOAN_OFFER.findall(text)) >= 2 and EDITORIAL.search(head)
        or len(EDITORIAL.findall(text)) >= 8 and field_count >= 3
        or topics >= 3 and field_count >= 1 and len(JOIN_DEFECT.findall(text)) >= 1
        or "カジノ" in head and len(TOPIC_CLUES[0].findall(text)) >= 6
        and len(TOPIC_CLUES[1].findall(text)) >= 3 and text.count("カジノリスト") >= 2
        or len(EDITORIAL.findall(text)) >= 6 and "ご入札をお控え" in text and "追加画像が必要" in text))

    if host and re.search(r"(?:^|&)(?:l_name|first_name|last_name)=", address.query):
        page("generated-personalized-reading-with-duplicated-answer",
             len(re.findall(r"(?:^|&)(?:l_name|f_name|first_name|last_name|birth_date)=", address.query)) >= 2
             and bool(re.search(r"(?:字|点)?画数\d+画|生年月日[^。]{0,35}占い", text))
             and (bool(re.search(r"(?m)^\|[^|\n]{10,110}とは[?？]\|\|[^|\n]{15,}", text))
                  or len(re.findall(r"(?:運勢|宿命|運命|天運)[はと].{0,9}[?？]", text)) >= 3
                  and len(re.findall(r"(?:改名|姓名|字画).{0,7}(?:判定|診断|判断)", text)) >= 4)
             and len(re.findall(r"(?m)^- (?:恋愛運|仕事運|健康運|金運|基本運|家庭運)\s*$", text)) >= 2)
    page("machine-import-with-duplicated-age-placeholders",
         bool(re.search(r"X[NXUM]+歳(?:から|〜|~|～|の)X[NXUM]+歳", text, re.I))
         and bool(re.search(r"あなた自身のために.{0,35}あなた自身ではありません|"
                            r"あなたはあなた自身.{0,25}あなたの.{0,35}あなたの", text)))
    page("machine-dream-template-with-malformed-interpretations",
         len(re.findall(r"夢見る(?:ために|こと)|夢見て", text)) >= 5
         and all(re.search(marker, text) for marker in (
             r"現実的な効果と反応|現実の影響と反応",
             r"夢想家の主観的な(?:想像|想像力|想定)",
             r"周りに悪い友達|悪役.{0,20}(?:注意|倒す|誹謗)|夢見るために.{0,12}注意",
         )))
    page("scripted-skepticism-promoting-a-paid-method",
         len(text) <= 1900 and sum(0 < len(line.strip()) <= 40 for line in text.splitlines()) >= 10
         and bool(re.search(r"(?:式|さんの|流)[^。\n]{2,30}(?:プログラム|マニュアル|教材)", text))
         and len(re.findall(r"って体験談にある|実践した人はどう|効果って人によって|"
                            r"そんなうまい話|本当なのかな|でも気になる", text)) >= 4)
    page("dated-archive-with-interleaved-checkout-and-service-pitches",
         bool(re.search(r"(?:^|&)m=\d{8}(?:&|$)", address.query if host else ""))
         and len(text) >= 2500 and len(STORE_COPY.findall(text)) >= 18 and distinct(STORE_COPY, text) >= 6
         and distinct(re.compile(r"配送について|同日内のご注文|商品コード|消費期限|ショッピングカート"), text) >= 3
         and distinct(re.compile(r"査定依頼|不動産会社|会員登録|出会い系|求人情報|"
                                 r"ドッグフード|ペットフード|転職支援|健康食品"), text) >= 5)
    page("repackaged-marketplace-category-ranking",
         bool(re.fullmatch(r"/list/[a-z]+/\d{6,}/?", path, re.I))
         and bool(re.match(r"[^\n]{2,36}の人気ランキング(?:\n|$)", text))
         and len(re.findall(r"(?m)^レーベル:", text)) >= 4
         and text.count("この商品を買った人はこんな商品も買っています") >= 3
         and bool(re.search(r"他サイトでの無断使用を固く禁じ|アマゾン配送センター", text)))

    # Third-party snippets can each read fluently even when the combined page has no article.
    page("scraped-entertainment-scenes-with-inline-pagination",
         len(re.findall(r"(?m)Next\s*$", text)) >= 4
         and len(re.findall(r"『』|\[ \]|Sponsored Links|血液型:", text)) >= 4
         and len(re.findall(r"演じ|俳優|デビュー|第\d+話|ドラマ", text)) >= 5)
    page("keyword-stuffed-fiction-with-seams-and-insertions",
         len(text) <= 3400 and bool(re.match(r"\|[^\n。]{3,40}\|", text))
         and sum(bool(re.search(r"[一-龯ぁ-ゖァ-ヺ] [一-龯ぁ-ゖァ-ヺ]", line))
                 for line in text.splitlines()) >= 12
         and len(re.findall(r"(?m)^[一-龯ぁ-ゖァ-ヺ]{1,8}$", text)) >= 4
         and len(re.findall(r"(?:の|みたい|より) (?:に|で|な|も|[一-龯])|"
                            r"[一-龯ァ-ヺ] (?:は|が|を|に|の|だ)[一-龯ぁ-ゖァ-ヺ]", text)) >= 5)
    page("third-party-app-listing-with-malformed-product-copy",
         bool(re.search(r"/(?:jp|ja)/[^/]+/(?:com|net|org)\.[a-z0-9_.]+/?$", path, re.I))
         and bool(re.search(r"(?m)^キーワード:|マーケットの中で最高の", text))
         and distinct(re.compile(r"写真をりサイズ|キャプチャーしたある|速く来て[^。]{0,40}作品|"
                                 r"このアプリを共用します|ボタンを押して\(\d"), text) >= 2)
    page("product-tag-collection-with-broken-imported-promotional-copy",
         bool(re.search(r"/(?:tags?|topics?)/[^/]+/?$", path))
         and len(re.findall(r"(?m)^\d[\d,]{2,8}円\s*$", text)) >= 3
         and distinct(re.compile(r"日程に[^。]{0,18}を加入|移動的な|十つの|"
                                 r"能力を打ち明けるを通して|形を?実現する|"
                                 r"新しいの[^。]{0,20}革命|ほっそりした、強健な、"), text) >= 3)
    page("translated-technical-mirror-with-literal-product-names",
         bool(re.search(r"/[a-z0-9-]{12,}-\d{10,}/?$", path))
         and distinct(re.compile(r"冥王星の(?:インターフェース|内部)|陪審員はまだ検討中|"
                                 r"走るだけで[―-]|男の写真をダウンロード|"
                                 r"ラウンドは通常次のようになります:あなたが"), text) >= 3
         and len(re.findall(r"プログラミング|ドキュメント|ノートブック|インターフェース", text)) >= 3)
    page("translated-countdown-with-damaged-word-senses",
         bool(re.search(r"/\d{1,2}-(?:things|reasons|ways|facts|details)-", path, re.I))
         and len(re.findall(r"(?m)^\d{1,2}[ \t.、-]*[一-龯ぁ-ゖァ-ヺ]", text)) >= 5
         and len(re.findall(r"見知らぬ人ではないので|胃を回転させ|完璧に釘付け|"
                            r"シリーズの.*勇敢な魂|解放された[ \t]+。|ケーキウォーク|"
                            r"最も挑戦的な偉業の[一1]つです。", text)) >= 3)
    page("machine-rewritten-technical-overview-with-impossible-word-senses",
         len(text) <= 4500 and len(re.findall(r"骨格|石灰質|外骨格|内骨格|節足動物", text)) >= 8
         and distinct(re.compile(r"棘皮動物の石灰性段ボール|ゴールソン[リパ]ン|"
                                 r"脱皮[^。]{0,26}咎を壊|ギュサンジル|外地骨格|"
                                 r"筋肉に[?]{2,}よって"), text) >= 3)
    page("affiliate-dialogue-replaced-by-copied-payment-terms",
         len(re.findall(r"(?m)^[^。\n]{4,45}[?？]\s*$", head)) >= 3
         and len(re.findall(r"公式サイト", head)) >= 2
         and len(re.findall(r"(?m)^■[^\n]{3,33}", text)) >= 5
         and distinct(re.compile(r"宅配伝票|送料について|手数料について|後払(?:い)?決済|"
                                 r"当日出荷|他店では販売しておりません"), text) >= 5)

    # Local listing metadata can be usable even when a copied appendix is unrelated.
    if re.search(r"/(?:healthcenter|clinic|hospital|welfare|medical)/\d+\.php$", path, re.I):
        ad_separator = re.search(r"(?m)^スポンサーリンク\s*$", raw)
        if (ad_separator and re.search(r"(?m)^\|(?:名称|施設名|所在地)\|\|", text[:380])
                and distinct(re.compile(r"\|(?:都道府県|所在地|電話番号|設置主体|管轄区域)\|\|"), text[:450]) >= 3
                and distinct(re.compile(r"郵便等投票証明書|選挙管理委員会|郵便投票"), text[500:]) >= 3
                and distinct(re.compile(r"感染症法|医師|管轄|地域保健法|保健医療"), text) >= 3):
            findings["facility-listing-with-unrelated-repeated-legal-appendix"] = [
                (ad_separator.start(), len(raw))
            ]
    page("translated-gallery-slice-with-multiple-attachment-errors",
         bool(re.fullmatch(r"/(?:ja|jp)/\d{5,}/\d{1,3}/?", path))
         and len(text) <= 4500
         and distinct(re.compile(r"続けてために|ために最善を尽くしましたが|"
                                 r"女性、[^。\n]{3,40}と抱いていた|再度ゆっくりと動き始め|"
                                 r"世界の注目を[^。\n]{0,20}向かわせるため|"
                                 r"恐ろしく困難なものでした"), text) >= 3)
    if (clock_heading := re.match(r"\d{1,2}月\d{1,2}日[ \t]+\d{1,2}時\d{1,2}分\n", text)):
        news_and_comments = [line.strip() for line in text[clock_heading.end():].splitlines() if line.strip()]
        if len(news_and_comments) >= 12:
            news = "\n".join(news_and_comments[:5])
            posts = news_and_comments[5:]
            page("unsourced-wire-copy-with-unlabeled-forum-snippets",
                 sum(len(line) >= 67 and "。" in line for line in news_and_comments[:5]) >= 4
                 and distinct(re.compile(r"記者会見|述べました|発表した|について|と報じられ"), news) >= 3
                 and len([line for line in posts if len(line) <= 65 and not line.endswith("。")]) >= 8
                 and distinct(re.compile(r"(?m)w+|(?:じゃん|けど|だろ|かね)[w \t]*$|^[×○〇]"), "\n".join(posts)) >= 3
                 and bool(re.search(r"関連記事|オススメ記事|おすすめ記事|人気記事", text[-180:]))
                 and not re.search(r"(?m)^\s*(?:出典|引用元|転載元|配信元|コメント欄|読者コメント)[：:]?", text))
    broken_tail = text[-2500:]
    page("uncited-story-with-keyword-splice-footer",
         bool(re.search(r"(?m)^[-*]{10,}\n[-*]{10,}\nカテゴリー", text[:200]))
         and 800 <= len(text) <= 10500
         and len(re.findall(r"(?m)^(?:私|その日|最初は|それから|一見)", text[:2200])) >= 8
         and distinct(re.compile(r"助けを[^。\n]{2,35}号|名前を[^。\n]{2,22}から[^。\n]{2,14}の実態|"
                                 r"をは甘くありません|だということねは|"
                                 r"翌日[^。\n]{0,30}計画[^。\n]{0,35}シリーズ|"
                                 r"そのまま[^。\n]{0,18}宅へ。"), broken_tail) >= 3
         and not re.search(r"(?m)^(?:作者|著者|執筆者|掲載元|転載元)[：:]", text))

    page("affiliate-questions-followed-by-unwitnessed-training-claims",
         len(text) <= 2400 and len(re.findall(r"(?m)^[^。\n]{5,55}(?:たい|ない)[ \t]*$", head)) >= 3
         and len(re.findall(r"プログラム|メソッド|マニュアル|講座|教材", text)) >= 2
         and bool(re.search(r"さんの\s*「[^。\n]{3,50}(?:プログラム|マニュアル|講座|教材)」", text))
         and distinct(re.compile(r"ネットの評価|私でも大丈夫|結果出るのかな|"
                                 r"結果が出るなら|試してみたいな|いいみたい|できるっていって"), text) >= 4)
    page("localized-article-with-incomplete-number-slots-and-broken-punctuation",
         bool(re.search(r"/(?:ja|jp)/", path))
         and len(re.findall(r"XNUM+|XNUMX", text, re.I)) >= 2
         and len(re.findall(r"です[。]{2}|ます[。]{2}|[。][、,]|"
                            r"すべての自由が可能|情報は[^。\n]{0,25}情報", text)) >= 3)
    opaque_slug = re.fullmatch(r"/[a-z0-9]{16,30}/?", path, re.I)
    if host and opaque_slug and sum(ch.isdigit() for ch in path) >= 4:
        storefront = re.search(
            r"(?im)^.+---[ \t]*(?:www\.)?" + re.escape(host.removeprefix("www.")) +
            r"[ \t]*\nmodel[ \t]*:[ \t]*[a-z0-9]{5,20}[ \t]*$", text
        )
        if storefront and storefront.start() >= 320:
            lead = re.sub(r"^【[^】]+】[ \t]+", "", storefront[0].partition("---")[0])[:36].strip()
            page("repeated-product-card-with-decimal-price-inside-copied-prose",
                 bool(lead) and text.count(lead) >= 3
                 and bool(re.search(r"当店通常価格[ \t]*[\d,]+\.\d{4}[ \t]*円", text[storefront.end():]))
                 and len(re.findall(r"(?m)^[^|<>【\n]+。$", text[:storefront.start()])) >= 3
                 and len(text.rstrip().splitlines()[-1]) >= 80)
    if re.fullmatch(r"/(?:auc|auction)-[a-z]{3,20}/[0-9]{2,8}[a-z]{2,10}[0-9]{9,20}\.s?html?", path, re.I):
        package = re.search(r"(?m)^パッケージ(?:の)?(?:内容|リスト)[:：][ \t]*$", text)
        if package:
            fields = re.findall(r"(?im)^(?:色温度|パワー|消費電力|寸法|電源|電圧|明るさ)\b"
                                r"(?:[ \t]*\([A-Z]+\))?[:：]", text[:package.start()])
            snippets = text[package.end():].splitlines()
            page("machine-auction-specs-followed-by-unlabelled-editorial-snippets",
                 len(set(fields)) >= 4 and bool(re.search(r"明るさ.{0,12}\d(?:\.\d+)?米/", text[:package.start()]))
                 and sum(len(line) >= 35 and bool(re.search(r"\.{3}$|…$", line)) for line in snippets) >= 2
                 and distinct(re.compile(r"(?:おしゃれな|人気の)カフェ|ランキング形式でご紹介|"
                                         r"中古車相場|中古車購入時|回転まで軽く吹け上がる"), "\n".join(snippets)) >= 3)
    if re.fullmatch(r"/(?:auc|auction)-[a-z]+(?:-[a-z]+){0,4}/[0-9]{2,8}[a-z]{2,10}[0-9]{6,20}\.s?html?",
                    path, re.I):
        technical = text[:230]
        page("machine-auction-specs-followed-by-unrelated-care-copy",
             len(text) <= 950 and len(re.findall(
                 r"(?m)^[|](?:特長|用途|仕様|材質.{0,6}|セット内容.{0,6}|注意|生産国|メーカー)[|]$",
                 technical)) >= 5
             and distinct(re.compile(r"切削|エンドミル|超硬合金|ドリル|カッター|旋削"), technical) >= 3
             and distinct(re.compile(r"育毛シャンプー|たんぱく質|表皮に浸透|頭皮環境|毛髪|角質層"), text[170:]) >= 4
             and not re.search(r"(?m)^(?:関連する記事|関連記事|おすすめ|出典)[：: \t]?", text))
    page("generated-catalog-number-with-machine-storefront-callout",
         bool(re.search(r"/\d{2,8}[a-z]{2,10}\d{10,18}\.s?html?$", path, re.I))
         and bool(re.match(r"(?:高い素材|最先端の素材|最高の素材|新入荷|熱い販売|低価格で販売)\s*[^\n]{10,}", head))
         and len(re.findall(r"(?m)^(?:ラグ|フープ|バット|カラー|サイズ|容量|材質|付属品|"
                            r"シェル|ブランド|仕様|カラーコード|電圧)[:：]", text)) >= 5
         and bool(re.search(r"実際のものと若干色味が異なる|ご理解[^。\n]{0,8}上でご購入|"
                            r"展示品のため[^。\n]{0,35}ございます", text)))
    page("short-localized-keyword-page-with-impossible-machine-syntax",
         120 <= len(text) <= 850 and bool(re.search(r"/(?:ja|jp)/[^/]+\d+/?$", path))
         and distinct(re.compile(r"沿っているそれらを|そのためにも、より左の|ゲーム\d+は、最も|"
                                 r"のうち、私たちは\d+ページでは|を作る移入|"
                                 r"視聴者とが必要|複雑な[^。\n]{0,12}完全に無意識"), text) >= 3)
    page("download-mirror-with-multiple-source-listing-blocks",
         len(re.findall(r"(?im)^Total (?:Videos|Files):[ \t]*\d+", text)) >= 3
         and len(re.findall(r"(?im)^Total Size:[ \t]*\d", text)) >= 3
         and len(re.findall(r"(?im)^Download(?:\s*\([^)]{2,15}\))?:\s*\nhttps?://", text)) >= 3
         and len(set(re.findall(r"(?m)^https?://(?:[^/\s]+/){2,}[^\n]+\.(?:rar|zip|7z)$", text))) >= 3
         and not re.search(r"(?m)^(?:転載元|著作者|配布許諾|ライセンス)[:：]", text))

    page("imported-app-copy-with-redundant-clauses-and-broken-verbs",
         bool(re.search(r"/(?:posts|apps?)/(?:information|details|android)/[^/]+/\d{4,}/?$", path))
         and bool(re.search(r"(?m)^(?:特徴|機能|使用方法)[:：]\s*$", text))
         and len(re.findall(r"Android|SMS|SDカード|アプリ|スマートフォン", text)) >= 7
         and distinct(re.compile(r"送信することを送信|復元しますアプリを復元|することができたい|"
                                 r"削除することができます復元|バックアップとバックアップ|"
                                 r"あなたは、あなたが"), text) >= 3)
    page("paid-method-affiliate-with-multiple-scripted-objections",
         len(text) <= 1900
         and sum(0 < len(line.strip()) <= 43 for line in text.splitlines()) >= 12
         and len(re.findall(r"スクール|プログラム|マニュアル|教材|コンサル", text)) >= 2
         and distinct(re.compile(r"本当とは思えな|どうだろうね|胡散臭いかな|"
                                 r"買ってもいいかな|実は効果あり|実績に関しても|"
                                 r"っていろいろ指摘"), text) >= 4
         and len(re.findall(r"(?m)^.{3,60}[?？]\s*$", text)) >= 2)
    page("scraped-blog-diary-with-trivia-and-weather-feed",
         bool(re.search(r"(?m)^Source:[ \t]*[^\n]{3,100}\s*\Z", text))
         and distinct(re.compile(r"ブログをご覧いただ|応援ポチ|にほんブログ村|往復クリック|"
                                 r"アメンバー申請|ブログスタンプ"), head + text[:1400]) >= 4
         and bool(re.search(r"(?m)^[ \t]*\([ \t]*[^\n)]{3,40}より[ \t]*\)\s*$", text))
         and distinct(re.compile(r"全国の天気予報|天気のポイント|冬型の気圧配置|"
                                 r"マイ天気|にわか雨|最高\d+℃"), text[-900:]) >= 3)

    if review_headings := REVIEW_HEADLINES_MARKER.search(raw):
        tail = normalize(raw[review_headings.end():])
        tail_lines = [line.strip() for line in tail.splitlines() if line.strip()]
        categories = (
            r"収納|壁掛け|財布|ファスナー|防水",
            r"充電|パソコン|スマホ|冷却ファン|Raspberry",
            r"名著|読む|本です|学を志す|バックナンバー|[一1]冊",
            r"ガンに|鼻うがい|血圧|風邪|頭痛",
            r"缶詰|飲みたく|ポップス|春夏秋冬|オヤジの唄|神曲",
            r"腕時計|レイバンサングラス|肌触り|迷彩流行り",
            r"ニッケル蓄電池|スピーカー|交換用バッテリー",
            r"名車|交換用タイヤ|ドライブレコーダー",
            r"ラッピングしたくなる本|感想文|読んでみたい本",
        )
        if (len(tail_lines) >= 14 and all(len(line) <= 86 for line in tail_lines)
                and sum("。" in line for line in tail_lines) * 6 <= len(tail_lines)
                and sum(bool(re.search(category, tail)) for category in categories) >= 4
                and not re.search(r"(?m)^投稿者|購入済み|カスタマーレビュー|同じ商品", tail)):
            findings["unrelated-short-product-review-headlines-appended-to-one-review"] = [
                (review_headings.start(), len(raw))
            ]
    restaurant_types = re.compile(r"懐石料理|火鍋屋|パスタ|串かつ|串カツ|冷麺|焼き鳥|居酒屋|カクテル|ラーメン|"
                                  r"焼肉|寿司|カレー|そば店|スイーツ|中華料理|メキシコ料理")
    if re.fullmatch(r"/(?:places?|spots?)/\d+/?", path) and 400 <= len(text) <= 2800:
        restaurant_lines = [line for line in text.splitlines() if len(line) >= 28]
        page("anonymous-restaurant-blurbs-merged-under-one-place",
             len(restaurant_lines) >= 8 and distinct(restaurant_types, text) >= 7
             and len(re.findall(r"お店です|屋さんです|メニューが|料理を楽し|料理がある", text)) >= 6
             and sum(bool(restaurant_types.search(line)) for line in restaurant_lines) >= 6
             and not re.search(r"(?m)^第\d位|^[◆■][^。\n]{2,65}$|ランキング|"
                               r"選を紹介|おすすめ\d+選|営業時間|住所:|掲載店舗|連絡先", text))
    if re.fullmatch(r"/(?:places?|spots?)/\d+/?", path) and 280 <= len(text) <= 820:
        blurbs = [line for line in text.splitlines() if line.strip()]
        venue_clues = (
            r"割烹|和食処|小料理屋", r"一人掛け|落ち着いた.{0,10}バー|カクテル",
            r"燻製(?:木|料理|醤油)|スモーカー", r"うな重|肉厚のうなぎ|鰻丼",
            r"皿うどん|海鮮風味|ちゃんぽん", r"とんこつラーメン|せいろそば",
        )
        page("short-anonymous-restaurant-collage-on-place-detail",
             4 <= len(blurbs) <= 8 and all(line.count("。") >= 2 for line in blurbs)
             and sum(any(re.search(clue, line) for clue in venue_clues) for line in blurbs) >= 4
             and sum(bool(re.search(clue, text)) for clue in venue_clues) >= 4
             and not re.search(r"住所[：:]|営業時間|店舗一覧|ランキング|をご紹介|まとめました", text))
    page("scraped-review-feed-with-repeated-empty-date-and-incompatible-products",
         bool(re.match(r"Reviews:\s*\d(?:\.\d)?", head))
         and len(re.findall(r"(?m)^(?:,\s*)?に書かれています\s*$", text)) >= 5
         and len(re.findall(r"(?m)^by\S{2,60}\s*$", text)) >= 5
         and sum(bool(re.search(terms, text)) for terms in (
             r"スニーカー|幅広サイズ|かかと", r"バッグ|カゴバック|ファスナー|マチ",
             r"小銭|お薬手帳|カードケース|財布", r"妊娠中|ワン.ツーサイズ|ウエスト|産後",
             r"液晶|イヤホン|USB|バッテリー", r"ネジ|ドリル|締め付け|六角",
         )) >= 3
         and not re.search(r"(?m)^商品名|レビューを投稿|レビューガイドライン", head))
    page("reposted-news-padded-with-unrelated-local-buyback-phrasings",
         bool(re.search(r"(?m)^\d{1,2}月\d{1,2}日\d{1,2}時\d{1,2}分配信", text))
         and distinct(re.compile(r"ヘッドラインをとり上げ|応援よろしく|こんな感じで終了|"
                                 r"今後の展開が楽しみ"), text[:1700]) >= 3
         and len(re.findall(r"売却申し込み|カービュー登録|買取り金額|下取り価格|買取査定|無料一括見積", text[-1500:])) >= 3
         and len(re.findall(r"(?:★☆★|☆★☆|④討い泙)", text)) >= 2)
    courses = re.findall(r"(?:教材|プログラム|セミナー|マニュアル|教室|スクール|講座)", head)
    page("duplicated-course-title-with-simulated-review-search",
         len(text) <= 1700 and len(courses) >= 4
         and bool(re.search(r"(?:実際に)?(?:買|購入)したレビューなのか|"
                            r"実践してみた(?:徹底)?レビューはない", text))
         and distinct(re.compile(r"(?:購入|実践)したレビュー|徹底レビュー|"
                                 r"一見すごそう|怪しいよね|試してみる価値|読[むんだ]+ブログで評価"), text) >= 4
         and bool(re.search(r"さんの.?[「『]?.{15,120}(?:プログラム|教材|講座|スクール)", head)))

    page("localized-promotional-article-with-multiple-literal-translation-breaks",
         bool(re.search(r"/(?:ja|jp)/[^/]+", path))
         and distinct(re.compile(r"は、我々は知っている|あなたは[^。\n]{0,25}一緒にされている|"
                                 r"適格なエンゲージメント|偉大なプロのソーシャル|"
                                 r"キックアスする|ツールがあれば、あなたの[^。]{0,20}楽になります"), text) >= 3)
    page("hotel-booking-template-with-unpatched-language-slots",
         bool(re.search(r"(?:ホテル|Hotel|Resort)", head))
         and distinct(re.compile(r"(?m)^(?:部屋|レストラン|食事|サービス|"
                                 r"リラクゼーション|インターネット|駐車場|客室)\s*$"), text) >= 4
         and distinct(re.compile(r"歴史的なにあり|有名なにあります|"
                                 r"Facilities There Is A|からわずかな時間|"
                                 r"それは、ユニークな|でEUR \d+ (?:人|1日)|"
                                 r"プライベート駐車場が敷地内で"), text) >= 3)
    page("translated-download-listing-with-corrupted-feature-copy",
         bool(re.search(r"/(?:ja|jp)/(?:arcade|games?|software|action)/", path))
         and bool(re.search(r"再梱包トレント|再パック|torrentダウンロード|トレントダウンロード", head, re.I))
         and len(re.findall(r"ジャンル:|開発者:|出版社:|修正:|ダウンロード|のコピー|"
                            r"リリース年:|バージョン:", text)) >= 4
         and distinct(re.compile(r"プレイヤーの手で|人々のカップル|貴重な機会ではありません|"
                                 r"押す«[^»]{1,9}»|の中で最も非常識な|"
                                 r"作業デスクは無料|ワークデスクは無料"), text) >= 2)
    page("ebook-download-template-with-unrelated-host-and-invalid-metadata",
         bool(re.fullmatch(r"/\d{4,9}-id\d{3,9}/?", path, re.I))
         and bool(re.search(r"PDF\s*[,、/]\s*TXT\s*[,、/]\s*FB2", head, re.I))
         and all(field in text for field in ("ファイル名", "ダウンロード", "関連書籍"))
         and bool(re.search(r"ISBN\s+(?:-\s*)?(?!97[89])[0-9]{13}\b", text))
         and bool(re.search(r"形式の冊の本|そしてはるかに", head)))
    page("automotive-localization-with-cabin-and-vehicle-spec-contradictions",
         bool(re.search(r"クロスオーバー|SUV|ハッチバック|セダン", head))
         and len(re.findall(r"馬力|ポンドフィート|トルク|kWh|EV", text)) >= 6
         and distinct(re.compile(r"最新[鋭の]+タクシー|先進的なタクシー|水平方向のワイピング|"
                                 r"米国の土壌にも|スタイルのDNA|エントリーレベルモデルの[^。]{2,16}安定したパートナー"), text) >= 3
         and bool(re.search(r"[2二]人乗りSUV[^。]{0,35}全ての乗員|"
                            r"ホンダは[^。]{0,10}(?:EQA|GLA|EQE|EQS)が", text)))
    page("machine-localization-with-looped-source-link-in-prose",
         bool(re.search(r"(?:https?://www\.){5,}", text, re.I))
         and distinct(re.compile(r"より速いスピードでそれらを与え|"
                                 r"行くようにそれを並べ替え|商業的対応は間もなく|"
                                 r"納税者のドル|進むにつれて[^。]{0,20}遺産の|風呂敷の足跡|"
                                 r"品質に関する問題を最小限に抑える"), text) >= 2
         and not re.search(r"正規表現|URLの例|テストケース|再現コード", head))
    if re.search(r"(?m)^※?出典[:：][^\n]{12,240}https?://(?:www\.)?(?:youtube\.com|youtu\.be)/", head, re.I):
        page("video-recap-with-repeated-unedited-transcript-errors",
             len(re.findall(r"(?m)^- [^\n]{9,100}$", text)) >= 4
             and bool(re.search(r"参考[:：]|動画では", text[800:]))
             and len(re.findall(r"[一-龯々]{3,10}選(?:は|の|が|を|側)", text)) >= 6
             and distinct(re.compile(r"虚偽国訴|刑事続き|直後の録が|"
                                     r"第一声が明かされました|招集メンバーからの外れ"), text) >= 2)
    if 240 <= len(text) <= 1100 and re.search(r"/entry/20\d{2}/\d\d/\d\d/\d{6}/?$", path):
        page("blog-post-stitches-unrelated-shop-lines-and-dangling-fragments",
             len(re.findall(r"(?m)^(?:また、|綿、|ですが、|といっても、|のは、|※付属品は仕様|!)\s*$", text)) >= 3
             and distinct(re.compile(r"お支払方法|サイズ[・と]素材|インラインフレームに未対応|コメント欄にお書き"), text) >= 2
             and sum(bool(re.search(category, text)) for category in (
                 r"ポリエステル|ウエスト|袖丈|裾幅", r"ポーカーサイズ|カードデッキ",
                 r"ディプロイバックル|スポーツウォッチ|駆動時間", r"ペンダント|ネックレス|指輪",
                 r"食べ比べ|味わってみて|小麦粉",
             )) >= 4
             and not re.search(r"まとめました|今週の新商品|商品一覧|週替わり特集", head))
    if 250 <= len(text) <= 2200 and re.search(r"リフォーム|見積|修繕", head):
        page("renovation-keyword-prose-with-broken-price-and-word-slots",
             len(re.findall(r"リフォーム|修繕|施工|見積", text)) >= 8
             and distinct(re.compile(r"その万円を|万円では万円|部屋の万円前後|万[円元]てのほう"), text) >= 2
             and distinct(re.compile(r"工事もり|諸費用もり|リフォームを子育て|お客様のご変更を事例|"
                                     r"自然がいっぱいな優先順位|ポイントえた"), text) >= 2)
    if 180 <= len(text) <= 1500 and re.search(r"外壁|塗り替え|屋根", head):
        page("home-repair-clause-montage-with-incompatible-place-slots",
             len(re.findall(r"外壁|塗り替え|サイディング|養生|見積|工事", text)) >= 8
             and len(set(re.findall(r"(?:京都|大阪|[一-龯]{2,3}県)", text))) >= 4
             and distinct(re.compile(r"県をポイントでする|愛知県の確認を行うことが福井県|"
                                     r"万円の不具合を年目|築\d+状況|県\d{2}年のはい|"
                                     r"塗料を迎える|に(?:なっ|応じ)て、年内・理由"), text) >= 3
             and len(re.findall(r"(?:任せ下さい|[一-龯]県|業者検討)www[、。]?", text)) >= 2)
    if "ブログ追加新規作成" in text and len(text) <= 2000:
        page("default-blog-seeded-with-keyword-substituted-news",
             bool(re.search(r"teacup\.ブログ\s*START!", text, re.I))
             and "この記事は管理画面から" in text
             and len(re.findall(r"(?:ホテヘル|出会い系|格安[^\n。]{1,8}販売)", text[:550])) >= 3
             and distinct(re.compile(r"月日とが利用|個別記事[^。\n]{0,55}について 年月|"
                                     r"各コンポーネント|ホテヘル内は全国に先駆け"), text[:550]) >= 2)
    if 250 <= len(text) <= 1400 and " 求人で" in text:
        wrapped = re.sub(r"\n(?=[^\n])", "", text)
        local_service = re.search(r"([一-龯]{2,10}) (デリヘル|風俗|ホテヘル)に行ってきて", wrapped)
        page("local-service-queries-forced-into-repeated-first-person-story",
             bool(local_service and f"{local_service[1]} {local_service[2]} 求人で働いて" in wrapped)
             and any(wrapped.endswith(wrapped[:length]) for length in range(14, 26)))
    if re.fullmatch(r"/most/[^/]+/[a-z0-9_-]{10,20}/?", path, re.I):
        promotional_comment = re.search(
            r"(?mi)^(?:Lol[ -]+)?reminds me of this video[^\n]{0,130}"
            r"\btrust me\b[^\n]{0,32}?\s+([a-z0-9.-]+)/most/bideo/[a-z0-9_-]{10,20}\s*$", text)
        page("video-comment-mirror-with-injected-cross-video-promotion",
             bool(promotional_comment and promotional_comment[1].lower().removeprefix("www.")
                  == host.removeprefix("www."))
             and len(text.splitlines()) >= 40 and len(re.findall(r"\b\d{1,2}:\d\d\b", text)) >= 3
             and not re.search(r"コメント欄について|コメント抜粋|コメントを引用", head))
    page("third-party-localization-preserves-foreign-publisher-pitch-and-broken-slots",
         bool(re.match(r"/(?:ja|jp)/[^/]+", path))
         and bool(re.search(r"(?:を|用の) *[A-Za-z0-9-]{3,25}\s*アプリをダウンロードして"
                            r"[A-Za-z0-9-]{3,25}に追いつ", text[-750:]))
         and bool(re.search(r"\[email protected\]|速報カバレッジ|私たちに従ってください", text[-750:]))
         and distinct(re.compile(r"まだ右の開始時|バック[12][90]\d{2}年代に|"
                                 r"彼らが正式に[^。\n]{2,35}を見つけたとき|"
                                 r"それはあなたが会社が今日どの|排他的な写真のための"), text) >= 3)
    if ">>" in text and re.search(r"/(?:archives|post|thread)/[^/]+", path):
        heading_groups = list(re.finditer(r"(?m)(?:^- [^\n]{5,110}(?:\n|$)){5,}", text))
        if len(heading_groups) >= 2:
            final_headings = set(heading_groups[-1][0].splitlines())
            page("scraped-thread-interrupted-by-duplicated-headline-groups",
                 len(re.findall(r"(?m)^>>\d+", text)) >= 5
                 and any(len(final_headings.intersection(group[0].splitlines())) >= 3
                         and re.search(r"(?m)^>>\d+", text[group.end():heading_groups[-1].start()])
                         for group in heading_groups[:-1])
                 and not re.search(r"関連記事|人気記事|おすすめ記事", text))
    if re.search(r"(?:^|\.)(?:bbs|forum|board)\.", host, re.I) or "/bbs/" in path:
        page("board-with-repeated-fabricated-cash-gift-testimonials",
             len(re.findall(r"(?m)^20\d{2}/\d\d/\d\d \([A-Z][a-z]{2}\) \d\d:\d\d:\d\d$", text)) >= 3
             and len(set(re.findall(r"(?m) - ([^\n]{1,18}) URL$", text))) >= 3
             and len(re.findall(r"(?:連絡|連絡先).{0,21}(?:した方|してください|してみて)", text)) >= 3
             and distinct(re.compile(r"遠慮しないで|記帳して|3000万|税金対策で支援|銀行に行って|"
                                     r"裕福になれる|お金をもらうことができ"), text) >= 3
             and not re.search(r"注意喚起|詐欺の事例|迷惑投稿の例", head))
    if re.fullmatch(r"/(?:ja|jp)/[a-z0-9]+(?:-[a-z0-9]+){3,}/?", path, re.I):
        page("foreign-cooking-article-with-machine-translated-sense-and-syntax-breaks",
             "言語を選択してください" in text[-230:]
             and distinct(re.compile(r"薄いリング|サンドイッチ|ゆで[た卵]|カット|調理|レタス"), text) >= 4
             and distinct(re.compile(r"プラント油|ハードゆで卵|使用、例えば、電球|沸騰水.{0,18}熱傷様|"
                                     r"多くの愛人で装飾|鳥の死骸の整合性|皿の申請をする|"
                                     r"料理がより飽和見て|卵カットエリアの急性"), text) >= 3)
    if re.search(r"/entry/20\d{2}/\d\d/\d\d/\d{6}(?:_\d{1,3})?/?$", path) and len(text) <= 1800:
        if shoe_listing := re.match(r"\s*[|]{1,3}([^\n|]{25,260}(?:靴|シューズ)[^\n|]{0,50})\|", text):
            intro, continuation = shoe_listing[1], text[shoe_listing.end():]
            product_codes = set(re.findall(r"\b(?:[A-Z]{1,3}[0-9]{4,7}|[A-Z]{2,5}/[A-Z0-9/]{4,18})\b", intro))
            page("shoe-catalogue-tokens-inserted-into-unrelated-sentence-clause-slots",
                 any(code in continuation for code in product_codes)
                 and len(re.findall(r"(?:シューズ|フルグレインレザー|アウトソール|スリーストライプス|アディダス|ナイキ)", continuation)) >= 3
                 and distinct(re.compile(r"酸欠で息が|急に用事を思い出し|飛んだり.{0,35}元通り|"
                                         r"仲良くこれからも上質で天職|ぜいたくな気をそらせ|"
                                         r"手間がかかっていて備えている"), continuation) >= 2)
    if re.search(r"(?:システムトレード|投資ソフト|株式投資|外国為替|証拠金取引)", text):
        snippet_tail = text[-3000:]
        page("affiliate-trading-post-appended-with-keyword-counts-and-source-snippets",
             len(re.findall(r"(?:\.{3}|…)\s*\(続きを読む\)", snippet_tail)) >= 4
             and any(len(re.findall(r"(?<![0-9])[0-9]{3,6}(?:fx|株|為替|日経(?:225)?)?"
                                    r"(?:システムトレード|投資ソフト|証拠金取引)", line, re.I)) >= 5
                     for line in snippet_tail.splitlines())
             and bool(re.search(r"超お金持ち|大金持ちも夢|必勝法|初心者でも.{0,12}稼げる", snippet_tail)))
    if host.startswith("ja.") and re.fullmatch(r"/\d{1,2}(?:-[a-z]{2,20}){5,}/?", path, re.I):
        page("machine-localized-numbered-quote-list-with-repeated-sense-distortions",
             len(re.findall(r"(?m)^[0-9]{1,2}\)\s*[^。\n]{6,140}", text)) >= 12
             and distinct(re.compile(r"沈黙が改善されない|賢い人は完全に行き|"
                                     r"彼らが私のものと同じくらい|欠陥のない友達のようなもの|"
                                     r"常に時間通りに起こります|25点見つけました"), text) >= 3
             and not re.search(r"翻訳者|原文との比較|訳注|機械翻訳の(?:例|誤り)", text))
    if host and re.search(r"(?:^|&)l_name=[^&]+&f_name=", address.query):
        page("generated-name-lookup-with-shared-score-profile-and-pitches",
             distinct(re.compile(r"(?m)^- (?:天格|人格|地格|外格|総格|社会運|家庭運|陰陽五行)\s*$"), text) >= 5
             and len(re.findall(r"画数\d{1,3}画", text)) >= 3
             and bool(re.search(r"姓名判断|無料名前占い|名前の画数", head))
             and distinct(re.compile(r"電話占いランキング|初回無料|\d+分無料|占い師ランキング"), text) >= 3)
    page("single-forum-post-with-repeated-search-keyword-and-broken-voice",
         bool(re.search(r"/bbs/[^/]+\.s?html?$", path))
         and bool(re.search(r"(?m)^[|｜].{0,160}投稿者[:：].{0,80}投稿日[:：].{0,60}No\.\d+", head))
         and len(text.splitlines()) >= 45
         and max(Counter(re.findall(r"[A-Z一-龯ぁ-ゖァ-ヺ]{6,26}(?:掲示板|動画集|通販サイト)", text)).values(),
                 default=0) >= 3
         and distinct(re.compile(r"がの[一-龯]|好きなのがな|気付いたよた|なったよた|"
                                 r"私はが|私がは|もがので|のがなのだけど"), text) >= 3)
    page("rewritten-pseudo-diary-with-unrelated-keyword-and-nonsensical-nouns",
         bool(re.search(r"/20\d{2}/\d{1,2}/?$", path))
         and bool(re.search(r"。(?:視力回復|発毛|育毛|買取見積|無料査定|美白ケア)\s*$", text))
         and distinct(re.compile(r"半球範疇|スポンジ[^。\n]{0,6}郷里|ケーキところの|"
                                 r"に絶頂もの|お世辞除外|腹一杯だ|社会話を|君のサイトを見てある"), text) >= 3)
    if (reaction := re.search(r"(?m)^(?:ニュースへの反応|ネットでの反応)\s*$", text)):
        article, comments = text[:reaction.start()], text[reaction.end():]
        lines = [line for line in comments.splitlines() if line.strip()]
        page("short-news-copy-with-repackaged-anonymous-reactions",
             bool(re.fullmatch(r"/\d{4,}/?", path)) and 2 <= article.count("。") <= 5
             and 8 <= len(lines) <= 60 and len(article) < 500
             and sum(not line.endswith(("。", "!", "?")) for line in lines) >= 3
             and not re.search(r"(?:出典|転載元|配信|提供元|公開日|著者|https?://)", article))
    page("scraped-news-translation-with-unrelated-retail-keyword-in-body",
         bool(re.fullmatch(r"/20\d{2}/\d\d/blog-post(?:_\d{1,4})?\.html?", path))
         and bool(re.match(r"\|[^|\n]{12,155}\|\s*\n[^。\n]{2,40}\((?:AFP|AP|Reuters|ロイター)\)\s*は *-", text))
         and len(re.findall(r"(?m)^- [^：:\n]{2,16}[：:]", text)) >= 4
         and bool(re.search(r"(?:ギフトカード|ギフト券|格安クーポン|デジタルコード).{0,35}"
                            r"(?:買い戻す気|オンライン購入|割引で入手|を販売)", text[-250:]))
         and distinct(re.compile(r"さまざまな大文字で|椅子緊急会議|自然安全保障理事会|"
                                 r"新たな脅威の光では|開発の一部は以下|警戒レベルを増加させる"), text) >= 3)
    page("localized-repair-answers-with-corrupt-sentences-and-unrelated-links",
         bool(re.fullmatch(r"/[a-z]{2,16}(?:-[a-z]{2,16}){4,}/?", path, re.I))
         and len(re.findall(r"(?m)^担当者[：:] *\d+(?:\.\d+)?k\s*$", text)) >= 3
         and bool(re.search(r"選択したソリューション|受け入れられた回答", text))
         and distinct(re.compile(r"春の時間と|多分これ ビデオ 手伝います|"
                                 r"ビデオはスケールをひっくり返しました|"
                                 r"数回使用して成功しましたが[、,]数回使用しません|"
                                 r"頭をひっくり返しました|残りを物理学に処理させ"), text) >= 3)
    page("unrelated-teaser-before-recycled-emulator-ad-body",
         bool(re.fullmatch(r"/entry/20\d{2}/\d\d/\d\d/\d{6}/?", path))
         and 220 <= len(text) <= 820
         and bool(re.match(r"[^。\n]{2,18}という言葉で[、,][^。\n]{3,30}想像をしてはいけません。\n", text))
         and bool(re.search(r"(?m)^.{1,30}\) \(@[A-Za-z_0-9]+\) 20\d\d年\d{1,2}月\d{1,2}日", text))
         and distinct(re.compile(r"縦画面のゲーム|横画面のゲーム|PCでスマートフォンアプリ|"
                                 r"アプリが遊べちゃいます|タブレットの比じゃ|DMMGAMESと提携"), text) >= 4)
    page("localized-wildlife-article-with-cross-species-translation-errors",
         bool(re.match(r"/ja(?:-jp)?/", path, re.I))
         and bool(re.match(r"目次\s*\n", text))
         and distinct(re.compile(r"放鳥|海鳥|くちばし|翼を広げ|繁殖する渡り鳥|"
                                 r"飛来海鳥|リンギング"), text) >= 4
         and bool(re.search(r"(?:ジャコウネコ|ボブキャット|ヤマネコ|オオヤマネコ|ムササビ|"
                            r"ジャッカル|カワウソ)の(?:くちばし|翼|風切羽)", text))
         and bool(re.search(r"(?m)[ァ-ヺー]{3,22}で"
                            r"[^。\n]{0,12}(?:ボブキャット|ヤマネコ|カワウソ|ジャッカル)"
                            r"が(?:発見|確認)されました。$", text)))
    page("localized-nutrition-article-with-broken-measures-and-ingredient-names",
         bool(re.search(r"(?i)/[^/?]*[a-z]{5,}[^/?]*[ぁ-龯]", path))
         and distinct(re.compile(r"カリウム|食物繊維|血糖値|イヌリン|栄養価|カロリー"), text) >= 4
         and bool(re.search(r"よりも少ない\d{1,3}カロリー|それぞれ\d{1,2}回と\d{1,2}回", text))
         and distinct(re.compile(r"の概要[:：]|体のための栄養素と利点|"
                                 r"和風サラダなどに持っていき|"
                                 r"それはあなたの健康にとってより良い|菊ポテト"), text) >= 3)
    if re.fullmatch(r"/entry/20\d{2}/\d\d/\d\d/\d{6}/?", path) and len(text) < 1550:
        page("broken-supplement-blurbs-bound-by-leftover-html",
             bool(re.match(r"<br\s*/?>\s*[+＋]?", text, re.I))
             and bool(re.search(r"<br\s*/?>\s*$", text, re.I))
             and distinct(re.compile(r"乳酸菌|サプリメント|健康食品|サンプルコスメ|酵母"), text) >= 3
             and distinct(re.compile(r"なぜその機能が冷静と|健康食品[^。\n]{0,5}健康食品|"
                                     r"栄養の取り(?:微粒|食物)|で[^。\n]{2,9}が治った今すぐ|"
                                     r"注目したいのが業界動向[一-龯]{3,}"), text) >= 3)
        page("cross-stitched-renovation-marketing-with-incompatible-predicates",
             distinct(re.compile(r"外壁塗装|モルタル|耐震改修|外構工事|通気層工法"), text) >= 4
             and distinct(re.compile(r"福祉用具レンタル|墓じまい|職人見習いを募集|"
                                     r"合計口コミポイント|世帯は玄関|家屋の固定資産税"), text) >= 3
             and distinct(re.compile(r"親水性があるので職人見習い|"
                                     r"高性能に耐震改修を行った家屋の固定資産税|"
                                     r"コスト削減で木のフェンス|モルタル施工前準備後々|"
                                     r"上がれるようにしまずは"), text) >= 2)
    page("video-news-transcript-mirror-with-broadcaster-prompts",
         bool(re.fullmatch(r"/(?:index\.php/)?20\d\d/\d\d/\d\d/post-\d+/?", path))
         and bool(re.match(r"[^\n]{10,165}[|｜](?:TBS NEWS DIG|ANNnewsCH|日テレNEWS|FNNプライムオンライン)\s*\n", text))
         and not bool(re.search(r"(?:^|\.)(?:tbs\.co\.jp|tv-asahi\.co\.jp|ntv\.co\.jp|"
                                r"fnn\.jp|youtube\.com)$", host))
         and distinct(re.compile(r"(?m)^▼(?:[^\n]{1,30}公式サイト|チャンネル登録[^\n]*|"
                                 r"(?:情報|映像)提供はこちら[^\n]*)"), text[-450:]) >= 3
         and not bool(re.search(r"(?m)^(?:出典|引用元|転載元|提供元)[：:]|^https?://", text)))
    if (mirror := re.match(r"([^\n]{4,75}(?:ブログ|通信|ニュース))[：:]20\d\d年\d{1,2}月\d{1,2}日\n", text)):
        stamp = re.escape(mirror[1]) + r"[：:]20\d\d年\d{1,2}月\d{1,2}日"
        page("drug-retail-domain-carrying-copied-diary-and-repeated-teasers",
             bool(re.search(r"(?:viagra|levitra|cialis|sildenafil|tadalafil|vardenafil|"
                            r"cheap-?med|discount-?pills|generic-?pharmacy)", host, re.I))
             and bool(re.search(stamp + r"関連(?:記事|ページ)", text))
             and len(re.findall(r"(?m)^- " + stamp + r"\s*$", text)) >= 4
             and bool(re.search(r"弁当|家族|母さん|旅行日記|小学生|子育て|習い事|自由研究", text[:450]))
             and len(re.findall(r"[\[［]…[\]］]|[\[［]\.\.\.[\]］]", text)) >= 3)
    page("event-domain-repurposed-for-unrelated-coupon-directory",
         bool(re.search(r"(?:hanabi|matsuri|festival)(?:[\d-]*)\.", host))
         and bool(re.fullmatch(r"/[a-z0-9-]{4,38}/?", path))
         and distinct(re.compile(r"新規会員登録で\d+ポイント|誕生日月クーポン|"
                                 r"割引クーポン|初回[A-Za-z]+利用|提携サイトで配布|年会費.*無料"), text) >= 5
         and any(all(re.search(term, text) for term in pair) for pair in (
             (r"カタログギフト", r"ラッピング|のし|手提げ袋"),
             (r"ワイシャツ|スーツ|ビジネスウェア", r"裾上げ|採寸|サイズ交換"),
             (r"食材宅配|宅配弁当", r"初回セット|定期購入|配送エリア"),
         ))
         and not re.search(r"花火大会|祭り会場|イベント来場|祭の参加者|フェス会場", text))
    page("event-domain-repurposed-for-unrelated-venue-promotions",
         bool(re.search(r"(?:^|[.-])(?:events|festivals?|carnival|fairgrounds)\.", host, re.I))
         and bool(re.fullmatch(r"/(?:post-|archives?/)\d+/?", path))
         and bool(re.search(r"(?m)^.{4,75}(?:の利用料金|の受付から.{1,14}開始までの流れ)$", head))
         and distinct(re.compile(r"指名料|出勤している|店舗詳細|体験談はこちら|住所をコピー|関連する.{1,12}体験談"),
                      text) >= 4
         and not re.search(r"イベント(?:主催|会場|公式|日程)|公演日程|出演者一覧|来場者案内|入場チケット", text))
    page("music-venue-domain-with-broken-casino-promotion",
         bool(re.search(r"(?:band|orchestra|livehouse|tribute|[-.]show)\.", host, re.I))
         and bool(re.fullmatch(r"/[a-z]+(?:-[a-z]+){1,3}/?", path))
         and distinct(re.compile(r"カジノ|オッズ|獲得賞金|連勝中|スロット|入金で"), text) >= 5
         and len(re.findall(r"\d+(?:[.,]\d+)?\s*(?:ユーロ|€|セント)", text)) >= 3
         and distinct(re.compile(r"スピンに成功して着地|暦の上での1日の遊び|"
                                 r"勝利のスピン|許可されたゲームで|スーパーチャージド(?:ウィン|ウイン)"), text) >= 2)
    page("medical-domain-with-apparel-catalog-on-opaque-query",
         bool(re.search(r"(?:septum|sinus|hernia|spine|bariatric|dent(?:al|ist))[a-z-]*"
                        r"(?:surgery|treatment|clinic|care)[a-z-]*\.", host, re.I))
         and path in ("", "/") and bool(host and re.fullmatch(r"[a-z]{9,22}", address.query))
         and distinct(re.compile(r"(?m)^(?:素材\s*:|着丈|ウエスト幅|股上|股下|身幅|肩幅|袖丈)"), text) >= 4
         and bool(re.search(r"タンブラー乾燥|洗濯機はお控え|生地の調達|再販・フルオーダー", text))
         and not re.search(r"術後|外科|手術|通院|診療|装具|医療用", text))
    page("school-notices-stitched-together-on-scholarship-application-route",
         bool(re.search(r"(?:scholarship|scholarsapply|scholarportal|scholars[a-z-]*)\.", host, re.I))
         and bool(re.fullmatch(r"/(?:[a-z]-\d{3,}|[a-z]+\d{3,})\.(?:php|html?)/?", path))
         and distinct(re.compile(r"昇降口|学校臨時休業|給食に|学校の木|学級編制|市立.{1,15}小学校|"
                                 r"教室訪問|\d年生家庭科|教育委員会"), text) >= 5
         and len(re.findall(r"\d{1,2}月\d{1,2}日\s*[（(][月火水木金土日][）)]", text)) >= 4
         and len(re.findall(r"(?m)[。）」]\s*\d{1,3}\s*$|^- と合併。|^jp[（(]", text)) >= 4)
    page("fragmented-japanese-content-on-scholarship-application-route",
         bool(re.search(r"(?:scholarship|scholarsapply|scholarportal|scholars[a-z-]*)\.", host, re.I))
         and bool(re.fullmatch(r"/[a-z]-\d{3,}\.(?:php|html?)/?", path))
         and 600 <= len(text) <= 4500 and len(text.splitlines()) >= 14
         and len(re.findall(r"(?m)[。）」?!]\s*\d{1,3}\s*$", text)) >= 3
         and len(re.findall(r"(?m)^[-•]|(?<=[。）」])\d{1,3}(?=\s|$)", text)) >= 4
         and not re.search(r"奨学金|スカラーシップ|応募資格|奨学生|研究奨励|"
                           r"選考委員会|scholarship application", head, re.I))
    if re.search(r"(?:^|[.-])(?:dive|diving|tauchschule)\.", host, re.I) and re.fullmatch(
            r"/(?:(?:[a-z]{7,15}/)?[a-z]{7,15}[0-9]{2,6}|[0-9]{6,12})(?:\.html?)?/?", path):
        page("diving-domain-with-unrelated-standalone-product-catalog",
             not re.search(r"スキューバ|ダイビング|体験ダイブ|海中ツアー|水中撮影", text)
             and any(distinct(re.compile(group), text) >= threshold for group, threshold in (
                 (r"天然石|真鍮|クラウンベゼル|フリーサイズ|直径約|磨き布|ペンダントトップ|腕周り", 5),
                 (r"プリザーブドフラワー|花時計|入れて発送|ノークレーム|配送中の破損|ラッピング", 5),
                 (r"アイアン脚|板材|奥行き\d|手回しのプラスドライバー|取り付け用のビス|椅子は付いて", 5),
                 (r"五月人形|端午の節句|次回窯入れ|立派な兜|無料ラッピング|発送の目安|素材[：:]陶器", 5),
             )))
    if host and path in ("", "/"):
        query = address.query
        page("tourism-domain-monthly-archive-with-corrupted-dating-queries",
             bool(re.search(r"(?:^|[.-])(?:kankou|kanko|tourism)\.", host))
             and bool(re.search(r"(?:^|&)m=\d{6}(?:&|$)", query))
             and bool(re.search(r"(?:^|&)paged=\d+(?:&|$)", query))
             and bool(re.search(r"(?m)^.{0,14}(?:セフレ|出会い系).{0,45}[?？]\s*$", text))
             and distinct(re.compile(r"セフレなお祝い|お腹と話す|を有効にします|"
                                     r"誕生日です[。\n]|お祝いが帰ってきた|セフレへのハイ"), text) >= 3
             and not re.search(r"観光協会|観光案内|観光スポット|入館料|交通アクセス|開催日程", head))
        page("tourism-domain-author-archive-with-repeated-dating-query-corruption",
             bool(re.search(r"(?:^|[.-])(?:kankou|kanko|tourism)\.", host))
             and bool(re.search(r"(?:^|&)(?:author|cat)=\d+(?:&|$)", query))
             and len(re.findall(r"セフレ|出会い系", text)) >= 8
             and distinct(re.compile(r"日本政府は申請書|輸出しないと報告|フッ化水素|"
                                     r"経済制裁の始まり|日本は日本を|セフレの日付"), text) >= 3
             and not re.search(r"観光協会|観光案内|観光スポット|入館料|交通アクセス|開催日程", head))
    if re.fullmatch(r"/[^/]*(?:netflix|streaming|prime-video)[^/]*/?", path, re.I):
        page("streaming-lineup-with-repeated-literal-sense-errors",
             bool(re.match(r"(?:ja|jp|jpn)\.", host, re.I))
             and len(re.findall(r"(?m)^(?:発売|配信|公開)日[：:]\s*20\d{2}年\d{1,2}月", text)) >= 5
             and distinct(re.compile(r"お金でロバを拭|彼らはその本を投げ|山火事.{0,20}ストライキ|"
                                     r"彼は戻ってきました、人々|寝台ショー|クラッキング警官|"
                                     r"彼らの火を燃やし続け"), text) >= 3)
    if re.fullmatch(r"/t\d{15,22}/?", path):
        affiliate_course = re.compile(r"(?m)^受講者数[\d,]+名を超える.{0,20}アフィリエイト教材\s*$")
        first_lines = text.splitlines()[:3]
        page("unrelated-affiliate-course-wrapping-reposted-social-replies",
             bool(affiliate_course.search(head)) and bool(affiliate_course.search(text[-500:]))
             and bool(re.search(r"(?m)^.{0,18}商品で[\d,.]+万円稼ぎ出す仕組み\s*$", head))
             and (len(re.findall(r"(?m)^返信先:\s*@", text)) >= 3
                  and distinct(re.compile(r"グループリーグ|ワールドカップ|日本代表|勝ち点|予選突破"), text) >= 4
                  or len(text.splitlines()) >= 16 and all(line in text[-400:] for line in first_lines[:2])
                  and len(re.findall(r"(?m)^\S[^。\n]{0,15}\n[^\n]{12,180}$", text[120:-100])) >= 5))
    page("gaming-video-transcript-prepended-with-unrelated-dating-pitch",
         bool(re.fullmatch(r"/[^/]*(?:攻略動画|ゲーム実況|プレイ動画)[^/]*/\d+/?", path))
         and distinct(re.compile(r"日本最大級|出会えた確率|恋愛マッチングサイト|無料で登録|出会い系アプリ"),
                      head[:285]) >= 3
         and bool(re.search(r"(?m)^(?:こんにちは|こんばんは)[、!！]", head))
         and distinct(re.compile(r"生放送で|配信主|初見さん|チャンネル登録|コメントを残して"), text) >= 4
         and not re.search(r"提供[：:]|スポンサー[：:]|タイアップ|プロモーションを含みます", head))
    page("personal-team-domain-with-unrelated-casino-payment-pitch",
         bool(re.match(r"(?:www\.)?team[a-z]{4,16}\.(?:com|org|net)$", host, re.I))
         and bool(re.fullmatch(r"/20\d{2}/\d{1,2}/\d{1,2}/[a-z0-9-]+-(?:payment|deposit|bonus)/?", path))
         and distinct(re.compile(r"オンラインカジノ|フリースピン|最低入金額|入金上限金額|出金条件|"
                                 r"クレジットカード|国内銀行送金|電子ウォレット"), text) >= 7
         and bool(re.search(r"(?m)^.{2,38}で利用できる入金方法\s*$", text))
         and len(re.findall(r"(?m)^.{0,45}入金(?:手順|できない場合の原因と対処法)\s*$", text)) >= 2)
    page("institutional-domain-with-standalone-auto-parts-copy",
         bool(re.search(r"(?:\.com\.br|\.org|\.edu|\.ac\.[a-z]{2})$", host, re.I))
         and bool(re.fullmatch(r"/(?:ssauto|autos|autoparts|moto)/\d{3,}[a-z]{3,8}\d{5,}/?", path))
         and distinct(re.compile(r"国内仕様|台湾仕様|レーシングスタンド|純正スタンド|"
                                 r"鏡面仕上げ|レース車両|車体|細部の仕様"), text) >= 5
         and not re.search(r"論文|訓練|整備士資格|機械工学|自動車部|研究室", text))
    page("historic-site-domain-with-unrelated-travel-magazine-catalog",
         bool(re.search(r"(?:joseki|joushi|shiroato|castle-ruins|castle-site)[a-z-]*\.", host, re.I))
         and bool(re.fullmatch(r"/[a-z][a-z-]{2,22}-\d{3,}/?", path))
         and bool(re.search(r"(?m)^20\d\d[./-]\d{1,2}[./-]\d{1,2}\s*$", head))
         and bool(re.search(r"(?m)^Trima[^。\n]{0,18}(?:編集部|雑学)\s*$", head))
         and (
             bool(re.search(r"(?m)^目次\s*$", text))
             and len(re.findall(r"(?m)^- [^。\n]{4,75}$", text)) >= 5
             or len(re.findall(r"(?m)^Trima[^。\n]{0,18}(?:編集部|雑学)\s*$", text)) >= 5
             or bool(re.search(r"(?m)^Trima[^。\n]{0,18}編集部のアカウントです。$", head))
             and len(re.findall(r"(?m)^[^。！？\n]{9,70}$", text)) >= 7
         )
         and not re.search(r"遺跡保全|城跡の公式|史跡保存|城跡見学|文化財管理", head))
    page("animal-therapy-domain-with-unrelated-comic-search-funnel",
         bool(re.search(r"(?:petpartners|animaltherapy|therapydogs|petassisted)[a-z-]*\.", host, re.I))
         and bool(re.fullmatch(r"/[a-z0-9]+(?:-[a-z0-9]+){1,5}/?", path))
         and len(re.findall(r"(?i)BookLive!?|コミックサイト|電子書籍サイト", text)) >= 2
         and distinct(re.compile(r"検索窓が開|作品名をクリック|無料試し読み|公式ページが開|"
                                 r"スマホの場合|クリックすれば読め"), text) >= 4
         and not re.search(r"補助犬|介助犬|保護犬|アニマルセラピー|動物介在|ペット介護", text))
    page("music-domain-with-standalone-loan-repayment-search-copy",
         bool(re.search(r"(?:jazz(?:server|club|station|radio)|orchestra|chambermusic|choir)\.", host, re.I))
         and bool(re.fullmatch(r"/(?:cash|casyu|loan|hensai|kyassy(u|uingu))[a-z0-9-]*\d+\.html?", path))
         and distinct(re.compile(r"返済.{0,9}遅れ|消費者金融|ブラックリスト|遅延損害金|取り立て|"
                                 r"金利|借入|滞納"), text) >= 6
         and not re.search(r"公演|演奏|アンサンブル|楽団|楽器|ジャズ|音楽|チケット", text))
    if re.fullmatch(r"/[a-z]+_[a-z0-9]{1,2}/[A-Za-z0-9+]{8,60}={0,2}/?", path):
        unclosed_locality = re.match(r"([一-龯々ヶ]{2,13}(?:町|村|市)\([一-龯々ヶ]{2,12}郡)\s", text)
        page("repeated-encoded-locality-slot-in-corrupt-tax-referral",
             bool(unclosed_locality) and text.count(unclosed_locality[1]) >= 4
             and len(re.findall(r"ふるさと納税一括検索サービス", text)) >= 2
             and distinct(re.compile(r"御礼品|返礼品|煩雑な手続き|寄附額|納税額が所得|還付される\)"), text) >= 5
             and not re.search(r"市役所|ふるさと納税担当|役場へ|お問い合わせ先", text))
    if re.fullmatch(r"/entry/20\d{2}/\d{1,2}/\d{1,2}/\d{5,8}/?", path):
        page("renovation-keywords-in-stitched-search-fragments",
             len(text.splitlines()) <= 5 and len(text) >= 290
             and distinct(re.compile(r"リビングダイニング|外断熱|サイディング|外壁塗装|シリコン系塗料|"
                                     r"現場監督|戸建て"), text) >= 5
             and distinct(re.compile(r"場所現場監督に|選択肢が多い、で|"
                                     r"こちら、それがサイディング|知っておきたいポイントを大工|"
                                     r"手間職人さんを|塗料で[\d,.]+万円お"), text) >= 3)
    if re.fullmatch(r"/[a-z]-\d{3,}\.(?:php|html?)/?", path):
        detached_dates_or_ranks = set(re.findall(r"(?m)[。）」]\s*(\d{1,3})\s*$", text))
        page("foreign-health-agency-route-with-stitched-japanese-search-results",
             bool(re.search(r"(?:saudereprodutiva|saludreproductiva|public-health|reproductive-health)\.", host, re.I))
             and (len(detached_dates_or_ranks) >= 5
                  or len(detached_dates_or_ranks) >= 3 and len(re.findall(r"[•·]|\[\s*\]|\(\s*\)", text)) >= 5)
             and len(text.splitlines()) >= 14
             and not re.search(r"保健局|性と生殖|保健省|生殖医療|母子保健", head))
    page("game-scraper-domain-with-unrelated-cosmetics-catalog",
         bool(re.search(r"(?:gta|game|minecraft)[a-z-]*scrap(?:er|ing)\.", host, re.I))
         and bool(re.fullmatch(r"/(?:product|item)/[a-z0-9-]+/[A-Za-z0-9]{3,12}/?", path))
         and distinct(re.compile(r"クレンジング|酸化皮脂|美容液成分|メイクアップ料|メーカー希望小売価格|"
                                 r"フローラルの香り|指先にさくらんぼ"), text) >= 5)
    page("unrelated-chat-domain-carrying-converted-japanese-campus-report",
         bool(re.search(r"(?:sohbet|chatroom|livechat)[a-z0-9-]*\.", host, re.I))
         and bool(re.fullmatch(r"/(?:univ|university|campus)/[^/]+/(?:report|news)/20\d{6}/?", path))
         and distinct(re.compile(r"學部|大學|醫療|委員會|壽命|座學|授與|認知癥|多數|參加"), text) >= 5
         and distinct(re.compile(r"公開講座|修了証書|受講者|市委託|教育委員會|耳科學"), text) >= 4)
    page("reposted-forum-translation-with-mixed-script-corruption",
         bool(re.match(r"\d{1,4}\s*[:：].{0,90}ID:", head))
         and bool(re.search(r"(?m)^機械翻訳です\s*$", head))
         and distinct(re.compile(r"[一-龯ァ-ヺ]{1,5}(?:∫|∑)[A-Za-z]{1,4}[一-龯]|"
                                 r"銀[a-z]{2,5}は|銀[A-Z] QRコード|借金[b-z]{2,5}者|"
                                 r"は[^。\n]{0,12}流行の寄付と戦"), text) >= 3)
    if re.fullmatch(r"/[^/]+-[a-z]{2}-[0-9]+_[0-9]+/[^/]+\.html?", path, re.I):
        main_group, item_slug = path.lstrip("/").split("/", 1)
        item_id = re.search(r"(?i)(?:^|-)b0[a-z0-9]{8}(?=-|\.htm)", item_slug)
        fields = re.findall(r"(?m)^(?:材質|電源|電圧|寸法|サイズ|容量|重量|作動時間|タンク容量)[:：]", text)
        if item_id and item_id[0].lstrip("-").upper() in text.upper() and len(set(fields)) >= 3:
            page("generated-retail-taxonomy-conflicts-with-item-specifications",
                 any(group.search(main_group) and product.search(head[:170]) for group, product in (
                     (re.compile(r"おむつ(?:取り?替え|交換|替え)|おしりふき|紙おむつ"),
                      re.compile(r"(?m)^(?:製品[：:]|商品名[：:]|商品[：:])?.{0,10}(?:加湿器|電子計測器|除湿器|ミキサー)")),
                     (re.compile(r"釣り用具|楽器用アクセサリ[ー]?"),
                      re.compile(r"(?m)^(?:製品[：:]|商品名[：:]|商品[：:]).{0,12}(?:携帯扇風機|ミシン|炊飯器)")),
                 )) and bool(re.search(r"パッケージ(?:の)?(?:内容|リスト)[:：]", text))
                 and distinct(re.compile(r"空焚き防止|電子電流|通常の時間|水使用時間|"
                                         r"綿にムラが生じ|綿を取り出して注ぎ|ネジが締まるように入れず"), text) >= 3)
    if re.fullmatch(r"/admin-\d+/?", path):
        page("piecework-keyword-page-with-incompatible-granular-sentence-joins",
             bool(re.match(r"(?:副業\s+内職|内職\s+副業|在宅\s+内職)\s*\n", text))
             and distinct(re.compile(r"仲介サイト|仲介手数料|ラベル貼り|モーニングコール|税金の申告|"
                                     r"電話だけで出来るお仕事"), text) >= 5
             and distinct(re.compile(r"副業にもいろいろな仕事をします|内職の仕事内容はそのまま|"
                                     r"副業で得た時に仲介手数料|そのおかげで仕事をしている企業|"
                                     r"出費がかかることが多く募集している"), text) >= 3)
        query_heading = re.fullmatch(r"(?:[ぁ-ゖァ-ヺ一-龯々ー]{1,18}[ \t]+){2,6}"
                                     r"[ぁ-ゖァ-ヺ一-龯々ー]{2,18}", text.split("\n", 1)[0])
        page("spaced-person-query-with-repeated-and-incompatible-source-clauses",
             bool(query_heading) and len(text) <= 1400
             and bool(re.search(r"(?m)^([^。\n]{8,85})(?:と思われています|とも言われています)。\1(?:と思われている|とも言われている)。", text))
             and distinct(re.compile(r"(?:自己PR欄|志望理由欄)には[^。\n]{0,45}(?:投げつけられ|放送で|に乱入)|"
                                     r"では一番[^。\n]{2,23}(?:高い|低い)のが[^。\n]{1,22}のことを挙げ|"
                                     r"のHP上には[^。\n]{1,20}出演し共演|ののキャラをして"), text) >= 2)
        repeated_prefixes = Counter(re.findall(r"(?:\A|[。\n])([^\s。！？]{5,22}?)(?=、|である|であった|でした)", text))
        page("tokenized-search-query-heading-with-repeated-broken-rewrite",
             bool(query_heading)
             and bool(re.search(r"であるでした|だったである|したでした|ことをでした", text))
             and max(repeated_prefixes.values(), default=0) >= 2
             and not re.search(r"(?m)^出典[：:]|^引用[：:]|^参考文献|^小説本文", head))
    if re.fullmatch(r"/\d{1,4}\.html?", path):
        clauses = [line.strip() for line in text.splitlines() if line.strip()]
        page("unattributed-affiliate-fragments-with-unclosed-clauses",
             len(clauses) >= 24 and sum(line.endswith(("、", "ので", "や")) for line in clauses) >= 9
             and distinct(re.compile(r"アフィリエイター|アフィリエイトセミナー|外注やツール|"
                                     r"ASPアフィリ|情報商材|副業でサイドビジネス|メルマガを新規に"), text) >= 5
             and not re.search(r"(?m)^引用[：:]|^出典[：:]|^著者[：:]|^\d{4}年\d{1,2}月", head))
    if re.fullmatch(r"/\d{1,4}/\d{4,}/?", path):
        page("medical-advice-rewrite-with-several-impossible-translation-slots",
             len(re.findall(r"(?m)^\d{1,2}\s*[.．、][^\n]{5,65}\n", text)) >= 4
             and bool(re.search(r"外傷|化学物質|応急処置|緊急事態|診断", head))
             and distinct(re.compile(r"水たまりの流れ|ソラリウムを過度に摂取|"
                                     r"水疱.{0,10}小文字|小文字.{0,10}マージ|"
                                     r"化学燃焼|以上の子供または人を燃や|熱い、沸騰水に寄りかか"), text) >= 3)
    if re.fullmatch(r"/\d{1,2}-(?:(?:fascinating|interesting|little-known|surprising)-facts-about|"
                    r"scientific-benefits)-[a-z0-9-]+/?", path):
        page("translated-trivia-republication-with-ad-markup-and-damaged-word-senses",
             bool(re.match(r"(?:ja|jp|jpn)\.", host, re.I))
             and bool(re.search(r"top-leaderboard|leaderboard-limit|トップリーダーボード制限|adslot[ -]", head))
             and len(re.findall(r"(?m)^\d{1,2}\s*\.[^\n]{4,90}$", text)) >= 5
             and distinct(re.compile(r"愛の興味を持|手紙に隠された|"
                                     r"が.{0,16}の声に乗った|雪の中で場所を取り|"
                                     r"強い女性キャラクターをフィーチャー|物語のプロットを孵化|"
                                     r"小説.{0,20}彼が彼の仕事|始めたスカーレット・レター彼が|"
                                     r"杯のジョーに匹敵|グリーンの前で運動したバイカー|"
                                     r"あなたのビジョンに適しています|SSS色の手紙|S S S色の手紙"), text) >= 2)
    if host and re.search(r"(?:^|&)cat=\d+(?:&|$)", address.query):
        lines = [line for line in text.splitlines() if line.strip()]
        page("game-discussion-archive-with-duplicated-opening-and-unrelated-fragments",
             bool(re.search(r"(?:^|&)paged=\d+(?:&|$)", address.query))
             and len(lines) >= 24 and len(lines[0]) >= 45 and lines[:1] == lines[1:2]
             and distinct(re.compile(r"敵レベル|ビルド|アルケイン|フレーム|火力|MOD構成|ソーティ"), text) >= 5
             and (bool(re.search(r"(?m)^[(IVX]+年[IVX]+組|^クラス数混乱", head))
                  or bool(re.search(r"(?m)^.{0,28}\d{1,2}クラス.{0,35}[セタヨ].{0,18}$", head)))
             and len(re.findall(r"(?m)^[ァ-ヺ]{2,4}\s*$", head)) >= 3)
    if re.fullmatch(r"/(?:star|person|talent)/[^/]{2,45}/[^/]{2,30}/?", path):
        page("rumor-search-template-with-explicitly-unrelated-search-snippets",
             bool(re.match(r".{2,56}\s*[×x]\s*.{2,35}の噂って[!?！？]+", head))
             and bool(re.search(r"(?i)wiki(?:pedia|ペディア).{0,65}記載はありません", head))
             and bool(re.search(r"関連の(?:ある物が|あるものが|ある記事が)見つかりません", head))
             and bool(re.search(r"関連度の低い記事.{0,14}信憑性の低い記事", head))
             and bool(re.search(r"人工知能の分析した.{0,55}関連度.{0,10}注目度", text))
             and (len(re.findall(r"(?m)^20\d\d年\d{1,2}月\d{1,2}日\s+\.{3}", text)) >= 2
                  or distinct(re.compile(r"\((?:Yahoo[!！]?知恵袋|NAVERまとめ|教えて!goo)\)", re.I), text) >= 2))
    if re.fullmatch(r"/(?:result|kekka)/\d+(?:result|kekka)\d+/?", path):
        page("fortune-result-with-multiple-broken-phrase-slots",
             bool(re.search(r"おすすめの占い|相性占い|占い結果", text))
             and bool(re.search(r"(?m)^ワンポイントアドバイス\s*$", text))
             and distinct(re.compile(r"(?:人数|回数)あや(?:性別|年齢)|ロマンチェックで|"
                                     r"必要素可決|必要[ー−]要素を|あなた(?:が|の)するは"), text) >= 2)
    if re.fullmatch(r"/(?:post-|archives?/)\d+/?", path):
        page("incident-rewrite-with-empty-subject-and-unrelated-keyword",
             bool(re.search(r"(?m)^(?:事件の概要|事件の詳細|事件の経緯)\s*$", head))
             and bool(re.search(r"として、の(?:社員|教員|職員|店員|従業員|男性|女性)が", text))
             and bool(re.search(r"(?:特定|判明|確認)には[一-龯々ァ-ヺA-Za-z]{2,14}"
                                r"(?:戦|試合|選手|祭|大会|公演)でした", text))
             and bool(re.search(r"(?im)^.{1,45}(?:顔画像|Facebook|SNS).{0,45}(?:家族|生年月日|動機)", text)))
    if re.fullmatch(r"/\d{2,}-[a-z0-9]{3,6}-\d{2,}\.html?", path) and len(
            re.findall(r"(?m)^[1-5]\.00\s*\n[^\n]{2,50}\n[^\n]{1,35}\n", text)) >= 7:
        product_topics = (
            r"ラインキャパ|スピニングリール|ベイトリール",
            r"バランスボール|フットポンプ|ヨガマット",
            r"ベルト通し|ダブルジッパー|ショルダーベルト",
            r"ディスクプレーヤー|プリンター|紙詰まり",
            r"ウエスト|サイズ感|ニット素材",
            r"シーズン[0-9１-９]|番組として|ドラマから",
            r"車検|車両型式|代車",
        )
        page("unrelated-numeric-route-packed-with-copied-review-cards",
             bool(re.search(r"(?:vet|veterin)[a-z]*\.", host, re.I))
             and (
                 distinct(re.compile(r"映画|監督|脚本|映像|主演|キャスト|限定版|アクション"), text) >= 5
                 or distinct(re.compile(r"森林保全|水道局|鉄道|水源|放送回|続編|視聴完了|作品内"), text) >= 4
             )
             and bool(re.search(r"(?m)^Amazon[ 　]+カスタマー\s*$", text))
             or bool(re.search(r"(?:drama|tv\d+|sinetron|television)", host, re.I))
             and sum(bool(re.search(topic, text)) for topic in product_topics) >= 3)
    if re.fullmatch(r"/(?:pk|keyword|search|tag)/[^/]+/?", path):
        page("keyword-route-with-unattributed-truncated-editorial-islands",
             len(re.findall(r"(?im)(?:\.{3}|…)\s*more\s*(?:\n|$)", text)) >= 4
             and distinct(re.compile(r"(?m)^(?:STEP\s*\d+|[■●◇][^\n]{5,55}|"
                                     r"【(?:材料|アイテム情報|作り方)】|価格[：:])"), text) >= 6
             and not re.search(r"(?im)^出典[：:]|^転載元[：:]|^著者[：:]|^https?://|"
                               r"^.+(?:タグ|キーワード|検索)の(?:記事|結果)(?:一覧)?\s*$", head))
    if re.fullmatch(r"/\d{3,}/?", path):
        fortune_offers = Counter(re.findall(r"(?m)^[^\n]{0,65}(?:他の占い|別の占い|他の鑑定)"
                                             r"[^\n]{4,90}$", text))
        page("empty-fortune-result-with-duplicated-referral",
             len(re.findall(r"(?m)^【\s*】\s*\n意味[：:]\s*$", text)) >= 2
             and max(fortune_offers.values(), default=0) >= 2
             and bool(re.search(r"(?m)^投稿日[：:]\s*\d{4}[-/]\d{2}[-/]\d{2}\s+更新日[：:]\s*$", text))
             and bool(re.search(r"(?m)^関連記事\s*$", text)))
    if path in ("", "/"):
        page("forum-front-page-with-unrelated-cash-windfall-referral",
             bool(re.search(r"(?:^|\.)(?:bbs|forum|board)\.", host, re.I))
             and len(text) <= 900
             and bool(re.search(r"(?m)^-\s+\S+\s+URL\s*\n\d{4}/\d{2}/\d{2}", head))
             and distinct(re.compile(r"(?:ただ|タダ|無料)でお金|借金.{0,20}完済|人生.{0,8}(?:180度|変わり)|"
                                     r"この場を借り|都合のいいこと"), text) >= 4
             and bool(re.search(r"(?m)^(?:是非|ぜひ).{0,19}(?:みて|見て).{0,13}\nhttps?://\S+\s*$", text))
             and not re.search(r"給付金|社会福祉協議会|公的支援|行政の支援|自治体", text))
    if re.fullmatch(r"/(?:movies?-info|film-info)/\d+/?", path):
        page("film-lookup-route-filled-with-software-download-tutorials",
             distinct(re.compile(r"(?m)^(?:ステップ\s*[1-9①-⑨]|まとめ[：:]?\s*$)"), text) >= 4
             and len(re.findall(r"(?m)^(?:ステップ\s*[1-9①-⑨]|まとめ[：:]?\s*$)", text)) >= 10
             and distinct(re.compile(r"コピーガード|モジュール|レンチ.{0,10}アイコン|"
                                     r"出力フォーマット|プロファイル切替|ダウンローダー|リッピング"), text) >= 5
             and len(re.findall(r"を例として|具体的な変換方法|操作手順|方法を参照してください", text)) >= 4
             and not re.search(r"(?m)^(?:作品情報|映画のあらすじ|スタッフ・キャスト|出演者一覧|上映スケジュール)\s*$",
                               head))
    page("empty-regional-service-results-padded-with-availability-claims",
         bool(re.fullmatch(r"/[a-z-]+/[a-z-]+/[a-z0-9-]+/?", path))
         and bool(re.search(r"(?m)^.{2,20}エリアの(?:風俗|デリヘル)情報\s*$", head))
         and bool(re.search(r"(?:ご指定の.{1,22}には|指定された.{1,22}に)登録(?:店|店舗)がありません", text))
         and bool(re.search(r"(?:エリアから探す|条件を変更).{0,35}(?:再度検索|検索し直)", text))
         and distinct(re.compile(r"風俗の利用がおすすめ|(?:デリヘル|風俗店).{0,12}が複数あります|"
                                 r"精一杯おもてなし|在籍するお店|観光スポット満載"), text) >= 3)
    page("activity-program-localization-with-unrelated-word-senses",
         bool(re.search(r"/(?:teambuilding-events|team-building|event-categories|workshops)/", path))
         and bool(re.match(r"(?:プログラムの概要|アクティビティの概要|イベント概要)\s*\n", text))
         and distinct(re.compile(r"非公式で脅かすことにない|延伸すると|"
                                 r"代表団は[^。\n]{0,38}通電|インスタントとして尊敬|"
                                 r"会議の活性剤|医師[^。\n]{0,45}行わています|"
                                 r"技術の詳述を一歩一歩デザイン"), text) >= 3
         and distinct(re.compile(r"従業員|マインドフルネス|参加者|"
                                 r"セッション|会議|ワークショップ|チーム"), text) >= 4)
    page("qa-repost-with-empty-age-and-mismatched-question-excerpts",
         bool(re.fullmatch(r"/(?:archives|posts?|article)/\d+/?", path))
         and bool(re.search(r"(?m)^.{5,70}(?:-|ー)[：:](?:-|ー)歳\s*$", head))
         and bool(re.search(r"(?m)^記事へのコメント\s*$", text))
         and distinct(re.compile(r"注目ランキング|新着記事一覧|関連するカテゴリー|"
                                 r"次回のコメントで使用するため"), text) >= 3
         and len(re.findall(r"(?m)^.{14,150}[？?]\s*$", text)) >= 3
         and len(re.findall(r"(?m)^.{25,230}(?:…|\.\.\.)\s*$", text)) >= 3
         and not re.search(r"(?m)^(?:出典|引用元|元の質問)[：:]|^https?://", text))
    if re.fullmatch(r"/(?:detail|goods|item)/\d+\.html?", path):
        stamps = re.findall(r"(?m)^(20\d\d-\d\d-\d\d \d\d:\d\d):(\d\d)\s*$", text)
        clockwork = sum(a == b and int(x) - int(y) == 1
                        for (a, x), (b, y) in zip(stamps, stamps[1:]))
        page("localized-retail-card-with-batched-timestamps-and-corrupted-reviews",
             clockwork >= 2 and bool(re.search(r"(?m)^価格[：:] *[￥¥]?\s*\n\d", text))
             and distinct(re.compile(r"防ブルーレイ|外観は大気上|"
                                     r"最初のテ-ブルでは|閃光が現れません|重い影がない|"
                                     r"兄の宅急便|社長は大気を直接に|価格は泥棒より|"
                                     r"鶏肉のリブのデザイン|光ファイバが柔らかくて|"
                                     r"箱を持ってきてください。開けたら"), text) >= 3)
        page("localized-clothing-card-with-batched-review-timestamps-and-consumption-phrases",
             clockwork >= 2 and bool(re.search(r"(?m)^価格: *[¥￥]?\s*\n\d", text))
             and len(re.findall(r"[绵韩飞绒货购装裤码]", text[:200])) >= 3
             and distinct(re.compile(r"子供の冬服|生地|カシミヤ|薄さも厚さも|宅配便|ファッション"), text) >= 4
             and bool(re.search(r"一回食べたら何セット|服を買ってあげて、頭が痛い|肥料をプレして", text)))
    page("templated-dating-profile-with-repeated-registration-funnel",
         bool(re.fullmatch(r"/(?:deaikei_[a-z_]+/)?(?:sokuhame|aite|match)\d{4,}/?", path, re.I))
         and text.count("↓") >= 8
         and distinct(re.compile(r"(?m)^(?:登録(?:地域|エリア)|誰似|似てる(?:有名人|芸能人)|"
                                 r"利用目的|スタイル|ルックス|"
                                 r"タイプの芸能人|興味のあるコスプレ)[：:]"), text) >= 5
         and len(re.findall(r"年齢認証 *\(年齢確認\)|年齢認証 *（年齢確認）", text)) >= 3
         and bool(re.search(r"(?:出会い?系|出合い系|出逢い系|であいけい|マッチング)"
                            r"(?:アプリ|サイト|コミュ)", text[-600:]))
         and bool(re.search(r"(?m)^[⇒→][^。\n]{2,75}(?:詳細|登録)はこちら\s*$", text)))
    if re.search(r"(?:pharmacy|pills|discount-?med)[\d-]*\.", host, re.I) and re.fullmatch(r"/\d+/?", path):
        diary_lines = text.strip().splitlines()
        page("short-unrelated-diary-fragments-on-pharmacy-retail-route",
             11 <= len(diary_lines) <= 28 and 180 <= len(text) <= 650
             and bool(re.search(r"[ヾヽ(].*[ヾヽ(]", diary_lines[0]))
             and bool(re.search(r"顔文字|ﾖﾛｼｸ|ヨロシク|よろしく|[ゝ・ω]", diary_lines[-1]))
             and sum(bool(re.search(terms, text)) for terms in (
                 r"ご飯|人参|じゃこ|ブロッコリー|豆腐|夕食|お弁当",
                 r"不動産投資|株価|円安|香港ドル|為替|外貨預金",
                 r"新幹線|[一-龯]{2,7}線を|航空券|海外旅行|ギャンブル",
                 r"ゲーム|Portable|攻略|アニメ|ガチャ|スイッチ",
             )) == 4
             and not re.search(r"医薬品|処方|服薬|副作用|かかりつけ薬局", text))
    if (re.search(r"(?:tadalafil|vardenafil|sildenafil|dapoxetine|discount-?pills|generic-?pharmacy)",
                  host, re.I) and re.fullmatch(r"/(?:date/|archives?/)?20\d{2}[/_-]\d{1,2}[/_-]\d{1,2}/?", path)):
        diary_lines = [line for line in text.splitlines() if line.strip()]
        page("unrelated-pseudo-diary-on-dated-drug-commerce-route",
             12 <= len(diary_lines) <= 40 and 200 <= len(text) <= 1100
             and bool(re.search(r"(?m)^(?:[^\n]{0,26}[)）☆][^ぁ-龯\n]{0,6})?"
                                 r"(?:こんばんは|こんにちは|おはよう)", head))
             and sum(bool(re.search(topic, text)) for topic in (
                 r"お気に入りのメニュー|お弁当|夕食|冷蔵庫",
                 r"(?:ペソ|ドル|為替).{0,6}(?:取引|交換)|不動産投資",
                 r"\d{1,2}時の電車|航空券|終電|在来線",
                 r"ママさん|お父さん|夕方帰ってくる|やせられる",
             )) == 4
             and not re.search(r"医薬品|処方|服薬|副作用|かかりつけ薬局|薬剤師", text))
    if (training := re.match(r"([一-龯々ヶケ]{2,10}(?:市|町|区|村))内?で[^。\n]{0,42}"
                             r"(?:犬しつけ教室|犬のしつけ教室|ドッグスクール)なら(?:ココ|ここ)", head)):
        slot = re.escape(training[1]) + r"の(?:犬(?:の)?しつけ教室|ドッグスクール)"
        page("municipality-keyword-in-generic-dog-training-sentences",
             bool(re.fullmatch(r"/\d+\.html?", path))
             and len(re.findall(r"(?m)^" + slot, text)) >= 5
             and sum(bool(re.search(r"(?m)^" + slot + continuation, text)) for continuation in (
                 r"で教わるまでもなく", r"に通うのが難しくても",
                 r"のトレーナーがよく", r"で教える[^。\n]{0,12}対策",
             )) >= 3
             and not re.search(r"営業時間|教室名|所在地|出張可能|当教室|ご予約|アクセス[:：]", text))
    if re.search(r"(?:^|&)paged=\d+(?:&|$)", address.query if host else ""):
        pitches = re.findall(r"(?ms)^[^\n]{2,35}さんの\n[「『][^\n]{5,70}って、どうなんだろう\?\n"
                             r".{100,650}?試してみるのもいいかも。\n", text[:4500])
        page("duplicated-affiliate-pitch-in-unrelated-course-archive",
             len(pitches) > len(set(pitches)) and len(text.splitlines()) >= 48
             and sum(bool(re.search(group, text)) for group in (
                 r"株初心者|損切り確定|トレード手法",
                 r"ゴルフレッスン|ゴルフスイング|ゴルフ上達",
                 r"犬のしつけ|ドッグスクール|愛犬の問題行動",
                 r"モテる方法|元カリスマホスト|恋愛教材",
             )) >= 3
             and distinct(re.compile(r"購入者の口コミ|噂も聞く|試してみる|"
                                     r"インチキではなさそう|って言っているけど"), text) >= 3)
    if (routed_fees := re.search(r"(?m)^([^\n]{2,14}(?:市|町|区|村))の探偵料金について[ \t]*\r?$", raw)):
        fees = normalize(raw[routed_fees.start():])
        location = re.escape(normalize(routed_fees[1]))
        if (bool(re.search(r"/(?:new|office|area)/[^/]*(?:tanteijimusyo|tantei-office)[^/]*\.html?$", path, re.I))
                and bool(re.search(r"(?m)^" + location + r"(?:メモ|の基本情報)\s*$", head))
                and bool(re.search(location + r"(?:探偵調査項目|の探偵事務所相談窓口)", head + text[600:1450]))
                and "依頼料が異なる理由" in fees
                and distinct(re.compile(r"調査を行うスタッフ|車両や機材|"
                                        r"広告費などの関係|調査にかける日数|依頼内容の難易度"), fees) >= 4
                and distinct(re.compile(r"料金事例|料金表ではありません|調査の難易度[・、]期間|見積りをご希望"), fees) >= 3
                and (fee_end := re.search(r"(?m)^(?:探偵事務所について|調査士会グループ理念|"
                                          + location + r"調査データ)\s*$", raw[routed_fees.end():]))):
            findings["standardized-fee-copy-inside-municipality-detective-guide"] = [
                (routed_fees.start(), routed_fees.end() + fee_end.start())
            ]
    page("translated-fiction-with-foreign-search-phrases-in-dialogue",
         len(re.findall(r"[「」]", text)) >= 8
         and bool(re.search(r"(?:第?\d{1,4}章|登場人物|地の文)", text))
         and len(re.findall(r"(?:北京|上海|南京|杭州|深圳|广州|成都|重庆|武汉|苏州|天津)"
                            r"[一-龯A-Za-z]{0,10}(?:论坛|楼凤网|夜网|桑拿网)", text)) >= 3
         and bool(re.search(r"[ァ-ヺぁ-ゖ][一-龯]{2,3}[一-龯A-Za-z]{0,10}"
                            r"(?:论坛|楼凤网|夜网|桑拿网)[ァ-ヺぁ-ゖ一-龯]", text)))
    page("unrelated-diary-on-political-campaign-domain",
         bool(re.search(r"(?:forcongress|forsenate|forgovernor|forcouncil|forassembly)\.", host, re.I))
         and bool(re.fullmatch(r"/[一-龯々ぁ-ゖァ-ヺー]{3,20}/?", path))
         and len(re.findall(r"(?m)^.{5,85}(?:[wｗ]{1,4}|（笑）|だわ)\s*$", text)) >= 4
         and bool(re.search(r"(?m)^.{0,15}(?:社長|大統領|市長|議員)[ \t]+"
                            r"[^。\n]{4,35}(?:観光|釈明|記者会見|会談|辞任|演説)$", text[-110:]))
         and not re.search(r"日本語(?:版|ページ|訳)|対訳|選挙活動|立候補|翻訳[:：]|出典[:：]", text))
    if (re.fullmatch(r"/(?:kaden|appliance|electronics)\d*/?", path, re.I)
            and re.search(r"(?:^|&)m=\d{8}(?:&|$)", address.query if host else "")):
        cards = re.findall(r"(?m)^([^\n]{4,95})\n\1\n商品番号\s+\w+\s*\n販売価格\s+", text)
        page("unrelated-copy-pasted-catalog-under-appliance-date-archive",
             len(set(cards)) >= 3 and
             sum(bool(re.search(group, text)) for group in (
                 r"洗顔|お肌|フェイスパック|化粧水",
                 r"賞味期限|焼き菓子|パウンドケーキ|温めてお召し上がり",
                 r"フラワーギフト|開花期間|ひな人形|ウェア|インテリア",
             )) >= 2
             and not re.search(r"エアコン|電子レンジ|掃除機|空気清浄機|炊飯器|"
                               r"正規取扱店|送料について|特定商取引法", text))
    page("rewritten-personal-skincare-steps-on-job-search-domain",
         bool(re.search(r"(?:haken|kyujin|tenshoku|shigoto)[a-z\d-]{0,22}\.", host, re.I))
         and bool(re.fullmatch(r"/20\d\d/\d\d/\d\d/[^/]{4,60}/?", path))
         and distinct(re.compile(r"洗顔フォーム|クレンジング|肌荒れ|角栓汚れ|"
                                 r"メイクを[^。\n]{0,14}落とす|洗い流し"), text) >= 4
         and distinct(re.compile(r"(?:良く|よく|悪く)ないない|[をが]るよく(?:こす|流)|"
                                 r"泡で筒うよう|を泡し洗|顔を包み込むように[、,][^。\n]{0,16}含ませる"), text) >= 3
         and not re.search(r"化粧品メーカーで働|新人研修|職場の人から|させていただいたお仕事", text))
    if (re.fullmatch(r"/[a-z]{2,10}\d{1,2}/?", path, re.I)
            and re.search(r"(?:^|&)p=\d+(?:&|$)", address.query if host else "")
            and 210 <= len(text) <= 980):
        merchant_names = Counter(re.findall(r"([一-龯ァ-ヺー]{2,15}(?:庵|園|農園|農場|商店|堂|工房))の", text))
        page("unattributed-merchant-description-on-numeric-publishing-route",
             max(merchant_names.values(), default=0) >= 2
             and distinct(re.compile(r"高級百貨店|お値打ち価格でご提供|贈答用|"
                                     r"高品質(?:メロン|いちご|みかん|果物)|格付けが上|"
                                     r"ギフトの代名詞|老若男女問わずに喜ばれる"), text) >= 4
             and bool(re.search(r"一木一果|(?:摘み取り|摘果|受粉|剪定)[^。\n]{0,45}(?:収穫|果実)", text))
             and not re.search(r"取材|問い合わせ先|当店|当園|当社|公式サイト|ご注文|出典|"
                               r"参加店舗|提供[：:]|https?://", text))
    page("localized-qa-mirror-with-anonymous-answers-and-corrupted-claims",
         bool(re.fullmatch(r"/(?:report|answers|questions)/[a-z\d]+(?:-[a-z\d]+){7,}/?", path, re.I))
         and len(re.findall(r"(?m)^答え *\d+[：:]?\s*$", text)) >= 2
         and distinct(re.compile(r"それを取って|同じ線で考えて|私の論理的思考を使用|"
                                 r"現在では\d{1,3}か国[^。\n]{0,18}人々を感染|"
                                 r"だけのサンプル広告|今[、,]あなたが立ち往生して"), text) >= 3
         and not re.search(r"(?m)^https?://|^出典[：:]|^転載元[：:]|^回答者[：:]", text))
    page("disconnected-advice-under-file-download-brand",
         bool(re.fullmatch(r"/tr[_-][a-z][a-z0-9]{0,3}/?", path, re.I))
         and bool(re.search(r"(?:download|warez|fileshare)[a-z0-9-]*\.", host, re.I))
         and 350 <= len(text) <= 2100 and bool(re.search(r"(?m)^[^。\n]{8,50}\n[^。\n]{8,50}\n", head))
         and any(distinct(re.compile(group), text) >= 4 for group in (
             r"幼児教育|お子さん|保護者|早期教育|育児|幼稚園",
             r"税務相談|税理士|事務所の規模|経営者|税務代理|税務書類",
             r"初診料|健康診断|医師会|予防接種|受診|診療所",
         ))
         and not re.search(r"ファイルをダウンロード|配布ファイル|資料提供|著者[：:]|"
                           r"出典[：:]|運営会社|実施団体|商標", text))
    page("corrupted-localization-on-nested-video-gallery",
         bool(re.fullmatch(r"/[a-z]{3,10}/[a-z][a-z0-9_-]{3,24}/(?:gallery)?\d{3,8}/index\.html?", path, re.I))
         and 420 <= len(text) <= 1700 and len(re.findall(r"[。!?]", text)) >= 8
         and distinct(re.compile(r"(?:豪華な|マッサージを)バックさせ|客-のための顧客|"
                                 r"問題で[^。\n]{0,30}横たわらず|盗まれた底|底を摩擦|"
                                 r"若い人への興味を持つために来た破産|黒い適された数値が出る|"
                                 r"よいすばらしさがされた|娘に飽きなかった|"
                                 r"それは穏やかに大胆に護衛した"), text) >= 2)
    page("english-course-referral-with-repeated-official-offer-placeholders",
         bool(re.fullmatch(r"/[a-z0-9]+-(?:level-check|trial-lesson|english-review)/?", path, re.I))
         and distinct(re.compile(r"を無料で体験する|無料体験レッスン|公式ページ|公式サイト|"
                                 r"公式ホームページ|下のリンク(?:ボタン|より)|お得なキャンペーン"), text) >= 4
         and bool(re.search(r"(?m)^([^\n]{3,22}の公式(?:サイト|ページ)はこちら)\s*$"
                            r"(?s:.*)\n\1(?:\n|$)", text))
         and len(re.findall(r"レベルチェック|無料体験", text)) >= 13
         and not re.search(r"私が実際に受けた|筆者は.{0,18}受講しました|"
                           r"当スクール|取材|監修[：:]|講師へのインタビュー", text))
    if (split_weather := re.search(r"(?m)^Photo by [A-Z][a-zA-Z .,\-]{4,75}\s*$", raw)):
        preview, article = normalize(raw[:split_weather.start()]), normalize(raw[split_weather.end():])
        page("malformed-weather-preview-prepended-to-reposted-report",
             (re.fullmatch(r"/\d{4,}/?", path) and 130 <= len(preview) <= 650
              and distinct(re.compile(r"強いシルトが発生|風が強風に強まる|"
                                      r"東京地方上空では危険な砂嵐|風が強い地域もあれば[、,]強い風|"
                                      r"空気の質[、,]特に子供や高齢者"), preview) >= 2
              and distinct(re.compile(r"猛ふぶき|日本海側|冬型の気圧配置|大しけ|北日本|"
                                      r"雪を伴った強い風|交通障害|前線の通過"), article) >= 4
              and not re.search(r"出典[：:]|引用元[：:]|予報提供|気象庁による発表", text)))
    page("streaming-pitch-with-copy-pasted-social-posts-and-fake-download-stamps",
         bool(re.search(r"(?:^|&)p=\d+(?:&|$)", address.query if host else ""))
         and distinct(re.compile(r"動画配信サービス|31 *日間の無料お試し|違法ダウンロード|"
                                 r"動画サービス名.{0,12}配信状況|月額(?:料金|使用料)"), text) >= 4
         and len(re.findall(r"(?m)^Downl(?:oa|o)d?視聴可能[ \t]+ChromeCast対応[ \t]+字幕アリ", text, re.I)) >= 4
         and len(re.findall(r"(?m)^第\d{1,3}話\s*$", text)) >= 4)
    page("dated-clickbait-video-snippets-before-detached-comment-list",
         bool(re.fullmatch(r"/\d{4,}\.html?", path))
         and bool(re.match(r"(20\d\d/\d\d/\d\d)\n\1\n", text))
         and len(re.findall(r"撮影した(?:衝撃)?動画|(?:画像|動画)が流出|動画w{2,}|"
                            r"動画.{0,28}(?:んでしょうか|について)", text[:950], re.I)) >= 5
         and len(re.findall(r"\.\.\.|…|記事を読む", text[:950])) >= 4
         and bool(re.search(r"メールアドレスが公開されることはありません。\n(?:名前|氏名)\n", text))
         and not re.search(r"(?m)^撮影[：:]|^出典[：:]|^https?://", text))
    if re.fullmatch(r"/channel/UC[A-Za-z0-9_-]{20,25}/?", path) and 650 <= len(text) <= 6000:
        comments = [line for line in text.splitlines() if line.strip()]
        page("third-party-video-channel-with-detached-viewer-comments",
             bool(host) and not host.endswith((".youtube.com", ".google.com"))
             and host not in {"youtube.com", "google.com"}
             and len(comments) >= 24 and sum(len(line) <= 66 for line in comments) >= .76 * len(comments)
             and len(re.findall(r"(?m)^(?:[0-9]{1,2}:\d\d|[0-9]{1,2}分[0-9]{1,2}秒)", text)) >= 2
             and distinct(re.compile(r"チャンネル登録|レビュー好き|レビュー待ってます|提供は参考|"
                                     r"レビュー早|比較レビュー|動画を投稿|テンションばり上が"), text) >= 3
             and not re.search(r"(?m)^投稿者[：:]|^撮影[：:]|^動画一覧|^出典[：:]|^https?://", text))
    if re.fullmatch(r"/entry/20\d\d/\d\d/\d\d/\d{6}/?", path) and len(text) >= 800:
        page("trading-diary-with-unrelated-sleep-product-sales-tail",
             distinct(re.compile(r"仮想通貨|売り圧力|高騰|暴落|取引所|入金|買い増し|決算期"), text[:-290]) >= 5
             and bool(re.search(r"(?:暴落|相場|下落)[^。\n]{0,35}(?:不安|心配)[^。\n]{0,35}"
                                r"(?:眠れない|寝つけない)[^。\n]{0,50}(?:枕|マットレス)", text[-350:]))
             and distinct(re.compile(r"美人体温|美容の大敵|寝ながらサポート|"
                                     r"身体を温め|美しく眠る|極上の寝心地|睡眠の質を"), text[-350:]) >= 3)
    itinerary = re.search(r"(?m)^([^()\n]{4,32})(?:\([^\n)]{2,40}\))?"
                          r"体験したい見どころ[3３]選と(?:秘話・裏話|裏話)\1", text)
    if itinerary and re.fullmatch(r"/\d{3,}/?", path):
        page("generated-sightseeing-pages-with-fused-headings-and-itinerary",
             text.count(itinerary[1]) >= 5 and len(text) >= 1400
             and distinct(re.compile(r"おすすめ観光プランのご提案|アクセス\(車・駐車場・電車・バス\)|"
                                     r"近くのレストラン・カフェ|周辺のおすすめホテル|"
                                     r"ランドマークとしては|各交通機関の公式ウェブサイト"), text) >= 5
             and len(re.findall(r"(?m)^\d{1,2}:\d\d[：:]", text)) >= 2
             and not re.search(r"(?m)^取材[：:]|^執筆[：:]|^撮影[：:]|^出典[：:]|現地で撮影", text))
    page("municipality-swapped-tutor-recruitment-with-generic-application-pitch",
         bool(re.fullmatch(r"/[a-z-]+/[a-z-]+_other/[a-z_-]+/?", path, re.I))
         and bool(re.match(r"[^。\n]{2,18}(?:市|町|区|村)で家庭教師のバイトを見つけたい方[、,]必見", text))
         and distinct(re.compile(r"他のサイトとの.{0,15}違い|家庭教師登録フォーム|"
                                 r"安心の研修制度|家庭教師の登録サイトなんて|圧倒的な紹介の早さ|"
                                 r"時給は一律|本当の高時給|カンタン[0-9]分[^。\n]{0,18}登録"), text) >= 6
         and bool(re.search(r"20\d\d年度調査データ[^。\n]{0,40}平均時給は\d{3,4}円", text)))
    page("romanized-entertainment-repost-with-broken-senses-and-teaser-block",
         bool(re.fullmatch(r"/p/[a-z0-9-]{45,}-\d{6,}/?", path, re.I))
         and distinct(re.compile(r"役割のために\d{1,3}ポンドを失う|"
                                 r"ニンジンとアーモンドだけに住んで|"
                                 r"医者を買う余裕|ノートを比較させたく|"
                                 r"それは有機的に起こ|怪我の中で日中何時間"), text) >= 3
         and len(re.findall(r"(?m)^「[^」\n]{4,65}」(?:の)?(?:シーズン|のスター|で、)", text[-700:])) >= 2
         and not re.search(r"(?m)^編集[：:]|^原文[：:]|^転載元[：:]|^記者[：:]", text))
    if missing_tags := re.match(r"ページはありません\nタグ[『「]([^』」\n]{3,28})[』」]のページ一覧\npage\n", text):
        page("empty-tag-result-filled-with-repeated-single-product-copy",
             bool(re.fullmatch(r"/(?:page/)?tag/[^/]+/?", path))
             and 125 <= len(text[missing_tags.end():]) <= 700
             and text[missing_tags.end():].count(missing_tags[1]) >= 2
             and distinct(re.compile(r"酵素の力で菌を分解|根本からの[^。\n]{2,15}予防|"
                                     r"家事代行のプロが考えた|対策にもってこい|"
                                     r"身体にも使用できます|制汗剤のように即効性"), text) >= 3)
    page("localized-product-card-with-fragmented-sentences-and-word-sense-errors",
         bool(re.fullmatch(r"/(?:products|items|product)/[a-z0-9-]{4,70}/?", path, re.I))
         and distinct(re.compile(r"(?m)^(?:プレミアム素材|心を落ち着かせる|楽しみに最適|"
                                 r"素晴らしい贈り物|教育パズル|配送情報)"), text) >= 4
         and distinct(re.compile(r"木製[^。\n]{2,25}はで作られ|耐久性と腐食です|"
                                 r"木製のジグソーパズル\nパズルは|完璧です\n選択|"
                                 r"パズルは目を促進する|あなたの愛する\d+時間の娯楽|"
                                 r"相互作用に適しています\n子供と親"), text) >= 3
         and bool(re.search(r"米国の配達時間|国際配達時間|平均的な複雑さ", text)))
    page("fortune-result-with-unfilled-profile-fields-and-repeated-offer",
         bool(re.search(r"[-/]result\d{1,3}/?$", path))
         and all(re.search(r"\[(?:" + roles + r")の(?:生年月日|誕生日|血液型|名前|星座)\]", head)
                 for roles in (r"自分|私|あなた", r"相手|彼|彼女"))
         and distinct(re.compile(r"鑑定結果|占い結果|ワンポイントアドバイス|"
                                 r"相手の本当の気持ち|初回無料|無料でプレゼント"), text) >= 4
         and len(re.findall(r"限定|無料で(?:プレゼント|診断)|初回無料", text[-1200:])) >= 3)
    page("entertainment-profile-with-reused-live-chat-registration-script",
         bool(re.fullmatch(r"/(?:articles?/)?\d{3,}/?", path))
         and bool(re.search(r"女優[^。\n]{0,22}プロフィール|プロフィール\n|プロフィールについて|"
                            r"店舗紹介|店を全\d+店舗から厳選|最近グランドオープンした新店", head))
         and distinct(re.compile(r"ライブチャット|匿名だから|登録者は\d+(?:万)?人|"
                                 r"最大[\d,]{3,6}円分のポイント|メール登録後|"
                                 r"登録後[^。\n]{0,25}ポイント|初回登録で"), text) >= 4
         and bool(re.search(r"https?://[^\s]+/ad/p/r\?[^ \n]{0,180}_article=\d+|"
                            r"https?://[^\s]+/track/af/[^ \n]{10,}", text, re.I)))
    page("translated-numbered-media-list-with-multiple-literal-sense-errors",
         bool(re.fullmatch(r"/[a-z0-9-]{36,}/?", path, re.I))
         and bool(re.search(r"(?m)^明日のためのあなたの星占い\s*$|^あなたの明日の星占い\s*$", head))
         and len(re.findall(r"(?m)^\d{1,2}\.\s*[^。\n]{8,100}$", text)) >= 8
         and distinct(re.compile(r"裏側のキックを与え|私を素早く迎えに来|"
                                 r"小さなリフトを提供|コースにとどまりそして|"
                                 r"オーバードライブにあなたの|あなたはあなたを続ける"), text) >= 3)
    if re.search(r"/(?:name-diagnosis|name-fortune|seimei)/(?:name-[a-z-]+|detail)/?$", path):
        page("name-slotted-fortune-page-with-copied-ranking-and-empty-dates",
             bool(re.search(r"(?:^|&)(?:last-name|last_name|surname)=[^&]+&(?:first-name|first_name|given)=", address.query))
             and bool(re.search(r"字画\d{1,3}画", text))
             and distinct(re.compile(r"ラッキーナンバー|ラッキーカラー|名字国内人口|"
                                     r"苗字ランキング|名前鑑定した結果|運勢\s*【動画】"), text) >= 5
             and bool(re.search(r"(?m)^- 【公開日】\s*\n- 【更新日】\s*$", text)))
    page("celebrity-query-copy-on-repurposed-rural-community-site",
         bool(re.search(r"(?:shuraku|satonet|tanada|nouson|moridukuri)[a-z0-9-]*\.", host, re.I))
         and bool(re.fullmatch(r"/archives?/\d+/?", path))
         and distinct(re.compile(r"出会いや馴れ初め|デキ婚|好きな女性のタイプ|"
                                 r"熱愛をスクープ|注目をされているので|結婚に関して|"
                                 r"現在交際をされて|多くの方から注目|"
                                 r"交際をされる事になりました|売名目的の理由"), text) >= 4
         and len(re.findall(r"(?:さん|ちゃん)と[^。\n]{2,24}さん", text)) >= 5
         and not re.search(r"移住|棚田|地域おこし|ボランティア|住民の|地元出身|"
                           r"取材[：:]|インタビュー", text))
    page("disclosed-seo-generated-prefecture-landing-with-numbered-list",
         bool(re.fullmatch(r"/\d{3,}/?", path))
         and bool(re.search(r"(?m)^本記事は[^\n]{2,70}AIによる自動生成機能で作成しました\s*$", text[-400:]))
         and bool(re.search(r"(?m)^\d{1,2}\.\s*まとめ\s*$", text[-700:]))
         and len(re.findall(r"(?m)^\d{1,2}\.\s+[^。\n]{3,80}$", text)) >= 7
         and bool(re.search(r"旅行スポットを[0-9]+選|絶対に行くべき|魅力にハマる", head))
         and not re.search(r"(?m)^取材[：:]|^執筆[：:]|^写真[：:]|^編集[：:]", text))
    if re.search(r"(?:^|&)s=\d{4,}(?:&|$)", address.query if host else ""):
        story_fragments = text.splitlines()
        openings = distinct(re.compile(r"(?m)^(?:そして|いつも|そんな|ただし|つまり|だからこそ|"
                                       r"ちょうど|再び|以前は|今(?:は|も|さら))"), text)
        repeated_subject = Counter(re.findall(r"(?<![ぁ-ゖ])([一-龯々ァ-ヺA-Z]{2,9}"
                                              r"(?:の[一-龯々ァ-ヺ]{2,8})?の動画)", text))
        page("anonymous-query-page-with-repeated-topic-and-fragmented-testimonials",
             70 <= len(story_fragments) <= 240
             and (openings >= 7 or openings >= 4 and max(repeated_subject.values(), default=0) >= 4)
             and sum(line.endswith("。") for line in story_fragments) >= .72 * len(story_fragments)
             and len(re.findall(r"動画を見|の動画|無料の画像|個人撮影|掲示板で知り合", text)) >= 9
             and not re.search(r"(?m)^投稿者名|^コメント一覧|^ご利用規約|^出典[：:]|^https?://", text))
    if re.fullmatch(r"/20\d\d/\d\d/\d\d/[^/]+/?", path) and "雀荘" in path:
        snippets = [line for line in text.splitlines() if line.strip()]
        page("mahjong-search-title-before-incoherent-short-snippets",
             39 <= len(snippets) <= 125 and sum(len(line) <= 72 for line in snippets) >= .83 * len(snippets)
             and distinct(re.compile(r"鳳凰卓|フリー雀荘|テンパイ|リーチ|聴牌|役満|"
                                     r"ツモ|和了り|点棒|シャンテン|配牌"), text) >= 5
             and (len(re.findall(r"(?m)^- [^。\n]{2,40}雀荘", text[-550:])) >= 4
                  or distinct(re.compile(r"これが[^。\n]{1,18}あせる|リンクがあるので方|"
                                          r"この度[、,]ことにいたしました|"
                                          r"入らないようになりまま|[^。\n]{1,20}冠水したりします"), text) >= 3)
             and sum(line.count("「") != line.count("」") for line in snippets) >= 3)
    if re.fullmatch(r"/(?:archives/\d{5,}\.html?|id/\d{5,}/\d+)/?", path):
        headlines = [line.strip() for line in text.splitlines() if line.strip()]
        source_labels = re.compile(r"(?:まとめ|速報|ちゃんねる|チャンネル|ニュース|アンテナ|ブログ|掲示板|"
                                   r"保管庫|日記|情報館|[23]ch|特価太郎|まとめサイト|J PRIDE)", re.I)
        page("headline-aggregator-with-alternating-unrelated-source-labels",
             21 <= len(headlines) <= 180 and len(re.findall(r"(?m)^【[^】\n]{2,14}】", text)) >= 4
             and sum(len(line) < 38 and bool(source_labels.search(line)) for line in headlines) >= 13
             and sum(len(line) >= 130 for line in headlines) <= 2
             and not re.search(r"(?m)^本文\s*$|^取材[：:]|^話題の背景\s*$|^https?://", text))
    if re.fullmatch(r"/(?:inf|q|search)/[^/\s]{2,32}\s+[^/\s]{2,32}\.html?", path):
        page("keyword-search-route-with-unrelated-dated-entertainment-articles",
             len(re.findall(r"(?m)^■20\d{2}年\d{1,2}月\d{1,2}日\s*$", text)) >= 4
             and len(re.findall(r"(?m)^.{4,100}(?:[。！？!?]|\))$", text)) >= 12
             and distinct(re.compile(r"話題|「.*」|\bhttps://t\.co/|週刊|新聞|配信|"
                                     r"に対し|と語っている|のようです"), text) >= 6
             and len(re.findall(r"(?m)^(?:執筆|著者|取材)[：:]", text)) == 0)
    if re.fullmatch(r"/(?:feed|rss)/\d{6,}/?", path) and 170 <= len(text) <= 1150:
        snippets = [line.strip() for line in text.splitlines() if line.strip()]
        page("short-repost-feed-without-article-or-post-boundaries",
             9 <= len(snippets) <= 29 and snippets[0].startswith("【")
             and bool(re.fullmatch(r".{2,42}(?:まとめ速報|まとめ情報|アンテナ)", snippets[1]))
             and sum(7 <= len(line) <= 78 and not line.endswith("。") for line in snippets[2:]) >= 8
             and not re.search(r"(?m)^https?://|(?:出典|引用)[：:]|(?:投稿者|コメント番号)[：:]", text))
    if (text.startswith("We are searching data for your request:\n") and host.startswith("ja.")
            and re.fullmatch(r"/[0-9]{4,5}(?:-[a-z0-9]{1,22}){3,18}\.html", path)):
        page("localized-scrape-under-shared-incomplete-search-wrapper",
             "Upon completion, a link will appear to access" in head
             or bool(re.search(r"(?m)^出典:\s*(?:https?://|MIT Technology Review|BBC News)", text[-220:]))
             or len(re.findall(r"[\u3040-\u30ff一-龯]", text)) >= 45 and text.count("。") >= 3)
    if 125 <= len(text) <= 1250 and re.fullmatch(r"/archive/20[0-9]{2}/[0-9]{1,2}/[0-9]{1,2}/?", path):
        archive_title_run = text.partition("\n引用をストックしました")[0]
        page("dated-headline-collage-with-glued-counts-and-failed-title-fetch",
             archive_title_run.startswith("×") and "引用するにはまずログインしてください" in text
             and len(re.findall(r"×[0-9]{1,5}(?=[^\s\d])", archive_title_run)) >= 4
             and bool(re.search(r"\[(?:タイトルが取得できませんでした|タイトルを取得できませんでした)\]", archive_title_run))
             and archive_title_run.count("|") >= 2
             and archive_title_run.count("。") <= 1)
    if source_replies := re.search(r"(?m)^ニュースへの反応[ \t]*\r?$", raw):
        article = normalize(raw[:source_replies.start()])
        replies = normalize(raw[source_replies.end():])
        if (re.fullmatch(r"/\d{4,}/?", path) and 125 <= len(article) <= 450
                and bool(re.match(r"20\d\d年\d{1,2}月\d{1,2}日 \d{1,2}:\d{2}\n", article))
                and article.count("。") <= 4 and bool(re.search(r"(?m)^https?://[^ ]+$", article.rstrip()))
                and 9 <= len(replies.splitlines()) <= 30 and replies.strip().endswith("みんなの声")):
            findings["dated-news-excerpt-with-anonymous-reaction-block"] = [(source_replies.start(), len(raw))]
    if AFFILIATE_CATALOG_ROUTE.fullmatch(path):
        lines = text.splitlines()
        snippets = [line.strip() for line in lines[3:] if line.strip()]
        page("income-pitch-padded-with-anonymous-unrelated-snippets",
             bool(re.fullmatch(r"/cate_[a-z0-9]{6,}/cont_[a-z0-9]{6,}/?", path, re.I))
             and 300 <= len(text) <= 2200 and "副業" in head and "在宅ワーク" in head
             and bool(re.search(r"月\s*\d+万(?:円|稼)|誰でも出来る簡単な", head))
             and 8 <= len(snippets) <= 32
             and sum(6 <= len(line) <= 45 for line in snippets) >= 8
             and sum(bool(re.search(clue, "\n".join(snippets))) for clue in (
                 r"色は.{1,12}透明|無色透明",
                 r"庭に.{1,12}が出|鳥のさえずり|ツバメが戻",
                 r"ヤンキース|メジャーリーグ|甲子園",
                 r"姑は|同居の義母|テンションで盛り上",
             )) >= 3)
        finance = "\n".join(lines[:3])
        page("short-finance-pitch-followed-by-unlabelled-scraped-fragments",
             300 <= len(text) <= 1800 and 8 <= len(snippets) <= 28
             and distinct(re.compile(r"バイナリーオプション|投資商品|FX初心者|お小遣い[稼情]|"
                                     r"ネット収入|(?:在宅|副業)でできる|ハイレバレッジ|スプレッドが狭い|海外業者"), finance) >= 4
             and sum(6 <= len(line) <= 48 for line in snippets) >= 7
             and sum(line.endswith(("の。", "が。", "ことが。", "たり。", "物に。", "ものに。", "…", "今。")) for line in snippets) >= 3
             and not re.search(r"(?m)^(?:出典|投稿者|引用|関連記事)[:：]|^https?://", text))
    if re.fullmatch(r"/[a-z]{3,24}/\d{5,8}\.html?", path, re.I):
        page("retail-copy-with-foreign-place-names-injected-inside-words",
             bool(re.search(r"商品番号\s*[:：]\s*[a-z0-9]{7,18}\s+価格\s*[:：]\s*\d{3,7}\.\d{2}", head, re.I))
             and bool(RETAIL_PUBLISH_MARKER.search(text))
             and distinct(INSERTED_CHINESE_LOCATION, text) >= 3)
    page("automatic-encyclopedia-with-search-count-and-mismatched-excerpts",
         path.startswith(("/q/", "/abst/")) and bool(re.search(r"出典:\s*全自動百科事典", head))
         and "Now making a new page" in head
         and len(re.findall(r"現在インターネット上では[^。]{8,115}\s*議論されているWebページの数は", text)) >= 3)
    if 600 <= len(text) <= 3500 and "Reading" in head and "以下引用" in text:
        page("credited-reprint-with-affiliate-inserts-inside-the-quote",
             bool(re.search(r"(?m)^([^\n。]{8,68}) Ranking\s*\n(?:\1 Reading[^\n]*\n){4,}", text))
             and bool(re.search(r"以下引用\s*https?://[^。\n]+\)[\s\S]{100,1400}引用終わり", text))
             and len(re.findall(r"■[^\n。]{5,55}Ranking", text)) >= 2)
    if re.search(r"/(?:category|archives)(?:/|$)", path):
        query_links = re.findall(
            r"(?m)。((?:ミュゼ|湘南美容|クレジットカード|ハイジニーナ|育毛剤|"
            r"カードローン|アメックス|酵素|出会い系|脱毛)[^\n。]{1,27})$", text)
        page("multi-topic-blog-archive-with-detached-search-queries",
             len(set(query_links)) >= 3
             and sum(bool(re.search(
                 r"(?:脱毛|ミュゼ|ハイジニーナ).{0,12}(?:自己処理|回数|ランキング|値段)|"
                 r"(?:マイル|ポイント) .{0,12}(?:どっち|比較)|"
                 r"(?:効果|口コミ|ランキング|おすすめ|安い)$", query)) for query in query_links) >= 3)
    if host and "paged=" in address.query and re.search(r"(?:^|&)m=20\d{4}(?:&|$)", address.query):
        page("affiliate-copy-montage-with-separate-technical-lead",
             len(text) >= 1300 and distinct(re.compile(r"舌苔|口臭|歯磨き|臭い玉|口腔|雑菌"), head) >= 4
             and sum(bool(re.search(topic, text[300:])) for topic in (
                 r"就職支援|面接・選考|正社員になりたい",
                 r"DHA.{0,4}EPA|コレステロール|サプリメント",
                 r"お駄賃|特産品や地域限定品|プチ収入",
                 r"常勤の場合|医師転職|転科成功",
                 r"税込[\d,]+円|カタログ約\d+ページ",
             )) >= 4)
    if re.fullmatch(r"/(?:lists|collections)/\d+/?", path) and 250 <= len(text) <= 900:
        sections = [line for line in text.splitlines() if line.strip()]
        page("anonymous-visitor-list-with-unrelated-reused-editorial-footer",
             5 <= len(sections) <= 12 and sum(line.count("。") >= 2 for line in sections) >= 4
             and "観光スポットをご紹介" in sections[0]
             and bool(re.search(r"暦の上でも[^。\n]{2,22}特集をお届け", sections[-1]))
             and distinct(re.compile(r"物産品|銘菓|料理の器具|ジャンルの本|レターセット|"
                                     r"ポストカード|館内売店|記念品"), text) >= 4
             and not re.search(r"(?m)^(?:名称|店名|スポット名|住所|電話番号|営業時間)[：:]", text))
    if re.search(r"/(?:keywords?|ranking|result)/", path, re.I):
        page("unnamed-ranked-catalog-excerpts-with-repeated-marketplace-taxonomy",
             len(re.findall(r"(?m)^\|\d{1,2}\|\|[ \t]*$", text)) >= 10
             and text.count("カテゴリ別売り上げランキング情報") >= 7
             and len(re.findall(r"(?m)^.{2,35} > カテゴリー別 > .{2,80}(?:第\d+位|ランク外)$", text)) >= 7
             and distinct(re.compile(r"対象年齢|材質|製造国|セット内容|使用上の注意|カラー"), text) >= 4
             and not re.search(r"(?m)^\|商品名\|\||^販売元[:：]", text))
    page("copied-research-report-in-unrelated-support-site",
         bool(re.fullmatch(r"/page/(?:web|guide|news)\d+/?", path))
         and bool(re.search(r"customer(?:service|support)|support-center|helpline", host))
         and bool(re.search(r"レポートは[、,]20\d{2}年\d{1,2}月に初めて(?:発行|公開)", head))
         and bool(re.search(r"この調査の目的は[、,][^。\n]{25,240}可能性があります", head))
         and len(re.findall(r"[。．]\.|[ぁ-ゖァ-ヺ一-龯]\.(?=\n)", text)) >= 9
         and len(re.findall(r"ここでビデオをチェック|ここで動画をご覧|調査は[、,]|(?m:^Contents$)", text)) >= 3)
    page("video-copy-with-untranslated-social-template-and-detached-comments",
         bool(re.search(r"^/20\d{2}/\d\d/\d\d/[^/]+/?$", path))
         and bool(re.search(r"(?m)^【(?:過去のオススメ動画|スタッフ募集|Twitterアカウント)", head + text[:800]))
         and 25 <= len(text.splitlines()) <= 75
         and len(re.findall(r"(?m)^.{3,60}(?:のTwitter|のSNS|サブチャンネル登録).{0,25}$", text)) >= 4
         and len(re.findall(r"(?m)^【[^】]*(?:編集スタッフ募集|過去のオススメ動画|Twitterアカウント)[^】]*】", text)) >= 3
         and bool(re.search(r"(?m)^コメント\s*\n", text))
         and len(re.findall(r"生配信|チャンネル|初コメ", text)) >= 5)
    page("cached-forum-reprint-with-duplicated-teaser-and-two-comment-structures",
         bool(re.fullmatch(r"/cache_(?:text|news|log)/\d+/\d+\.s?html?", path))
         and bool(re.match(r"([^\n]{7,115})back *[▼▲]\n\1\n", text))
         and text.count("続き・詳細・画像をみる") >= 2
         and distinct(re.compile(r"コメント一覧|人気サイト更新情報|人気記事ランキング|元スレ|削除依頼"), text) >= 3
         and len(re.findall(r"(?m)^\d+\s*[:：.]$", text)) >= 10)
    if re.fullmatch(r"/cache_(?:text|news|log)/[0-9]+/[0-9]+\.s?html?", path):
        teaser = re.match(r"([^\n]{7,115})back[ \t]*\n\1\1", text)
        if teaser and text.rstrip().endswith("\nback"):
            headlines = [line for line in text[teaser.end():].splitlines() if 12 <= len(line) <= 160]
            page("cached-headline-stream-with-mechanically-repeated-lead",
                 len(headlines) >= 10
                 and sum(bool(re.search(r"[wW]{3,}|【[^】]{2,20}】|[！？!?]$", line))
                         for line in headlines) >= 4)
        cached_lead = re.match(r"([^\n]{7,150})back[ \t]*[▼▲]\s*\n\1\n", text)
        if cached_lead and re.search(r"(?m)^back[ \t]*[▼▲].{0,30}削除依頼", text):
            separators = list(re.finditer(r"(?m)^続き・詳細・画像をみる[ \t]*$", text))
            if len(separators) >= 2:
                after_story = text[separators[-1].end():].splitlines()
                page("cached-excerpt-wrapped-in-unlabelled-headline-montage",
                     sum(14 <= len(line) <= 145 for line in after_story) >= 8
                     and sum(bool(re.search(r"[!?]|w{2,}|【[^】]{2,20}】", line))
                             for line in after_story) >= 4)
    if 220 <= len(text) <= 1200 and re.search(r"/entry/20\d{2}/\d\d/\d\d/\d{6}(?:_\d{1,3})?/?$", path):
        page("supplement-sales-snippets-with-repeated-broken-joins",
             len(re.findall(r"サプリメント|食品|・通販|で出荷", text)) >= 6
             and distinct(re.compile(r"安全性を保持す握|全性を保持す握|"
                                     r"サプリメントには是非お待ち|の販売店本紙は|"
                                     r"では紹介した内容は、パンフ|で健康な、営業日"), text) >= 2
             and distinct(re.compile(r"出荷|お届け目安|パンフ|願書|価格|全国の通販サイト"), text) >= 3)
    if re.fullmatch(r"/v\d{3,7}_20\d{2}-\d\d-\d\d\.html", path):
        clipped_joins = re.findall(r"\.{3}\s*(more|»続きを読む)", text, re.I)
        page("dated-program-page-mixes-truncated-material-from-separate-sources",
             len(clipped_joins) >= 3 and len(set(clipped_joins)) >= 2
             and ("※前スレ" in head or len(re.findall(r"https?://", text)) >= 2)
             and not head.startswith(("番組表", "放送予定", "ニュース一覧")))
    if re.fullmatch(r"/\d{2,5}/?", path) and re.search(r"nike|adidas|sneakers|shoes", host, re.I):
        page("footwear-domain-used-for-simulated-course-reviews",
             200 <= len(text) <= 950 and bool(re.search(r"FXツール|爆益|復縁方法|情報商材|投資ソフト", text))
             and distinct(re.compile(r"インチキ|ネタバレ|本当なのかな|人気みたい|正直、怪しい|体験談|"
                                     r"買ってみて使えない|試してみ(?:ても|よう)|口コミ"), text) >= 4
             and bool(re.search(r"(?m)[「『][^」』\n]{6,75}[」』]", text))
             and not re.search(r"シューズ|スニーカー|靴ひも|ソール", text))
    feed_archive = host and path != "/" and re.search(r"(?:^|&)m=(?:19|20)\d{4}(?:\d\d)?(?:&|$)", address.query)
    if feed_archive and len(text) >= 1100:
        industries = (
            r"(?i)CleanMyMac|Mac用クリーンアップ|macOSのクリーナー", r"保険の無料相談|保険相談お申し込み",
            r"給料債[権券]|現金調達可能|資金調達サービス|売買手数料のみ",
            r"セルライト|愛されBody|まつ毛ケア|ふくらはぎ", r"月の土地|ボールペン.*宇宙",
            r"資産形成術|マネー講座|貯蓄術|空いた時間に少しでも稼ぎ",
        )
        page("calendar-archive-mixes-disconnected-service-pitches",
             sum(bool(re.search(industry, text)) for industry in industries) >= 3
             and len(re.findall(r"今すぐ|申し込[みむ]|プレゼント|無料|お客様のお声", text)) >= 4
             and not re.search(r"(?m)^(?:記事一覧|おすすめ記事|連載)", head))
        page("calendar-archive-collage-with-repeated-mismatched-sales-copy",
             distinct(re.compile(r"(?i)ニキビ跡|角質づまり|洗顔クリーム|化粧液・乳液"), text[:900]) >= 3
             and distinct(re.compile(r"お土産通販|海外のお土産|旅先で|地ビール特集|お土産を注文"), text[-2100:]) >= 3
             and any(count >= 2 for line, count in Counter(text.splitlines()).items()
                     if 32 <= len(line) <= 155 and re.search(r"コラーゲン|お試し|配合|吸収性|限定価格", line))
             and not re.search(r"(?m)^(?:記事一覧|おすすめ記事|連載)", head))
        sales_sections = (
            r"資金繰りが上手くいかない|キャッシュフローが長い|給料債[権券]",
            r"プエラリアミリフィカ|ワイルドヤム|大豆種子エキス|プラセンタ美容液",
            r"司法書士講座|公務員.{0,8}お得な割引|公開模試がセット",
            r"遺伝子ヘアリスク|ハミルトン・ノーウッド分類|ルードウィヒ分類",
            r"3Dモーションセンサー.{0,32}歯磨き|歯磨きミッション|ブラッシュモンスター",
        )
        page("calendar-archive-with-unlabelled-finance-beauty-and-qualification-promotions",
             sum(bool(re.search(section, text)) for section in sales_sections) >= 4
             and distinct(re.compile(r"期間限定割引|キャンペーン|無料でプレゼント|合格目標|銀行から融資|保湿成分"), text) >= 4
             and not re.search(r"(?m)^(?:記事一覧|出典[:：]|編集部[:：]|商品一覧|カテゴリ一覧|週刊まとめ)", text))
    if path.endswith(".php"):
        fields = re.findall(r"(?m)^(?:製品|商品)(?:名|の材質|の色|重量|サイズ)[:：]", text[:1400])
        editorial_archive = re.search(
            r"(?m)^記事データベース[ \t]*\n[^。\n]{12,95}(?:写真で振り返|記事を検索)", text
        )
        if editorial_archive:
            product_ids = set(re.findall(r"\bB0[A-Z0-9]{8}\b", text))
            page("product-specifications-spliced-into-newspaper-archive",
                 product_ids and (len(set(fields)) >= 4 or (
                     len(product_ids) >= 3 and len(re.findall(
                         r"縫い仕上げ|お手入れ簡単|手作業による測定|洗濯機で水洗い|お届け日数", head)) >= 3))
                 and re.search(r"(?m)^(?:.{1,22}について|[|].{0,42}(?:天気|気温|℃))",
                               text[:editorial_archive.start()]))
    if re.fullmatch(r"/[a-z]{3,18}-[0-9]{1,5}/?", path):
        query = text.split("\n", 1)[0]
        clause_leads = re.findall(r"(?:^|[。\n])([^。\n]{12,24})の方[がに]", text)
        page("spaced-search-query-with-repeated-clause-and-incompatible-joins",
             bool(re.fullmatch(r"[\wー]+(?:[ \t]+[\wー]+){2,8}", query)) and 6 <= len(query) <= 72
             and len(set(clause_leads)) < len(clause_leads)
             and distinct(re.compile(r"(?:陳列|表示|保存)された質問には|"
                                     r"(?:健康|安全)第一を考えて[、,][^。\n]{2,12}の向きですが|"
                                     r"のは[^。\n]{0,9}期限ではなく常温の場所|"
                                     r"ケースでは[、,]鍋の(?:出し|だし)が減"), text) >= 2)
    if re.fullmatch(r"/(?:archives|entry)/[0-9]+\.html?", path) and 240 <= len(text) <= 1500:
        page("hardware-query-stuffing-with-interleaved-unrelated-marketing",
             len(re.findall(r"ゲーミング(?:ノート)?[Pp][Cc]", text)) >= 8
             and len(re.findall(r"(?:買(?:った|っちゃった|うことを決意)|(?:購入|新調)したい)", text)) >= 3
             and re.search(r"(?:^|。)[ \t]*(?:[A-Z]{2,12}の)?(?:ダブルフォーカスクリア|"
                           r"美白美容液[^。\n]{0,15}|毛穴すっきり洗顔[^。\n]{0,15})。", text))
    if re.fullmatch(r"/[^/]{12,170}/?", path) and "•" in text:
        page("unedited-localization-with-unexpanded-English-joke-and-broken-sports-senses",
             bool(re.search(r"(?i)\[insert (?:joke|quip|pun) (?:about|here)[^\]\n]{0,120}\]", text))
             and distinct(re.compile(r"に借りて農業を犯|(?:回|試合)の賃貸に出場|目標を得たが[、,].{0,30}ビルドアップ|"
                                     r"手にゲームがあり|圧力を好まないました|情報を?付けることができますか"), text) >= 3
             and len(re.findall(r"[\w.-]+\.com/[A-Za-z0-9/]+|[•·]{3,}", text)) >= 2)
    page("literal-news-localization-with-multiple-unrelated-word-senses",
         450 <= len(text) <= 4300 and bool(re.search(r"/(?:マガジン|ニュース|magazine|news)/", path))
         and bool(re.search(r"(?m)^\(出典\)\s*\Z", text))
         and distinct(re.compile(r"黒人の危機|不注意は[、,].{8,70}から到着|燃えるような啓示|"
                                 r"危機の声に身をさら|異常な社会的冷たさ|感傷的な状況を明らかに|"
                                 r"はがきでも.{1,55}を見たくない"), text) >= 3)
    page("localized-hotel-card-with-empty-opinion-slots-and-malformed-prose",
         path in {"", "/"} and bool(re.search(r"ホテル|\bHotel\b|リゾート", head))
         and distinct(re.compile(r"24時間対応|シャトル|インターネットアクセス|荷物保管室|"
                                 r"ルームサービス|無料駐車場|部屋数"), text) >= 5
         and bool(re.search(r"(?m)^(?:一般的に|総合)\s*\n長所\s*\n短所\s*\n(?:から|料金)", text))
         and distinct(re.compile(r"(?:センター|空港)までわずかな時間|近くの辺にあります|"
                                 r"簡単に行けます|まで車で行けば[、,]ちょうど|部屋数[：:] *\d+\."), text) >= 3)
    if reactions := re.search(r"(?m)^ネットの声[ \t]*\r?$", raw):
        article, comments = normalize(raw[:reactions.start()]), normalize(raw[reactions.end():])
        if (len(article) <= 550 and bool(re.search(r"結婚式|挙式|婚姻届|披露宴", article))
                and bool(re.search(r"(?m)^<引用元:https?://[^>]+>\s*$", article))
                and 12 <= len(comments.splitlines()) <= 45
                and distinct(re.compile(r"間違われない|いっつも間違えられ|\d文字だぞ|"
                                        r"売名して|今更売名|誰だっけ|名前が似て"), comments) >= 3):
            findings["unrelated-reaction-snippets-after-reprinted-news"] = [(reactions.start(), len(raw))]
    if re.search(r"/(?:thread|threads)/(?:[^/]+/)?view/\d+/?$", path):
        footer = re.search(
            r"(?m)^このサイトは([^\n。]{2,55}掲示板)ではありません。"
            r"[\n ]+現在[、,]閲覧しているサイトは\1を不正にコピーしています。", raw)
        if footer and "サイトの安全性" in raw[footer.end():] and "公式サイトから閲覧" in raw[footer.end():]:
            findings["forum-copy-notice-after-discussion"] = [(footer.start(), len(raw))]
    page("regional-treatment-review-with-imported-route-and-corrupted-phrases",
         bool(re.search(r"/entry_[\w.-]+\.(?:com|net|jp|info)_entry\d+/?$", path))
         and len(set(re.findall(r"学割プラン|無料カウンセリング|月額制|全身脱毛|通い放題|照射", text))) >= 4
         and bool(re.match(r"([^\n]{10,80}口コミレビュー)\n\1\n", text))
         and distinct(re.compile(r"手を消毒しながら美肌|危険な安心|受付を運びて|"
                                 r"マンションの毛が濃い|効果はしっかりストレス|IPL脱毛効果.{0,15}ひんやり"), text) >= 3)
    page("family-narrative-with-repeated-machine-joined-relationship-keywords",
         600 <= len(text) <= 4500 and len(re.findall(r"「[^。\n]{5,68}|」", text)) >= 6
         and len(re.findall(r"(?m)^[^\n]{0,25}(?:結婚|婚活|恋活|婚約)[^\n]{0,35}$", text)) >= 4
         and distinct(re.compile(r"役割分担(?:私|僕|俺)[はが]|(?:婚活|結婚)の問題があり(?:今|私|僕)|"
                                 r"(?:婚活|結婚|恋活).{0,30}ましたこのように|結婚に行くことができます|"
                                 r"(?:指輪|式)(?:私|僕|俺)は時々|恋活の擁護者になりでも"), text) >= 3)
    page("product-specifications-followed-by-incompatible-customer-reviews",
         bool(re.search(r"/20\d{2}/\d\d/\d\d/[^/]{3,45}[-_][a-z]{2,6}-\d{3,}/?$", path, re.I))
         and len(re.findall(r"●[^●\n]{5,120}", head)) >= 7
         and len(set(re.findall(r"ロック錠|解錠|耐火時間|ダイヤル錠|リロッキング装置|扉の厚さ", head))) >= 4
         and distinct(re.compile(r"かわいいレジ袋|お友達に自慢|子供が保育園に持って|お既読に買い物"), text[500:]) >= 3
         and "発送" in text and "梱包" in text)
    page("vehicle-appraisal-keywords-threaded-through-incoherent-paragraph",
         len(text) <= 2700 and bool(re.match(r"[^。\n]{0,45}(?:買取|査定|下取り) +20\d{2}\d列", head))
         and distinct(re.compile(r"事故車|買取業者|下取り情報|見積もり|値引き|買取相場|査定"), text) >= 5
         and distinct(re.compile(r"車売却このサイト|(?:検索|利用)頂き誠に有難う御[、,]|"
                                 r"査定\d{3,}つまり|査定.{2,20}さてい|ということが量産体制"), text) >= 2)
    diary_lines = [line.strip() for line in text.splitlines() if line.strip()]
    if 1400 <= len(text) <= 18000 and len(diary_lines) >= 65:
        dangling = re.findall(
            r"(?m)^[ \t]*(を(?:する|しな|実行|始め|気に)|から(?:に|しよう|の[にへ])|"
            r"が(?:気にな|すいた|重くて|大事)|は(?:いつも決ま|しょっちゅう|を始め|以上続|どんな気遣い)|"
            r"に(?:取り組む|手伝って|対する意気込み|遊びに行|も痩せ|も同じことが言え)|の(?:前で|のように)|"
            r"や(?:に[!！]?$|をすごく|のような|そのためのに対する))", text)
        page("serial-diary-with-nouns-and-subjects-missing-from-prose",
             len(dangling) >= 8 and len({word[0] for word in dangling}) >= 3
             and sum(len(line) <= 44 for line in diary_lines) * 5 >= len(diary_lines) * 4
             and distinct(re.compile(r"引っ越|ダイエット|リバウンド|痩せ|脂肪|筋肉痛|カロリー|減量"), text) >= 3
             and distinct(re.compile(r"が気になって[、,]|(?:頑張って|気分が|すると)しても|"
                                     r"が(?:すいたとき|動かない時)|(?:した|行く)らに(?:遊び|行く)|"
                                     r"や[との]食事を|食事やなど|がをする|(?:や|とか)好きに食べ|ようにが動"), text) >= 3)
    if re.search(r"/(?:[a-z0-9_-]+-)?result\d+/?$", path):
        page("personalized-reading-result-with-unexpanded-subject-fields",
             len(re.findall(r"\[[^\]\n]{2,20}(?:結果|日柱|氏名|生年月日|名前|特徴|タイプ)[^\]\n]{0,8}\]",
                            text[:400])) >= 3
             and bool(re.search(r"鑑定結果を最後まで読んで|以下のアドバイスで", text))
             and len(re.findall(r"初回無料でプレゼント|今すぐ鑑定結果", text)) >= 2)
    if re.search(r"/(?:kuchikomi|testimonials?|reviews?)/", path):
        customer_header = re.compile(r"(?m)^年齢[：:]\s*\d{2}歳\s*\n性別[：:]\s*[男女]性\s*\n在住[：:]")
        headers = list(customer_header.finditer(text))
        if len(headers) >= 5:
            comments = [text[left.end():right.start()] for left, right in zip(headers, headers[1:])]
            statements = [{sentence.strip() for sentence in re.split(r"[。\n]", part)
                           if 11 <= len(sentence.strip()) <= 85} for part in comments]
            page("testimonials-with-consecutive-statements-copied-between-customer-identities",
                 bool(re.search(r"定期購入|愛用して|これからも.{2,14}続け|維持しています", text))
                 and any(len(left & right) >= 2 for left, right in zip(statements, statements[1:])))
    page("product-copy-with-mutated-narrative-and-repeated-heading",
         bool(re.search(r"/\d{2,}[a-z]+[a-z0-9]*[0-9]{5,}\.s?html?$", path, re.I))
         and bool(re.match(r"【(?:感謝価格|特売価格|特価|限定価格)】", head))
         and len(re.findall(r"(?m)^\|[^|\n]{2,12}\|\|[^|\n]{2,54}\|", text)) >= 3
         and distinct(re.compile(r"東夷栽培面積|分布しているところあがる|"
                                 r"(?:栽培|生産)面積は\d?に推奨し|いきいきとしてを与え"), text) >= 2)
    page("dialect-rewrite-with-incompatible-transit-phrases-inside-car-leasing-copy",
         380 <= len(text) <= 2100 and len(re.findall(r"(?:じゃけ|じゃろ|なんじゃ|しとる|なっとった)", text)) >= 5
         and distinct(re.compile(r"車検|自動車税|ガソリン代|リース|普通車|未使用車|売却"), text) >= 5
         and distinct(re.compile(r"手なげる時|路線に乗るとき|急ぎの乗換え|積み立て回数券|"
                                 r"時差回数券|通れる個人がリースが|ガソリン代も安うなる会社しがち"), text) >= 4)
    page("short-health-copy-with-disconnected-comparison-and-missing-verbs",
         200 <= len(text) <= 900 and bool(re.search(r"(?m)^- *URL *\|\s*\Z", text))
         and distinct(re.compile(r"効力だけでは治りません|肌にてくれます|多いのは外用薬|"
                                 r"ローションタイプの方がといわれ|(?m:^方が個々の肌質)"), text) >= 3
         and distinct(re.compile(r"処方|効用|炎症|角質|外用薬"), text) >= 4)
    locality_summary = re.match(
        r"[^「\n]{2,55}には「[^」\n]{2,42}」に関する(?:ホテル|宿泊施設|観光施設)情報が0件[、,]"
        r"(?:まとめ)?記事が[01]件掲載されています。", text)
    if re.fullmatch(r"/(?:city|area|destination)/\d+/?", path) and locality_summary:
        blurbs = [line for line in text.splitlines() if line.strip()]
        page("empty-travel-landing-with-detached-destination-blurb",
             180 <= len(text) <= 700 and 7 <= len(blurbs) <= 24
             and any(line.endswith("...") and line.count("。") >= 2 for line in blurbs[1:4])
             and sum(2 <= len(line) <= 20 and bool(re.fullmatch(r"[\w・ｰ-]+", line))
                     for line in blurbs[2:]) >= 6
             and not re.search(r"(?m)^\*|^https?://|^#{1,3} |(?:住所|営業時間)[：:]", text))
    if re.fullmatch(r"/\d+\.s?html?", path) and 550 <= len(text) <= 6900:
        substitutions = re.findall(
            r"(?m)^.{3,48}(ということなのだ。|という指摘があるが、|にとどまっているのは|"
            r"からは馬鹿にされ、|の受け売りだが、|でもそうだった。|から察するに|"
            r"されるばかり。|になりたかった。|だが、しかし|をお届けします。)$", text)
        page("random-entity-lines-with-repeated-unconnected-predicate-shells",
             len(substitutions) >= 13 and len(set(substitutions)) >= 6
             and len(re.findall(r"[\w-]+_+[A-Za-z0-9(（]", text)) >= 4
             and len(re.findall(r"(?m)^.{7,36}[。、]?$", text)) >= 36)
    if re.search(r"/(?:taikendan|experience|testimonial|story)/", path):
        page("service-testimonials-with-repeated-clause-splices-and-impossible-count",
             distinct(re.compile(r"チャットサービス|チャットレディ|ライブチャット|無料ポイント|"
                                 r"プロフィール更新|報酬発生|継続しない事へのペナルティ"), text) >= 5
             and bool(re.search(r"\d{8,}人が(?:参加|来場|登録)", text))
             and len(re.findall(r"([^。\n]{12,45}。)\1", text)) >= 1
             and bool(re.search(r"([^。\n]{10,28}などでも)\1", text)))
    page("unexpanded-topic-slot-in-download-marketing",
         bool(re.search(r"<%[a-z][a-z0-9-]{3,40}%>", text, re.I))
         and distinct(re.compile(r"無料体験|体験版|購入したでしょうか|フリーソフト|ダウンロードソフト|"
                                 r"ダウンローダー|モジュールを選択"), text) >= 4
         and len(re.findall(r"(?m)^(?:Step|ステップ)[1-9①-⑨]", text, re.I)) >= 6)
    page("scraped-faq-with-duplicated-and-mismatched-answers",
         bool(re.fullmatch(r"/\d{4,}/?", path))
         and len(re.findall(r"(?m)^[^\n。]{4,65}\?\s*$", text)) >= 13
         and len(re.findall(r"(?m)^(?:キャッシュ|引用元を表示|結果を表示)\s*$", text)) >= 2
         and bool(re.search(r"(?m)^[^\n。]{4,65}\?\s*\n[^\n]{0,160}「\s*」.{0,50}", text)))
    page("short-spun-personal-blog-with-detached-product-keyword",
         200 <= len(text) <= 1800 and bool(re.search(
             r"。(?:痩せる酵素|酵素ダイエット|視力回復|育毛剤|脱毛サロン|無料査定)\s*$", text))
         and distinct(re.compile(r"勤めが上がって|大好きなオンラインをしました|"
                                 r"お買得要綱|おショップ|ショップの形サイト|旬雑貨の|"
                                 r"味が\d種目も生じる|歯ごたえが\d種目|マンゴー母乳|"
                                 r"ストロベリー母乳|白々しいデザート|ウンザリ輩"), text) >= 3)
    if re.fullmatch(r"/[a-z-]+/\d+/?", path):
        dating_inserts = Counter(re.findall(r"[一-龯々ヶケ]{2,7}の(?:割り切り|出会い)", text))
        page("regional-dating-query-stuffed-into-profile-dialogue",
             max(dating_inserts.values(), default=0) >= 4
             and bool(re.search(r"(?:ではありません|写真を見る|Thank|[）)])"
                                r"[一-龯々ヶケ]{2,7}の(?:割り切り|出会い)|"
                                r"[一-龯々ヶケ]{2,7}の(?:割り切り|出会い)私", text))
             and len(re.findall(r"画面が表示されない|写真を見る|コメントを書いた人はブロック", text)) >= 4)
    if re.search(r"/(?:category|tag)/[^/]+/page/\d+/?$", path):
        graft = re.search(r"(?m)^(?:ところで|さて)[、,](?:夫婦にも危機|夫婦の危機)", raw)
        if graft:
            tail = raw[graft.start():]
            if (raw[:graft.start()].count("。") >= 5 and 300 <= len(tail) <= 1500
                    and re.search(r"(?m)^(?:みんなの|おすすめの|無料で相談できる)浮気調査\s*$", tail)
                    and tail.count("浮気調査") >= 4 and re.search(r"プロに依頼する|探偵に相談", tail)):
                findings["affiliate-investigation-pitch-after-unrelated-diary"] = [
                    (graft.start(), len(raw))
                ]
    if catalog := re.search(r"(?m)^\|(?:商品コメント|仕様|商品説明)\|\s*$", head):
        body = text[catalog.end():]
        merchandise = r"リュック|ポーチ|バッグ|バックパック|スカジャン|スニーカー|ウォレット"
        page("import-catalog-with-empty-fields-and-interleaved-copied-article",
             path.endswith((".htm", ".html")) and bool(re.search(r"[a-z]\d{4,}[a-z]", path, re.I))
             and bool(re.search(r"海外(?:から|送料|取り寄せ)|税関", head))
             and len(re.findall(r"(?m)^\|(?:ブランド名|商品コメント|型番|仕様|商品説明)\|\s*$", text)) >= 2
             and bool(re.search(r"(?m)^TEL *:", body))
             and len(re.findall(r"(?m)^[^\n。]{5,86}(?:" + merchandise + r")[^\n。]{0,25}$", body)) >= 3
             and bool(re.search(r"(?m)^(?:僕自身|私自身|私も最近|何の儲けにも)[^。\n]{6,150}。", body))
             and sum(line.endswith("。") and len(line) >= 20 for line in body.splitlines()) >= 8
             and bool(re.search(r"のは[☆★◆][^\n。]{4,45}(?:" + merchandise + r")[^\n。]{0,24}です。", body)))
    page("search-result-compilation", structural.stitched_search_snippets(raw)
         or bulk_search and (search_count >= 3 or len(audit.SEARCH_DATE.findall(text)) >= 2
                             and len(APP_PITCH.findall(text)) >= 2
                             or APP_SEARCH_ROUTE.search(path) and distinct(APP_SOURCES, text) >= 4)
         or (search_count >= 3 or len(SERP_COUNTS.findall(text)) >= 3)
         and DIRECTORY.search(head) and len(text) >= 600)
    page("catalog-editorial-islands", (
        field_count >= 2 and len(EDITORIAL.findall(text)) >= 3
        or field_count >= 3 and topics >= 2
        or SYNTHETIC_PATH.search(path) and field_count >= 1 and len(paragraphs) >= 10
        or field_count >= 3 and text.count("||") >= 7 and len(paragraphs) >= 10
        or "楽天ショッピングはこちら" in head and "商品詳細||" in text
        and len(re.findall(r"ファッション|コーディネート", text)) >= 4
        or field_count >= 2 and "通信販売" in text and len(re.findall(r"コンタクトレンズ|処方箋", text[-1400:])) >= 3
        and re.search(r"ギター|ピックアップ|トレモロ", head)))
    page("same-topic-bad-substitutions", distinct(IMPLAUSIBLE, text) >= 2 or
         distinct(audit.MALFORMED_VERB, text) >= 2 or distinct(audit.BROKEN_AFFILIATE, text) >= 2)
    page("keyword-replacement-across-topics", len(SEMANTIC_SWAP.findall(text)) >= 2
         or SWAP_COLLISIONS.search(text) or len(audit.MALFORMED_QUERY.findall(text)) >= 5
         or len(LEGAL_FORM.findall(text)) >= 3 and len(audit.LEGAL_NOISE.findall(text)) >= 4)
    page("fluent-paraphrase-campaign", BOOK.search(text) and (
         distinct(BOOK_PARAPHRASE, text) >= 3 or len(IN_MARKETING.findall(text)) >= 3
         and len(re.findall(r"無料アニメ動画|Webで見る|試し読み|購入", text)) >= 5))
    page("leading-particle-holes", sum(bool(gate.BARE_PARTICLE.match(p)) for p in paragraphs)
         >= max(5, len(paragraphs) // 5))
    page("contaminated-grammar-slot", structural.repeated_orphaned_prompt(raw)
         or len(gate.DEFECTIVE_SLOT.findall(text)) >= 3)
    page("duplicate-clause-end", JOIN_DEFECT.search(text) and (
         len(JOIN_DEFECT.findall(text)) >= 2 or notices >= 3
         or distinct(gate.LANGUAGE_DEBRIS, text) >= 3))
    page("literal-product-rendering", distinct(CALQUE_PRODUCT, text) >= 1 and (
         field_count >= 1 or len(re.findall(r"材質|メーカー|配送|腕時計|レプリカ", text)) >= 3
         or distinct(CALQUE_PRODUCT, text) >= 2))
    page("instruction-meaning-distortion", distinct(INSTRUCTION_DISTORTION, text) >= 2)
    page("literal-pun-translation", len(LITERAL_QA.findall(text)) >= 2
         and distinct(LITERAL_IDIOM, text) >= 2)
    page("query-echo", len(gate.QUERY_SEO.findall(text)) >= 2
         and len(gate.COMPOUND_QUERY.findall(text)) >= 3 or
         any(m[1] == m[1].strip() and " " in m[1] and text.count(m[1]) >= 3 for m in LONG_QUERY.finditer(head))
         or len(REPEATED_LANDING_QUERY.findall(text)) >= 2 and len(LOCAL_TARGET.findall(text)) >= 2)
    page("product-field-stitch", (field_count >= 2 or CATALOG_COMMAS.search(head)) and any(
         len(p) >= 105 and (len(gate.PRICE_KEYS.findall(p)) >= 4 or len(gate.MIXED_PRODUCT_CODE.findall(p)) >= 2)
         for p in paragraphs))
    page("replica-pitch-density", len(gate.COPY_SALES.findall(text)) >= 3 and notices >= 3)
    page("station-table-with-generic-pitch", distinct(TRANSIT_FIELDS, text) >= 2 and (
         len(gate.COMMERCIAL_BODY.findall(text)) >= 4 and len(gate.ACTION.findall(text)) >= 2
         or STATION_QUERY.search(head) and len(gate.PROMOTION.findall(text)) + len(DATING_PITCH.findall(text)) >= 3))
    station_ad = re.match(r"([^\n]{14,82}駅(?:近辺|周辺|付近)の)の情報を検索[!?]\s*\n\1以外にも", head)
    if station_ad:
        page("station-record-inserted-into-repeated-loan-search-pitch",
             text.count(station_ad[1]) >= 3 and distinct(TRANSIT_FIELDS, text) >= 3
             and len(set(re.findall(r"[一-龯々ヶァ-ヺ]{2,15}駅(?:周辺|近辺|付近)", head))) >= 4
             and distinct(re.compile(r"融資|キャッシング|借入|即日|審査|お金を借り"), text) >= 3
             and re.search(r"(?m)^緯度[ /／]+経度[ \t:：]*[\d./]+\s*\n地図「", text))
    repeated_query = re.match(
        r"([^\n。]{9,80})\n(?:([^\n]{9,110})以外にも[,、.。…]+\n)?[\s-]{0,16}ご訪問有難うございます",
        head,
    )
    if repeated_query:
        query = re.sub(r"の情報を検索[!?]$", "", repeated_query[1])
        page("station-record-and-interchangeable-search-keywords",
             len(query) >= 9 and repeated_query[2] in (None, query)
             and text.count(query) >= 3 and distinct(TRANSIT_FIELDS, text) >= 3
             and bool(re.search(r"(?m)^\|?緯度\s*/\s*経度[| :]*[\d.]+/[\d.]+", text))
             and "検索者が何をしたいのか" in text and "この記事は関係ありません" in text
             and distinct(re.compile(r"情報もたくさんあります|など検索すれば|検索してみよう|チェックしてみよう"), text) >= 3)
    if 430 <= len(text) <= 2900 and "検索者が何をしたいのか" in text:
        employment_query = re.match(r"([^\n。]{2,48}(?:バイト|派遣)[^\n。]{0,28}?)なら[^\n。]{2,30}[!。]", head)
        page("station-record-and-repeated-job-affiliate-search-terms",
             bool(employment_query) and text.count(employment_query[1]) >= 4
             and distinct(re.compile(r"駅名\|\||駅名\(ひらがな\)|鉄道名\|\||鉄道名\(ひらがな\)|所属路線\|\|"), text) >= 3
             and len(set(re.findall(r"[ぁ-ゖ一-龯々ヶァ-ヺー]{2,16}駅周辺", text))) >= 4
             and distinct(re.compile(r"が検索されています|検索されているキーワード|検索者が何をしたいのか|"
                                     r"(?:検索して|探して)み(?:ましょう|よう)"), text) >= 3
             and distinct(re.compile(r"ジョブセンス|バイト募集|アルバイト求人|高収入バイト|派遣バイト"), text) >= 3)
    if 180 <= len(text) <= 2400 and re.fullmatch(r"/cate_[a-z0-9]{5,16}/cont_[a-z0-9]{5,16}/?", path):
        page("earnings-template-with-unrelated-short-sentence-padding",
             distinct(re.compile(r"副業|求人情報|男性会員|メール好き|月\d+万|スマホメール"), head) >= 4
             and bool(re.search(r"毎月\d+万[円]?以上稼ぎたい.{1,20}求人情報.{0,8}毎月\d+万[円]?以上稼ぎたい", head))
             and sum(6 <= len(line) <= 28 and line.endswith("。") for line in text.splitlines()[-15:]) >= 6)
    if 180 <= len(text) <= 2500 and re.search(r"/amazon-auto-links/embed/?$", path):
        page("standalone-automatically-generated-affiliate-catalogue-embed",
             bool(re.search(r"(?:^|&)embed=amazon-auto-links(?:&|$)", address.query))
             and "WordPress への埋め込み" in text and "HTML での埋め込み" in text
             and "商品価格と取扱状況" in text and bool(re.search(r"¥[\d,]+", text)))
    if "更新することで広告が下部へ移動します" in text[:130] and 190 <= len(text) <= 1200:
        page("inactive-wiki-filled-with-corrupted-counterfeit-sales-copy",
             bool(re.fullmatch(r"/[^/]+/pages/\d+\.html", path))
             and bool(re.search(r"(?:ロレックス|腕時計|オメガ)\s*スーパーコピー", text))
             and distinct(re.compile(r"ケース|ムーブメント|文字盤|厚さ\s*\d|直径\s*\d"), text) >= 4
             and bool(re.search(r"(?m)^.{3,35}(?:ファンデーション|化粧品|スニーカー)\s+(?:比較|通販|人気).{0,20}https?://", text)))
    if 180 <= len(text) <= 1100 and path.startswith("/ja/") and path.count("/") <= 3:
        game_title = re.search(r"([^/]{2,20}(?:姫|王女|プリンセス|バービー))/?$", path)
        page("localized-game-page-with-incompatible-title-and-broken-machine-rendering",
             bool(game_title) and len(re.findall(r"ドレスアップゲーム|着せ替|バービー", text)) >= 2
             and distinct(re.compile(r"PS4|RPG|戦闘と探査|ロボット恐竜|オートマトン"), text) >= 3
             and distinct(re.compile(r"そんなに株式|この株式はお金|航海しなければならない送信|"
                                     r"達成者錫|世界オーバーフロー過去|diddleゲーム"), text) >= 2)
    if 170 <= len(text) <= 1300 and re.fullmatch(r"/[a-z]{2}\d{8,12}/[a-z]{2}\d{8,12}\.html", path):
        page("keyword-shopping-wrapper-with-unlabelled-directory-and-retail-fragments",
             "総合情報" in text[-180:] and "価格比較" in text[-160:]
             and len(re.findall(r"(?m)^●[^。\n]{3,60}。", text)) >= 2
             and distinct(re.compile(r"フットワータ|ダりーップカ|制菌効果|フィット感|吸水拡散性"), text) >= 3
             and len(re.findall(r"(?m)^[^。\n]{6,50}$", head[:230])) >= 4)
    if 220 <= len(text) <= 3700 and re.fullmatch(r"/[a-z]{2}\d{8,12}/[a-z]{2}\d{8,12}\.html", path):
        product_credits = re.findall(r"(?m)^(?:NIKIGOLFonline|アウトドア&フィッシング ナチュラム|"
                                     r"ゴルフダイジェスト・オンライン)$", text)
        page("coded-retail-aggregator-with-clipped-product-fragments",
             text.startswith("オススメ商品リスト\n")
             and max(Counter(product_credits).values(), default=0) >= 4
             and not re.search(r"販売価格|価格[:：]|商品番号|カートに入れる|[\d,]+円", text)
             or "総合情報" in text[-180:] and "価格比較" in text[-160:]
             and (bool(re.search(r"(?m)^Warning: preg_match\(\):", head))
                  or distinct(re.compile(r"国際キャンプ会議|財団法人日本アウトワードバウンド協会|"
                                         r"競技のフィールドをがっちり|防犯ブザー|ホースの巻き取り|"
                                         r"フットワータ|ダりーップカ|シグ\(SIGG\)"), text) >= 3))
    if 800 <= len(text) <= 3800 and re.search(r"不動産投資|年金対策|[Ff][Xx]-", path):
        page("investment-doorway-with-reused-household-story-and-rotating-advice",
             all(part in head for part in ("東京都内で親子", "アラフォ主婦", "業績不振で給与もボーナスも", "副業禁止って"))
             and text.count("不動産投資の家賃収入") >= 2
             and re.search(r"最後にもう一回[^\n]{10,60}良いところ", text[-480:])
             and "デメリットに思えたのでは" in text[-580:])
    if 620 <= len(text) <= 4900 and re.fullmatch(r"/notice-\d{6,8}\.html", path):
        page("retail-notice-with-embedded-copy-brand-substitutions",
             all(field in head for field in ("|題目||", "|作者||", "|作成日||"))
             and len(re.findall(r"(?:スーパーコピー|激安ブランド|ブランドコピー)", text)) >= 4
             and "|前ページ:" in text[-300:] and "次ページ:" in text[-250:]
             and distinct(re.compile(r"製品が見られるの公式|他のブランドとは異なるの|ボタンごとにの|"
                                     r"コクォルリティー|激安名今年|をするのもです"), text) >= 2)
    if 220 <= len(text) <= 1100 and re.fullmatch(r"/archives/\d+/[a-z][a-z0-9_-]{4,40}/?", path):
        page("attachment-page-with-merged-headline-teasers",
             bool(re.search(r"(?im)^\(Visited \d+ times?, \d+ visits? today\)$", text))
             and len(re.findall(r"(?:』|[。!?])(?:…|\.{3})[^。\n]{6,90}[!?]", text)) >= 3
             and text.count("『") >= 3 and not re.search(r"(?m)^(?:前の記事|関連記事|おすすめ記事)", head))
    if 300 <= len(text) <= 2200 and "Delivered by Feed43 service" in text[-140:]:
        declared_title = re.search(r"(?m)^本日は、([^\n]{12,120})の[^\n]{2,24}のサイトから紹介を行います。$", head)
        page("affiliate-redirect-generated-from-a-third-party-catalogue-feed",
             bool(declared_title) and text.count(declared_title[1]) >= 4
             and len(re.findall(r"(?m)^【[^\n]{8,150}】$", text)) >= 3
             and bool(re.search(r"画像クリックで[^。\n]{2,30}のサイトに飛びます", text[-360:])))
    if 500 <= len(text) <= 1900 and re.fullmatch(r"/\d{2,8}/?", path):
        review_title = re.search(r"(?m)^以上が([^。\n]{2,50})のレビューでした。$", text)
        page("boilerplate-fiction-review-with-repeated-imported-mistranslation",
             bool(review_title) and text.count(review_title[1]) >= 3
             and len(re.findall(r"(?m)^(?:概要|ストーリー|登場人物|評価)$", text)) == 4
             and len(re.findall(r"(?m)^・[^:：\n]{2,25}[:：]", text)) >= 4
             and len(re.findall(r"橡皮|天気予報士|悪玉海賊団|人間と.{2,8}のハイブリッド", text)) >= 3)
    if path.endswith(".php") and 950 <= len(text) <= 8500:
        page("retail-cards-interleaved-with-a-noncommercial-itinerary",
             bool(re.fullmatch(r"[a-z]{4,16}\d{4,8}[a-z]{0,8}-[a-z0-9_-]+/\d{3,8}\.html?", address.query))
             and distinct(re.compile(r"はじまりの会|\d日目|手帳|ロープワーク|火おこし|昼食の準備|班で行動"), text) >= 4
             and distinct(re.compile(r"オットマン付き|幅\d{2,4}cm|刺身セット|フェアウェイウッド|"
                                     r"受注生産|エックス フェアウェイ|まとめ売り|\d+枚\s*×\s*\d+セット"), text) >= 5)
    if 250 <= len(text) <= 1800 and re.fullmatch(r"/", path) and re.fullmatch(r"cat=\d{1,7}", address.query):
        page("category-page-with-repeated-industry-keywords-in-broken-clause-slots",
             len(re.findall(r"センサー式湿度計で|湿度計センサーで", text)) >= 4
             and distinct(re.compile(r"すこやかさ面|確立市場において|予め手段を取ることができ|"
                                     r"効率化や安全性の向上が、|体制が、非常に重要"), text) >= 3)
    if 500 <= len(text) <= 2100:
        auction_titles = Counter(re.findall(r"[ァ-ヺー]{3,20}・[A-Z0-9-]{4,13}・\d{2,3}V/[\d.]+kW", text, re.I))
        page("auction-catalogue-copy-with-repeated-lot-title-and-template-headings",
             bool(re.search(r"(?m)^\*\*[^*\n]{6,55}\*\*$", text))
             and len(re.findall(r"(?m)^[^。:\n]{8,45}:$", text)) >= 3
             and max(auction_titles.values(), default=0) >= 2
             and distinct(re.compile(r"オークション|最新のテクノロジー|待望のアイテム|性能を誇り|"
                                     r"最高のパフォーマンス|出張買取|梱包して運送業者"), text) >= 5)
    if 230 <= len(text) <= 1350 and re.fullmatch(r"/[^/]+/\d{5,9}/?", path):
        page("video-description-wrapped-in-unrelated-dating-affiliate-ad",
             distinct(re.compile(r"恋愛マッチングサイト|出会えた確率|日本最大級|\d[\d,.]*万人以上"), text[:200]) >= 3
             and (bool(re.search(r"(?m)^(?:初見さんへ|チャンネルの自己紹介|配信について)", text[30:240]))
                  and distinct(re.compile(r"ゲームの配信|視聴者様|ブロックします|アドバイス|配信の報告|チャンネル登録"), text[105:]) >= 4
                  or bool(re.search(r"(?m)^こんにちは[、,][^\n]{2,40}です[!。]", text[90:240]))
                  and distinct(re.compile(r"コメント|配信主|チャンネル登録|Twitterのフォロー"), text[120:]) >= 3
                  and len(re.findall(r"(?:^|\s)#[\wー]+", text)) >= 3))
    if 650 <= len(text) <= 4500 and path.endswith(".html"):
        locality_queries = Counter(re.findall(r"[一-龯々ァ-ヺ]{2,12}([市区町]\d{2}[才歳][^\s。]{2,14} [^\s。]{8})", text))
        page("local-job-query-repeated-inside-unsegmented-search-padding",
             max(locality_queries.values(), default=0) >= 6 and text.count("副業") >= 9
             and distinct(re.compile(r"商賈仮借|推量来遊者|御内儀の人生|副業中失礼|\d霊殿あたり|"
                                     r"別表高収入|特殊稼げる"), text) >= 3)
        title = re.match(r"【([^\s】]{4,18})\s+([^\s】]{5,32})】", text)
        if title:
            first, second = title.groups()
            page("two-heading-keywords-replaced-throughout-a-side-job-template",
                 bool(re.fullmatch(r"(?:男性|女性)\d{2}(?:才|歳)", first))
                 and text.count(first) >= 6 and text.count(second) >= 7
                 and len(re.findall(rf"{re.escape(second)}(?:をする|をした|と本業|も適職|経験がある)", text)) >= 4
                 and distinct(re.compile(r"在宅|副業|確定申告|就業規則|ダブルで収入|サラリーマン"), text) >= 5)
    if 260 <= len(text) <= 1800 and re.fullmatch(r"/t\d{18,20}/?", path):
        posts = text.splitlines()
        shared = Counter(re.findall(r"[ァ-ヺー]{6,20}", text))
        page("tweet-id-landing-assembled-from-repeated-keyword-posts",
             len(posts) >= 16 and sum(1 <= len(line) <= 23 and not re.search(r"[。！？!?]$", line) for line in posts) >= 7
             and (max(shared.values(), default=0) >= 6
                  and len(re.findall(r"(?m)^.{10,130}(?:ww|…|懐かし|ヤバ|ざわつ|ふざけ|しぬ|ハッシュタグ|\s#).*$", text)) >= 4
                  or max(Counter(re.findall(r"[A-Z]{2,8}[一-龯]{2}", text)).values(), default=0) >= 3
                  and max(Counter(re.findall(r"(?m)^【[^】\n]{3,32}】$", text)).values(), default=0) >= 2
                  and sum(1 <= len(line) <= 22 and not re.search(r"[。！？!?]$", line) for line in posts) >= 8)
             and not re.search(r"(?m)^(?:執筆|本文|取材|投稿日時|投稿日|プロフィール|返信先)", head))
        reused_name = Counter(term for line in posts[2::2]
                              for term in set(re.findall(r"[一-龯々]{2,5}[ぁ-ゖ]{3}", line)))
        page("status-id-search-landing-with-recycled-nickname-and-no-post-attribution",
             len(posts) >= 19 and len(set(posts)) == len(posts) and len(posts[0]) <= 45
             and max(reused_name.values(), default=0) >= 7
             and sum(2 <= len(line) <= 21 and not line.endswith(("。", "?", "!")) for line in posts[1::2]) >= 8
             and not re.search(r"https?://|投稿日時:|リポスト|原文へのリンク|執筆", text))
        reply_targets = set(re.findall(r"(?m)^返信先:\s*@([A-Za-z0-9_]+)", text))
        social_keyword = Counter(term for line in posts[2::2]
                                 for term in set(re.findall(r"[一-龯]{3,8}|[ァ-ヺー]{4,16}", line)))
        page("numbered-social-keyword-collage-with-empty-comment-footer",
             14 <= len(posts) <= 35 and posts[-1] == "コメント"
             and len(posts[0]) <= 14
             and max(social_keyword.values(), default=0) >= 6
             and sum(1 <= len(line) <= 24 and not re.search(r"[。!?]$", line) for line in posts[1:-1:2]) >= 8
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
        page("numbered-social-search-page-with-detached-keyword-posts",
             16 <= len(posts) <= 36 and len(set(posts)) == len(posts)
             and (len(reply_targets) >= 3 and max(shared.values(), default=0) >= 6
                  or max(Counter(re.findall(r"[ァ-ヺー]{4,20}", text)).values(), default=0) >= 7
                  and max(Counter(re.findall(r"(?<!\w)#[^\s#]{3,28}", text)).values(), default=0) >= 3)
             and max(sum(1 <= len(line) <= 23 and not re.search(r"[。!?]$", line) for line in posts[offset::2])
                     for offset in (0, 1)) >= 8
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
        page("tweet-conversation-collage-between-unrelated-marketing-lines",
             len(posts) >= 15 and len(set(posts)) >= 12 and posts[0] == posts[-1]
             and bool(re.fullmatch(r"日本人男性専用トレーニング|男性向けモテる男養成講座", posts[0]))
             and len(re.findall(r"(?m)^返信先:@[A-Za-z0-9_]+", text)) >= 2
             and sum(1 <= len(line) <= 27 for line in posts[1:-1]) >= 8
             and not re.search(r"(?:https?://|発信者:|投稿日時:)", text)
             and distinct(re.compile(r"トレーニング|筋力|ジム|筋トレ"), "\n".join(posts[1:-1])) <= 1)
        page("social-reply-collage-with-detached-trade-and-image-headlines",
             len(posts) >= 17 and sum(1 <= len(line) <= 25 for line in posts) >= 10
             and bool(re.search(r"(?m)^【交換】.{2,35}\n[A-Z]{3,12}\n【画像】", text[:165]))
             and max(Counter(re.findall(r"[ぁ-ゖ]{4,7}(?=の|は|[、!?]|MV)", text)).values(), default=0) >= 4
             and bool(re.search(r"(?m)^返信先:@[A-Za-z0-9_]+", text))
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
        display_posts = [line for line in posts[5:-1] if len(line) <= 28]
        page("numbered-social-search-collage-with-detached-quote-after-title",
             16 <= len(posts) <= 32 and posts[-1] == "コメント"
             and bool(re.search(r'(?m)^『[^\n]{16,150}【[^】\n]{4,50}】$', text[:220]))
             and len(display_posts) >= 8 and bool(re.search(r"返信先:\s*@[A-Za-z0-9_]{3,}", text))
             and max(Counter(re.findall(r"[ァ-ヺー]{4,14}", text)).values(), default=0) >= 6
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
        page("numbered-social-reply-collage-with-duplicated-headlines-and-empty-handle",
             len(posts) >= 17 and len(posts[0]) <= 18
             and sum(1 <= len(line) <= 22 for line in posts) >= 10
             and bool(re.search(r"(?m)^返信先\s*:\s*@[ \t]*$", text))
             and len(re.findall(r"@[A-Za-z][A-Za-z0-9_]{3,24}より", text)) >= 2
             and max(Counter(re.findall(r"(?m)^〈独自〉[^\n@]{15,100}", text)).values(), default=0) >= 2
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
        page("social-search-results-with-clipped-promo-in-reply-feed",
             17 <= len(posts) <= 38 and posts[-1] == "コメント"
             and bool(re.search(r"(?m)^返信先:@[A-Za-z0-9_]{3,}", text))
             and sum(1 <= len(line) <= 19 and not re.search(r"[。!?]$", line) for line in posts[1:-1]) >= 10
             and distinct(re.compile(r"番組紹介サイト|アニメ円盤新作情報|【楽天市場|^先着$|^#$", re.M), text) >= 3
             and not re.search(r"https?://|投稿日時:|原文へのリンク", text))
    if 800 <= len(text) <= 5000 and re.fullmatch(r"/(?:uranai/)?event\d{2}(?:/divination|/index_01)?/?", path):
        name_age_heading = re.match(r"([^\n]{2,28})さんの姓名判断\n\1さんの年代運勢\n", text)
        unlikely_places = re.search(r"(?m)^- 場所\n(?:- (?:怪しい|汚れた|狭い)"
                                    r"(?:歩道橋|城|霊園|屋敷|墓地|廃墟)\n){2}", text)
        page("generated-name-fortune-with-unrelated-random-compatibility-objects",
             address.query.startswith("l_name=") and "&f_name=" in address.query
             and (distinct(re.compile(r"天格\d+画|人格\d+画|地格\d+画|外格\d+画"), head) >= 4
                  or (name_age_heading and unlikely_places))
             and bool(re.search(r"(?m)^- 吉運の相性\n- 凶運の相性\n- 人\n(?:- [^\n]+\n){2}"
                                r"- 物\n(?:- [^\n]+\n){2}- 場所\n(?:- [^\n]+\n){2}- 名言・格言$", text))
             and len(re.findall(r"(?m)^- \d{2}代(?:[〜~]|から)\d{2}代の(?:運勢|吉凶)", text)) >= 3)
        page("generated-name-fortune-with-empty-fields-and-random-objects",
             address.query.startswith("l_name=") and "&f_name=" in address.query
             and bool(re.match(r"[^\n]{2,28}さんの姓名判断\n- 総格\n", text))
             and "- 陰陽五行\n-\n- 五行三才\n-" in head
             and len(re.findall(r"(?m)^- \d{2}代(?:[〜~]|から)\d{2}代の(?:運勢|吉凶)", text)) >= 3
             and bool(re.search(r"(?m)^- 吉運の相性\n- 凶運の相性\n- 人\n(?:- [^\n]+\n){2}"
                                r"- 物\n(?:- [^\n]+\n){2}- 場所\n(?:- [^\n]+\n){2}- 名言・格言$", text))
             and distinct(re.compile(r"下品な(?:座布団|椅子|靴)|大きな顔の|近い(?:花壇|墓地)|"
                                     r"朱色の(?:絵具|輪ゴム)|怪しい(?:屋敷|歩道橋)"), text[-575:]) >= 2)
        page("generated-age-fortune-with-unrelated-compatibility-insert",
             address.query.startswith("l_name=") and "&f_name=" in address.query
             and bool(re.match(r"([^\n]{2,28})さんの年齢別の運勢を診断\n\1さんの年齢別運勢を姓名の字画数", text))
             and len(re.findall(r"(?m)^[^\n]{2,28}さんの(?:誕生[〜~～]|\d{2}歳[〜~～])\d{1,2}歳運勢の傾向$", text)) >= 4
             and bool(re.search(r"(?m)^- 吉運の相性\n- 凶運の相性\n- 人\n(?:- [^\n]{2,28}\n){2}"
                                r"- 物\n(?:- [^\n]{2,28}\n){2}- 場所\n(?:- [^\n]{2,28}\n){2}"
                                r"[^\n]{2,35}さんに贈る言葉$", text))
             and distinct(re.compile(r"[色の]輪ゴム|不思議な携帯電話|汚れた(?:靴|箱)|色の付いた(?:紙|袋)|"
                                     r"狭い(?:競輪場|霊園|墓地)|怪しい(?:屋敷|歩道橋)|静かな島"), text[-500:]) >= 3)
    if 160 <= len(text) <= 1900 and re.search(r"/(?:archive|entry)/20\d{2}/\d{2}/\d{2}(?:/\d{6})?/?$", path):
        page("spun-blog-text-with-broken-attribution-wrappers",
             bool(re.search(r"素人ですが、(?:検索で|サイトでみてみた情報では)", text))
             and distinct(re.compile(r"が、ですが|な、結論されていと|消去不可能だった|"
                                     r"では歴然とした定義はありません|のように公表されているみたいです|"
                                     r"のように解釈されている模様です|たぶん胃袋には負荷をかけないで済む"), text) >= 3
             and ("「「" in text or len(re.findall(r"」(?:な、|のように|だと)", text)) >= 3))
    if 160 <= len(text) <= 1300 and re.fullmatch(r"/(?:tvs|movie|tv)/\d{4,9}/?", path):
        page("video-listing-with-only-unrelated-embedded-tweets",
             bool(re.match(r"評価\n評価はありません。\n共有\nこの作品に関するツイート\n", text))
             and len(set(re.findall(r"\(@([A-Za-z0-9_]{2,20})\) (?:January|February|March|April|May|June|July|"
                                    r"August|September|October|November|December) \d{1,2}, 20\d{2}", text))) >= 2
             and not re.search(r"(?m)^(?:作品紹介|作品情報|あらすじ|公開日|出演者|キャスト|監督[:：])", text))
    if 400 <= len(text) <= 3500 and re.fullmatch(r"/[a-z]{3,6}\d{3,6}[a-z]{3,6}\d{2,5}[a-z]{3,6}/?", path, re.I):
        page("opaque-merchant-route-with-catalogue-bracketed-by-diary-clips",
             len(re.findall(r"(?m)^.{15,130}\.\.\.$", head[:220])) >= 2
             and len(re.findall(r"(?m)^.{15,130}\.\.\.$", text[-290:])) >= 3
             and len(re.findall(r"(?m)^\|[^\n]{8,130}\|$", text)) >= 2
             and distinct(re.compile(r"適合車種|排気量|取付け説明書|本商品は|車検対応品|"
                                     r"材質|商品仕様|部品番号|定格出力|適合機種"), text) >= 4
             and not re.search(r"(?m)^(?:関連(?:記事|商品)|おすすめの(?:記事|商品)|このサイトについて)", text))
    if 350 <= len(text) <= 3200 and re.fullmatch(r"/[^/]{3,24}/blog-entry-\d{4,8}\.html?", path, re.I):
        page("mirrored-image-post-with-repeated-sponsor-shell-and-no-body",
             bool(re.search(r"(?m)^↓メインコンテンツはもう少し下だよ[^\n]*↓\nスポンサーサイト\n"
                            r"オススメサイトのPICK UP記事 その1\n↓{3,}\s*メインコンテンツ\s*↓{3,}\n"
                            r"この画像も見逃せない!\n超話題の激選サイト\nオススメサイトのPICK UP記事 その2\n関連記事\n", text))
             and len(re.findall(r"(?m)^- [^\n]{15,180}$", text)) >= 7)
    if 300 <= len(text) <= 4800 and re.search(r"退職代行|転職|債務整理|引越|住宅ローン", path):
        endorsements = re.findall(r"(?m)^([^\n]{10,180}[。!])\n\([一-龯々ぁ-ゖァ-ヶ]{3,12}様\)$", text)
        lines = text.splitlines()
        page("unrelated-testimonial-rows-under-nonmedical-commercial-keyword",
             len(set(endorsements)) >= 6 and lines[0] == lines[-1]
             and distinct(re.compile(r"DVDと同じ動き|張っていくのを感じ|早まって手術|"
                                     r"手術に手を出さない|体が硬くて|食事以外ありません|全身が若返った"), text) >= 3
             and not re.search(r"(?m)^(?:関連|引用|出典|利用上の注意|お客様アンケート)", text))
    if 320 <= len(text) <= 2400 and path == "/" and re.fullmatch(r"p=\d{1,6}", address.query):
        page("opaque-post-with-unattributed-game-chat-and-interleaved-unrelated-comments",
             distinct(re.compile(r"RaHu|FoTe|TAアブダクション|デッドリーサークル|ロビキャン|"
                                     r"モデュ装備|AIS|アサバス|クロト\d連"), text) >= 5
             and distinct(re.compile(r"携帯の充電の減り|髪型服ネイル全部一緒|ださくてもオリジナリティ|"
                                     r"レベルも下の[⑨9]のほうがよっぽど"), text) >= 2
             and len(re.findall(r"(?i)PSO2", text)) >= 4
             and bool(re.search(r"置いてある。う[A-Z]{2,4}[^。]{3,35}。|のしか知らない。最近レセプター", text))
             and not re.search(r"(?m)^(?:コメント\s*[:：]|著者|投稿者|返信先|出典)\s*", text))
    if 950 <= len(text) <= 5900 and re.match(r"/20\d{2}/\d{2}/\d{2}/", path):
        place_slot = re.match(r"([一-龯]{2,6}[都道府県]\s+[一-龯]{2,13}[市町村区])出会い系アプリランキング", text)
        page("local-dating-app-pitch-with-repeated-slots-and-broken-promotion-markup",
             place_slot and text.count(place_slot[1]) >= 3 and text.count("ASOBO出合いアプリ") >= 4
             and distinct(re.compile(r"(?m)^アプリに登録まで$|^二人きりのデート$|^アプリはいいよ!$"), text) >= 3
             and bool(re.search(r"ASOBO出合いアプリ!>", text)))
    if 220 <= len(text) <= 2600:
        page("keyword-results-with-detached-search-term-list-and-no-answer",
             path.startswith("/kw/") and bool(re.search(r"(?m)^「[^\n」]{3,48}」に関する新着セミナー$", text))
             and bool(re.search(r"(?m)^「[^\n」]{3,48}」に関連するキーワード\n注目キーワード一覧$", text))
             and len(re.findall(r"(?m)^- [^\n。]{8,70}$", text)) >= 8
             and len(re.findall(r"(?m)^(?:基礎解説)?[^\n。]{3,25}とは[?？]$", text)) >= 2
             and not re.search(r"(?m)^(?:最新[!！]人気の記事情報|「[^\n」]+」に関する記事情報)$", text))
        manual_query = re.fullmatch(r"/kw/(?:[^/\s]{2,26}\s+){0,2}((?=[a-z0-9-]*[0-9])[a-z][a-z0-9-]{2,17})"
                                    r"\s+(使用説明書|説明書|取説|マニュアル)/?",
                                    normalize(path).replace("−", "-"), re.I)
        if manual_query and "注目キーワード一覧" in text:
            lead = re.search(r"(?m)^「([a-z]{2,9}|使用説明書|説明書|取説|マニュアル)」に関する記事情報\n", text, re.I)
            page("model-manual-keyword-page-populated-with-unrelated-search-excerpts",
                 lead and (manual_query[1].lower().startswith(lead[1].lower()) or manual_query[2] == lead[1])
                 and manual_query[1].lower() not in text.lower()
                 and len(re.findall(re.escape(f"「{lead[1]}」"), text)) >= 3
                 and len(re.findall(r"(?m)^- [^\n。]{7,70}$", text)) >= 8
                 and bool(re.search(r"(?m)^「[^」\n]+」に関連するキーワード\n注目キーワード一覧$", text)))
        page("spaced-diet-diary-under-unrelated-business-page-title",
             bool(re.match(r"/20\d{2}/\d{2}/\d{2}/", path))
             and bool(re.search(r"退職|転職|債務|融資|査定|引越", path))
             and len(re.findall(r"[ぁ-んァ-ヺ一-龯] +(?:は|が|を|の|に|でも|です|ます|など)[ぁ-ん、]", text)) >= 8
             and distinct(re.compile(r"ダイエット|体操|腹筋|ぜい肉|有酸素運動|ウエスト|肩幅"), text) >= 5
             and not re.search(r"(?m)^(?:注記|転載元|著者|資料|追記)", text))
        page("fx-affiliate-pitch-followed-by-standalone-diary",
             bool(re.search(r"fx|トレード|投資", path, re.I))
             and distinct(re.compile(r"FX(?:トレード|初心者)|トレーダー|勝率|常勝|相場が上がる|給料以外|稼げる"), text[:350]) >= 3
             and bool(re.search(r"(?m)^(?:お元気ですか[?？]|おつかれ[!！]|こんにちは[!！])\s*$", text[170:700]))
             and distinct(re.compile(r"って事で日記は|仕事休みになれば|またです[!！]|それはさておき|"
                                     r"昼ご飯を食べ|おいしかった[!！]|は仕事あり過ぎ|焼酎でも飲みたい|"
                                     r"今度のお休みは|ショッピングに行って|今日も訪問感謝"), text[-750:]) >= 3)
        page("counterfeit-keywords-inserted-in-broken-shopping-translation",
             len(re.findall(r"(?:偽物|スーパーコピー)(?:[ぁ-ゖァ-ヺ一-龯]|\s+また)", text)) >= 2
             and distinct(re.compile(r"コストはありません|ショッピングカートをロード|"
                                     r"かかとを着る|二重義務を行う|少し幻想的な買い物|"
                                     r"潜在的に危険でないことなく"), text) >= 3)
    if 750 <= len(text) <= 6500 and re.fullmatch(r"/archives/\d{4,9}/?", path):
        recruiting = re.findall(r"このサイトは([^\s、。]{2,13})の女性に対する高収入情報", text)
        page("place-swapped-recruiting-solicitations-with-keyword-padding",
             len(set(recruiting)) >= 4 and "検索タグ" in text
             and len(re.findall(r"(?:^|[,，])(?:高級|未経験|短期間|求人|高収入求人)(?=[,，])", text)) >= 6
             and distinct(re.compile(r"デリヘル|女性パート|託児所|日払い|短時間"), text) >= 4)
    if 850 <= len(text) <= 6000 and re.search(r"/what-channel-is-[a-z0-9-]+(?:/|$)", path):
        page("translated-sports-schedule-with-unrelated-film-and-game-queries",
             distinct(re.compile(r"プレミアリーグ|スポーツ ハブ|ライブストリーミング|試合後|RadioTimesSport|bet365"), text) >= 4
             and distinct(re.compile(r"アーミーオブザデッド キャスト|グッド ガールズ netflix|サドル マインクラフト|"
                                     r"シムズ[0-9 ]+チート|シーズン \d+ ネタバレ"), text) >= 2
             and distinct(re.compile(r"このコンテストは終了しました|うまく走ることが期待|マネージャーが喉を鳴ら|"
                                     r"重要な呪文です|ランナーとライダーの数"), text) >= 2)
    if 190 <= len(text) <= 1050 and path in {"", "/"}:
        housing_phrases = Counter(re.findall(r"[一-龯]{2,6}の(?:マンション|賃貸物件|不動産)", text))
        page("personal-diary-filled-with-housing-query-after-bare-idn-link",
             bool(re.match(r"- bestsite\s*\nhttps?://xn--[^\n/]+/?\s*\n", text, re.I))
             and max(housing_phrases.values(), default=0) >= 5
             and distinct(re.compile(r"引っ越し|家に行って|手伝う|卒業アルバム|結婚する"), text) >= 3)
    if 650 <= len(text) <= 2800 and path in {"", "/"}:
        page("regional-dating-entry-mixing-keywords-with-unrelated-conversation-fragments",
             bool(re.search(r"(?m)^.*(?:いりぐち|Enter).*$", text[:220]))
             and distinct(re.compile(r"東北|北陸|関東|近畿|九州|[一-龯]{2,3}県"), text) >= 9
             and len(re.findall(r"恋活|婚活|出会い|セフレ", text)) >= 24
             and (len(re.findall(r"line掲示板[a-z]*/detail/\d{4,}", text, re.I)) >= 3
                  or bool(re.search(r"\d{2}:\d{2}:\d{2} ID:[\w+/]+", text)))
             and max(Counter(re.findall(r"というのは抜群でした|完全無欠HP|マニア向けページ|"
                                        r"今から書くことは[^。\n]{14,55}", text)).values(), default=0) >= 2)
    if 350 <= len(text) <= 2900 and re.fullmatch(r"/[a-z]{5,26}/\d{4,9}\.html?", path):
        code_counts = Counter(re.findall(r"(?<![A-Z0-9])[A-Z]{2,5}-[A-Z]{1,4}-\d{2,5}(?![A-Z0-9])", text))
        price_cards = re.findall(r"(?m)^商品番号\s*:\s*[a-z0-9]{8,25}\s*\n価格\s*:\s*\d+\.\d{2}", text, re.I)
        japanese_insertions = Counter(re.findall(r"(?<=[ぁ-ゖ])[ァ-ヺー]{5,20}(?=[ぁ-ゖ、,。])", text))
        if price_cards:
            punctured_words = re.findall(r"(?:上[,。]げ|なっ[,。]た|拾わ[,。]れ|もち[,。]ろん|私た[,。]ち|"
                                         r"等[,。]級|へい[,。]った|選ん[,。]だ|でき[,。]た|あな[,。]た|"
                                         r"言いま[,。]し|振っ[,。]て|し[,。]た)", text)
            page("retail-price-card-with-punctured-serialized-fiction",
                 len(punctured_words) >= 4
                 and distinct(re.compile(r"軽功|熟練度|棺の蓋|神行靴|レベル|内功|装備|任務|"
                                         r"派の|剣法|実力|戦場|怒鳴った"), text) >= 5
                 and text.count("「") >= 3
                 and (bool(re.search(r"&[a-z]{2,9}[,。][a-z]{1,4};", text, re.I))
                      or len(punctured_words) >= 7))
        page("retail-item-code-repeated-inside-serialized-fiction",
             bool(price_cards)
             and (max(code_counts.values(), default=0) >= 5
                  and distinct(re.compile(r"王妃|任務|甥と姪|剣|を[^。\n]{0,6}振って|と[，,]?言いました|首を横"), text) >= 4
                  and len(re.findall(r"。[,，]|[,，]。|。で[,，]|。に振", text)) >= 2
                  or len(price_cards) >= 2 and sum(n >= 2 for n in japanese_insertions.values()) >= 2
                  and len(re.findall(r"[ぁ-ゖ]。(?=[ぁ-ゖ])|[一-龯][,，](?=[一-龯])|[,，]。", text)) >= 4
                  and distinct(re.compile(r"攻撃力|急所を刺す|属性を見|宦官|生け捕り|切磋琢磨|口を自慢"), text) >= 4))
    if 750 <= len(text) <= 8000 and re.fullmatch(r"/[a-z0-9]+items/(?:etidm|itm)[a-z0-9]+/?", path, re.I):
        page("secondhand-sale-cards-inserted-inside-book-review",
             distinct(re.compile(r"献本|読書メモ|書籍|インタビュー記事|本で描かれ|引用"), text) >= 4
             and distinct(re.compile(r"カードダス|ライトセーバー|ブラジャー&ショーツ\d点|真作|まとめて出品|"
                                     r"防音ケージ|マルジェラ|遊戯王"), text) >= 5
             and bool(re.search(r"体験した人た[ァ-ヺー]|の影響は、「[^」]+」や「[^」]+\d点セット」", text)))
    if 140 <= len(text) <= 630 and re.fullmatch(r"/archive/20\d{2}/\d{2}/\d{2}/?", path):
        page("clipped-daily-archive-combining-unrelated-entertainment-snippets",
             "引用をストックしました" in text and "限定公開記事のため引用できません" in text
             and bool(re.match(r"(?:今日|昨日)[^。\n]{15,100}。[^。\n]{12,140}。[^。\n]{12,100}(?:…|\.\.\.)\n", text))
             and distinct(re.compile(r"アニメイト|VRが発達|アニメキャラランキング|都内で[^。\n]{3,20}MovieNEX|"
                                     r"が舞台あいさつ|声優ランキング|ファン投票"), text[:250]) >= 4)
    if 260 <= len(text) <= 1150 and re.fullmatch(r"/feed/\d{6,12}/?", path):
        lines = [line for line in text.splitlines() if line]
        page("video-headline-feed-with-test-marker-and-unrelated-humor-snippets",
             17 <= len(lines) <= 40
             and bool(re.search(r"(?m)^▼\s*テスト\d+$", text))
             and sum(line.startswith("▼") for line in lines) >= 3
             and len(re.findall(r"(?m)^.{8,120} - (?:シュール|バカ)系\d+枚$", text)) >= 3
             and distinct(re.compile(r"ドラレコ|動画|対向車|映像|スピード出しすぎ|DQN"), text) >= 4)
        page("feed-entry-filled-exclusively-with-mixed-standalone-headlines",
             14 <= len(lines) <= 32 and sum(7 <= len(line) <= 78 for line in lines) >= 13
             and sum(line.endswith("。") for line in lines) <= 1
             and distinct(re.compile(r"おすすめの本|小説|青空文庫|電動歯ブラシ|オブジェクト指向|"
                                     r"旅行記|行き方|ブログ始めて|ロックフェス"), text) >= 6
             and not re.search(r"(?m)^(?:https?://|出典|関連記事|投稿者|引用|関連リンク)[ :：]?", text))
    dated_post = re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?", path)
    hatena_appraisal_post = (
        dated_post and host.endswith((
            ".hatenablog.com", ".hatenablog.jp", ".hateblo.jp",
            ".hatenadiary.com", ".hatenadiary.jp",
        ))
        and "査定" in text and ("ガリバー" in text or "ラビット" in text)
    )
    if hatena_appraisal_post:
        page("dated-hatena-post-with-car-appraisal-and-dealer-name", True)
    elif dated_post and 220 <= len(text) <= 1100:
        appraisal_vocab = distinct(re.compile(r"買い替え|買取相場|売却|カローラ|プリウス|高額査定|下取り"), text[:420])
        page("car-buyback-copy-with-unrelated-fashion-and-word-sense-fragments",
             appraisal_vocab >= 5
             and distinct(re.compile(r"ラビットファーをまとう|小人の国|巨人としてふるまう|直売\d+万件|"
                                     r"元売の\d+年度シェア|店の雰囲気などによって自分のと"), text) >= 3)
        page("car-buyback-copy-with-unrelated-service-and-product-snippets",
             appraisal_vocab >= 4 and text.count("査定") >= 4
             and bool(re.search(r"引越し業者に.{0,12}見積もり|引越センター.{0,30}見積もり", text))
             and bool(re.search(r"(?:ロジャーラビット|ラビット).{0,5}(?:DVD|ブルーレイ)", text))
             and bool(re.search(r"。も(?:含め|でき)|価格の\d+(?:車|買い替え)", text)))
    if 140 <= len(text) <= 620 and re.fullmatch(r"/tag/[^/]+-[a-f0-9]{20,110}/?", path):
        page("encoded-tag-with-mixed-news-and-gossip-machine-snippets",
             bool(re.match(r"[A-Z]{2,5}経由の画像。", text))
             and distinct(re.compile(r"地方検事|過失致死罪|射殺した警察官|ゲッティイメージズ|"
                                     r"の音楽や振る舞い|何か間違ったことをした"), text) >= 5
             and len(re.findall(r"[A-Za-z]{4,}[A-Z][a-z]{3,}", text)) >= 2)
    if 330 <= len(text) <= 1900 and re.fullmatch(r"/(?:19|20)\d{2}/\d{2}/\d{2}/[^/]+/?", path):
        page("automatic-market-report-sales-page-with-repeated-report-id-and-translated-labels",
             "precisionreports.co/" in text and "市場レポート" in head
             and len(re.findall(r"precisionreports\.co/(?:enquiry/[^/ \n]+|purchase)/\d{5,12}", text)) >= 3
             and distinct(re.compile(r"サンプルPDFレポートを入手|クエリについては|市場のプレーヤーで|"
                                     r"地域別の[^。\n]{3,20}市場分析|市場レポートを購入する理由|レポートの価格"), text) >= 5
             and bool(re.search(r"タップできる今後の機会|市場を襲っている主要なチャネル|"
                                 r"完全な注意を提供します|需要の元の要因", text)))
        page("comic-clickbait-heading-grafted-to-repeated-clinic-keywords",
             bool(re.match(r"【(?:漫画|マンガ)】[^\n]{15,130}(?:【マンガ動画】|【漫画動画】)\n", text))
             and distinct(re.compile(r"首周り|筋肉の緊張|カイロプラクティック|骨格の歪み|理学療法|脊椎|神経圧迫"), text) >= 5
             and len(re.findall(r"(?:かたこり|肩凝り|肩こり)\((?:かたこり|肩凝り|肩こり)", text)) >= 5)
        page("business-clickbait-heading-grafted-to-an-unrelated-clinical-article",
             bool(re.match(r"[^\n]{4,120}(?:インボイス|せどり|納税額)[^\n]{4,100}[!！]\n(?:頭痛|腰痛|肩こり)", text))
             and distinct(re.compile(r"インボイス|せどり|納税額|経理|大迷惑"), text[:150]) >= 3
             and distinct(re.compile(r"頭痛|片頭痛|疾患|慢性|患う|熱が|神経|湿布|吐き気"), text[70:]) >= 4)
    if 165 <= len(text) <= 1050 and re.search(r"/business/[^/]+/[^/]+\.html?", path):
        page("copied-business-profile-with-foreign-ad-keywords-joined-to-prose",
             distinct(re.compile(r"醫薬|抗體|生體|従來|貢獻"), text) >= 4
             and bool(re.search(r"。[^\n。]{3,24}[,，][^\n。]{3,24}[,，][^\n。]{3,24}[,，]", text))
             and distinct(re.compile(r"三级|无码|日韩综合|国产|欧美|自拍亚洲|自拍偷拍"), text[-280:]) >= 4
             and not re.search(r"(?m)^(?:関連資料|引用元|ログ|出典)[ :：]", text))
    if 850 <= len(text) <= 5800 and re.fullmatch(r"/20\d{2}/\d{2}/\d{2}/[^/]*雀荘[^/]*/?", path):
        page("mahjong-landing-assembled-from-unattributed-forum-clips",
             len(re.findall(r"(?m)^.{6,64}$", text)) >= 29
             and len(re.findall(r"(?m)^- [^\n]{0,20}雀荘[^\n]{4,65}$", text)) >= 4
             and distinct(re.compile(r"アガる|ピン東|ゴミ手|オーラス|手役型|タンヤオ|仕掛け|四暗刻"), text) >= 6
             and len(re.findall(r"(?m)^.{3,60}(?:と思います|ですよね|でしょうか|だよな|これは迷います)[。？!?]?$", text)) >= 3
             and not re.search(r"(?m)^(?:投稿者|引用|出典|コメント番号|書き込み時刻)", text))
    if 520 <= len(text) <= 3650 and re.fullmatch(r"/20\d{2}/\d{2}/\d{2}/[^/]+/?", path):
        page("fashion-query-insertions-inside-broken-localized-dialogue",
             distinct(re.compile(r"ポールスミス|ブランド|ウォッチ|時計|メンズ|アウトレット|バッグ|財布"), path) >= 3
             and max(Counter(re.findall(r"[一-龯]{2}バッグ[ァ-ヺー]{7}", text)).values(), default=0) >= 2
             and distinct(re.compile(r"テキストメッセージ|電話の向こう|彼女の声|彼女を助ける|マスター[一-龯]{1,3}|"
                                     r"彼女を心配|腎臓にスライド"), text) >= 4
             and bool(re.search(r"(?m)^Read More[:：]\s*$|(?:財布|バッグ) 新作。彼女", text)))
    if 120 <= len(text) <= 700 and re.fullmatch(r"/[a-z]{6,18}/\d{4,9}\.html?", path):
        page("unlabelled-multilingual-query-collage-on-numbered-landing",
             distinct(re.compile(r"军|耽美|婷婷|护士|视频|纶理|喷液|新入口|四川|无码|乱子图片"), text) >= 5
             and distinct(re.compile(r"しんちゃん.{0,10}動画|映画館|ボディーガード|ダウンロード|ドラマ全集|"
                                     r"で私のキス|の親映画館"), text) >= 4
             and len(re.findall(r"[、,]", text)) >= 8 and len(text.splitlines()) <= 5)
    if 95 <= len(text) <= 550 and re.fullmatch(r"/[a-z0-9]{5,18}/\d{4,9}\.html?", path):
        phrases = re.split(r"[、,\n]", text)
        simplified = re.compile(r"[妈儿视频两齐图检鸡飘边该库与这汉门声谍战剧张爷鬟戏粤语线在线播放峡说动经钻进产湾实]")
        page("numbered-query-page-with-unlabelled-chinese-and-japanese-fragments",
             len(phrases) >= 12 and len(text.splitlines()) <= 5
             and sum(bool(simplified.search(s)) and not re.search(r"[ぁ-ゖ]", s) for s in phrases) >= 4
             and sum(bool(re.search(r"[ぁ-ゖ]", s)) for s in phrases) >= 4
             and distinct(re.compile(r"カソード楽器|アライグマのコート|GIFを滑っ|入院前の\d日間を読む|"
                                     r"ニュースシステムを開発することにより|女性の割[。.]$|"
                                     r"の恋人韓国語バージョン|のドアドライ|ホテル\d接続|かかとのルアー|"
                                     r"禁止小説女性|ガールフレンド動物王国|パンツヘビープレイ中|"
                                     r"女性の写真を再生|クリップピンアクシ"), text) >= 3)
    if 250 <= len(text) <= 3500 and re.fullmatch(r"/買取[^/]{2,55}\.html?", path):
        page("buyback-landing-with-mechanically-rewritten-packing-instructions",
             bool(re.match(r"【買取[^】]{2,65}】", text))
             and distinct(re.compile(r"新聞紙新聞紙|新聞紙の強度をの商品|商品や商品、ダンボール|"
                                     r"緩衝材を敷きます|気泡の商品の空いた|保護材は新聞紙にある|"
                                     r"ご送料まで梱包|ご無料お送り業者|お提出地域を必ず控え"), text) >= 4
             and distinct(re.compile(r"緩衝材|プチプチ|着払|佐川急便|送り状|ダンボール"), text) >= 4)
    if 420 <= len(text) <= 8500 and path in {"", "/"}:
        dating_slots = Counter(re.findall(r"(?<![一-龯])([一-龯]{2,6})(?:の|での?)出会い(?:掲示板)?", text))
        page("place-dating-phrase-inserted-throughout-unrelated-diary-fragments",
             max(dating_slots.values(), default=0) >= 8
             and distinct(re.compile(r"長い間あなたを見に来た|仕事中に何をしていますか|体育実技試験|"
                                     r"下向き矢印|散った汗|ソロでDJ|ハート・ダッシュ|水槽|"
                                     r"味噌汁|涙1リットルスペシャル|寝る手|幸せな顔|不安を抱え"), text) >= 5
             and bool(re.search(r"[A-Za-z]{2,}[一-龯]{2,6}(?:の|での?)出会い[A-Za-z]{2,}|"
                                 r"出会いを終えた水族館|出会いは長い間あなたを見に来た", text)))
    if 200 <= len(text) <= 900 and path in {"", "/"}:
        page("unattributed-reply-clips-pasted-into-a-blog-homepage",
             bool(re.match(r"返信先[ぁ-ゖァ-ヺ一-龯][^\n]{18,100}\n", text))
             and 5 <= len(text.splitlines()) <= 16
             and distinct(re.compile(r"電通|卒業していったメンバー|公演中止|声の出演|インフルエンザ|[48]K"), text) >= 5
             and bool(re.search(r"(?m)^は\dK(?:どころか|も)", text))
             and not re.search(r"(?m)^出典|^引用|^関連記事|^https?://|@[A-Za-z0-9_]+", text))
    if 200 <= len(text) <= 900 and re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?", path):
        page("dated-blog-entry-concatenating-incompatible-nutrition-and-medical-snippets",
             distinct(re.compile(r"健康食品|ハーブ|栄養成分|プロポリス|サプリメント|ミネラル"), text) >= 5
             and distinct(re.compile(r"について獣医師が|クリニック監修発生量|健康レッドクローバー|"
                                     r"腎機能の障害20\d{2}年|店舗やに問い合わせ|身体機能正規化|"
                                     r"ボタンウフウ末|パンに、日に約"), text) >= 4)
    if 160 <= len(text) <= 790 and re.fullmatch(r"/[^/]{2,32}/\d{3,7}/?", path):
        endorsement = re.match(r"([^\n]{5,65}?)\s*に関する色々な(?:効果|評判|感想)", text)
        page("numbered-affiliate-endorsement-with-repeated-title-slots-and-inflated-verdict",
             endorsement and text.count(endorsement[1]) >= 2
             and distinct(re.compile(r"一から情報を集め|予想に反して知らなきゃ損|とんでもなく注目されることが増え|"
                                     r"内容にお買い得感があるから|が問題解決の最良の手段だと納得|"
                                     r"諦める前にチャレンジしてみる価値"), text) >= 4
             and not re.search(r"(?m)^(?:参考文献|検証条件|比較表)", text))
    if 180 <= len(text) <= 1550 and re.fullmatch(r"/doc_[A-Za-z0-9]{24,48}", path):
        page("fabricated-baseball-report-repeats-unanswered-player-question",
             len(re.findall(r"(?:捕手|選手)は誰だったのでしょうか[?？]", text)) >= 2
             and bool(re.search(r"名前が明らかにされていませんでした|氏名は発表されていませんでした", text))
             and distinct(re.compile(r"強力な肩|非常に重要です|野球の試合では|報告します|活躍に注目です|"
                                     r"期待が高まります"), text) >= 4
             and not re.search(r"(?m)^(?:出典|引用元|取材|文・|記者|画像)[ :：]", text))
    if 150 <= len(text) <= 1050 and re.fullmatch(r"/[a-z0-9_-]{5,25}/?", path, re.I):
        page("personal-diary-with-unrelated-search-terms-inserted-in-names-and-lines",
             bool(re.search(r"東急\s*(?:アダルト|セックス)\s*ハンズ", text))
             and len(re.findall(r"(?:^|[、\s])(?:アナル\s*セックス|野外\s*セックス|アダルト動画)(?=$|[。\s])", text)) >= 2
             and distinct(re.compile(r"道に迷|山の上|ヒノキのまな板|親子レク|お肌もツルツル|川を挟"), text) >= 4)
    if 210 <= len(text) <= 680 and re.fullmatch(r"/[^/]{2,30}/[0-9]{3,7}/?", path):
        lines = text.splitlines()
        offer = re.match(r"([^\n]{8,100}?)\s+の(?:中身|激安|2ch|評価|口コミ|評判)", text, re.I)
        page("affiliate-opinion-with-reused-product-slots-and-generic-verdict",
             8 <= len(lines) <= 15 and bool(offer and lines[-1].startswith(offer[1]))
             and sum(bool(re.search(pattern, text)) for pattern in (
                 r"様々な話を(?:発見|調べ)|新しい話を見つけ|情報を調べてみました",
                 r"(?:話題|噂|注目度).{0,17}(?:聞きます|ということです|ように思えます)",
                 r"(?:考え方|感じ方|捉え方)は(?:人それぞれ|様々|色々)",
                 r"(?:答えを探し出す|情報を探す|色々探す|ネットで調べる)のは、.{0,12}(?:難し|苦労)",
                 r"(?:やらなきゃ損|試してみない理由が見当たらない|やらない理由を見つけられない|"
                 r"評価の理由|人気が高い理由|何故(?:注目|認め))",
             )) >= 4)
    if "質問タグ:" in text and "アンサー" in text:
        page("article-assembling-qa-threads-under-repeated-clipped-headings",
             len(re.findall(r"(?m)^(?:【[^】\n]{2,10}】)?([^\n]{15,110}(?:…|\.\.\.))\n\1$", text)) >= 4
             and len(re.findall(r"(?m)^アンサー(?:$|:)", text)) >= 3
             and len(re.findall(r"(?m)^質問タグ:[^\n]{5,120}$", text)) >= 4)
    if 280 <= len(text) <= 2200 and re.fullmatch(r"/blog-date-20\d{4}\.html", path):
        page("copied-archive-article-with-empty-fields-and-unrelated-affiliate-tail",
             bool(re.search(r"(?m)^・\s*null[ \t]*\n・\s*null[ \t]*\n", text[-450:]))
             and len(re.findall(r"(?m)^・\s*クレジットカード現金化[^\n]*$", text[-450:])) >= 2
             and bool(re.search(r"(?m)^・\s*(?:ネイルサロン|美容サロン|脱毛)[^\n]*$", text[-450:])))
    if 260 <= len(text) <= 1000 and re.fullmatch(r"/c/turismo-\d+/e/restaurante-[a-z0-9-]+/?", path):
        page("tourism-restaurant-slot-serving-an-unrelated-cosmetic-service-article",
             text.count("脱毛") >= 5
             and distinct(re.compile(r"美容方法|毛根を直接|自己処理|施術|ムダ毛|エステサロン|ヒゲ|髭"), text) >= 5
             and not re.search(r"飲食店|レストラン|料理|観光|旅行|地元|メニュー", text))
    if 150 <= len(text) <= 1000 and re.search(r"/\?m=video_detail(?:\*|%2[Aa])\d{4,10}(?:\*|%2[Aa])\d{1,3}(?:$|&)", url):
        codes = re.findall(r"(?mi)^(?:亚洲情色)?([a-z]{3,8})-?\d{3,6}(?:-|\s)", text)
        page("video-detail-slot-concatenating-different-catalogue-snippets",
             text.startswith("亚洲情色") and len(set(codes)) >= 5
             and len(text.splitlines()) <= 12 and "掲載元" not in text)
    if 260 <= len(text) <= 1450 and re.fullmatch(
            r"/(?:tokyo|fukuoka|osaka|kyoto|hyogo|aichi|miyagi|shiga|saitama|hokkaido|chiba|kanagawa|"
            r"hiroshima|okinawa|nagano|shizuoka|niigata|kumamoto|nagasaki|yamaguchi|okayama)\.html?", path):
        page("prefecture-page-with-fragmentary-and-mechanically-spaced-adult-prose",
             len(re.findall(r"(?<=[一-龯ぁ-ゖァ-ヺ]) +(?=[一-龯ぁ-ゖァ-ヺ])", text)) >= 18
             and len(re.findall(r"(?m)^(?:僕|タンス|とファック|オレ|すけべな|顔をしていた)\s*$", text)) >= 3
             and distinct(re.compile(r"ブルセラ|アドレナリンが出すぎ|飲みたいと思うオレ|携帯の番号にかけ|"
                                     r"つい最近オープンした銭湯|明後日の夜|ミルクココアを"), text.replace(" ", "")) >= 4)
    if 240 <= len(text) <= 1900 and re.fullmatch(r"/([a-z]{3,16})/\1_\d{1,3}/\d{3,7}hikkosi\.html", path):
        company = re.match(r"([^()\n]{4,50})\([一-龯]{3,24}\)の引っ越し費用見積もり", text)
        page("numbered-mover-directory-with-repeated-company-slots-and-advertising",
             company and text.count(company[1]) >= 6
             and text.count("引っ越し費用見積もりを安く抑えて賢く節約する方法") >= 2
             and distinct(re.compile(r"見積もりを一括比較|キャッシュバックがもらえる|\|住所よみがな\|\||"
                                     r"\|営業時間\|\s*\n\|休業日\|"), text) == 4)
    if 1600 <= len(text) <= 18000 and path.startswith("/keyword/"):
        page("long-keyword-montage-with-fiction-dialogue-and-detached-link-metadata",
             bool(re.match(r"はてなキーワード:\s*[^\n]{1,30}とは\n", text))
             and len(re.findall(r"(?m)^「[^」\n]{2,32}」$", text[:2300])) >= 16
             and text.count("||") >= 24
             and bool(re.search(r"(?m)^(リンク20\d{2}/\d{2}/\d{2})\n(?:\1\n){3,}", text))
             and not re.search(r"(?m)^(?:記事への反応|引用元|出典|投稿者)[ :：]|Permalink\s*\|", text))
        page("keyword-landing-combining-citation-dense-prose-and-unlabelled-game-snippets",
             bool(re.match(r"はてなキーワード:\s*[^\n]{1,30}とは\n", text))
             and len(re.findall(r"\[\d{1,3}\]", text)) >= 8
             and len(re.findall(r"(?m)^シード値\s*:\s*[-−]?\d{5,}", text)) >= 2
             and distinct(re.compile(r"気になった世界一|最[高長]齢|経済[産業]{1,2}省|エネルギー政策|"
                                     r"地中熱|人型になって走る|幼い頃から"), text) >= 4
             and not re.search(r"(?m)^(?:関連エントリー|関連記事|引用元|キーワードを含むブログ)", text))
    if 500 <= len(text) <= 8000 and path.startswith("/keyword/"):
        keyword_heading = re.match(r"はてなキーワード:\s*([^\n]{1,40})とは\n", text)
        labelled_sources = re.search(r"(?m)^(?:関連エントリー|関連記事|引用元|出典|投稿者|キーワードを含むブログ)"
                                     r"|Permalink\s*\|\s*記事への反応", text)
        page("keyword-landing-splicing-unattributed-posts-and-mid-sentence-replies",
             bool(keyword_heading) and not labelled_sources
             and len(re.findall(r"(?m)^.{180,}$", text)) >= 3
             and len(re.findall(r"(?m)^(?:[一-龯ぁ-ゖ]{2,14}(?:けれど|が|だが)、|[>＞][^\n]{4,50})$", text)) >= 3
             and bool(re.search(r"(?m)^(?:[a-z][a-z0-9_]{3,20}です。|拝見していていくつか)", text)))
        if keyword_heading and not labelled_sources and host == "anond.hatelabo.jp":
            body = text[keyword_heading.end():]
            page("keyword-montage-of-detached-bullet-lists-and-reply-continuations",
                 len(re.findall(r"(?m)^・[^\n]{4,55}$", body[:220])) >= 5
                 and bool(re.search(r"(?m)^={3,}$", body[:220]))
                 and len(re.findall(r"(?m)^.{140,}$", body)) >= 2
                 and bool(re.search(r"(?m)^に対する再反応$", body))
                 and len(re.findall(r"(?m)^(?:という考えがあります。|理由としては、|というわけで、|いかがでしょう\?|続く|[（(]続く)$", body)) >= 3
                 and not re.search(r"https?://|発信者:|投稿日時:", body))
            page("keyword-montage-with-repeated-timed-fragment-and-detached-essay",
                 len(re.findall(r"(?m)^.{2,25}$", body[:260])) >= 8
                 and bool(re.search(r"(?m)^([^\n]{4,40}![^\n]{1,12})\n(\d{1,3}分後、)\n\1\n\2$", body[:320]))
                 and len(re.findall(r"(?m)^.{155,}$", body)) >= 2
                 and bool(re.search(r"(?m)^↓\n↓\n", body))
                 and not re.search(r"https?://|発信者:|投稿日時:", body))
            page("keyword-landing-with-foreign-topic-intro-and-a-single-cited-fiction-fragment",
                 1600 <= len(body) <= 6800
                 and len(re.findall(r"(?m)^「[^\n」]{6,100}」$", body)) >= 15
                 and len(re.findall(r"(?m)^https?://anond\.hatelabo\.jp/\d{14}$", body[-340:])) == 1
                 and distinct(re.compile(r"給与明細|労働基準法|省力化|ストレージ|過払い"), body[:1000]) >= 4
                 and distinct(re.compile(r"第二次オイルショック|山陽百貨店|トイレットペーパー|神姫バス|"
                                         r"ドラえもん.{1,24}参戦"), body[700:]) >= 4)
            recycled_signoff = "すいすいすいようび~\n今日も頑張りましょう!"
            page("keyword-landing-recycling-an-unattributed-signoff-across-digests",
                 len(re.findall(r"(?m)^.{3,60}$", body)) >= 22 and "\nうふふ。\n" in body
                 and (body.rstrip().endswith(recycled_signoff) or body.count(recycled_signoff) >= 3))
            page("keyword-landing-with-detached-search-excerpts-missing-the-keyword",
                 keyword_heading[1] not in body and len(body.splitlines()) >= 12
                 and len(re.findall(r"[。！？!?]", body)) >= 5)
            paragraphs = [len(line) >= 166 for line in body.splitlines() if len(line) <= 57 or len(line) >= 166]
            long_count = sum(paragraphs)
            if (long_count >= 3 and len(paragraphs) - long_count >= 15 and len(paragraphs) >= 30
                    and sum(a != b for a, b in pairwise(paragraphs)) >= 5 and "http" not in text):
                width = (len(text) + 4) // 5
                grams = [set(re.findall(r"(?=([一-龯ぁ-ゖァ-ヺー]{4}))", text[i:i + width]))
                         for i in range(0, len(text), width)]
                page("keyword-landing-mixing-uncredited-short-replies-and-disconnected-long-posts",
                     sum(50 * len(a & b) <= min(len(a), len(b)) for a, b in combinations(grams, 2)) >= 6)
    if 1000 <= len(text) <= 9500 and re.fullmatch(r"/promo/(?:[a-z0-9-]+\.)+[a-z]{2,12}/?", path):
        coupon_language = distinct(re.compile(r"お得情報をゲット|まで有効|クーポンコード|ショップ|値下げ|期間限定"), text)
        page("merchant-coupon-pages-with-mechanically-substituted-promotions-and-checkout-copy",
             coupon_language >= 5 and text.count("クーポン") >= 13
             and (distinct(re.compile(r"気軽く了解|割引が受けられるという保証が付きません|"
                                         r"からのを買える|入力する時一文字が多くなった場合が多い"), text) >= 3
                  or len(re.findall(r"毎日の節約を得て|チェックアウトでオンライン買い物するとき|"
                                     r"クリックしてリストを確認し、[^。\n]{2,36}で節約できます", text)) >= 6))
    if 190 <= len(text) <= 950:
        page("slot-filled-affiliate-endorsement-with-rotating-urgency-line",
             bool(re.match(r"[^\n]{7,70}(?:における|についての)[^\n]{1,20}(?:感想|評価|体験談|レビュー|"
                           r"クチコミ)[^\n]{3,40}[♪！。]\n", text))
             and bool(re.search(r"(?m)^【大事】\s*(?:こちらで[、,]?.{0,12}見る|期間限定[、,]?.{0,12}提供|"
                                r"特典付きで購入|こんな方は失敗する確率)", text))
             and distinct(re.compile(r"想像以上に大変でした|何故認められている|体験者に感謝され|総評として"
                                     r"|ストレートな評価として|全体を通した感触|人気の秘密のひとつ"
                                     r"|理由が思い当たらない|意外に厳しかった|中身も間違いはない|正直な見識|"
                                     r"勝手な見識|専門的な内容が期待以上|から感謝されていることに疑い|"
                                     r"注目されている理由は、期待以上|○{2,}を□{2,}"), text) >= 3
             and not re.search(r"(?m)^(?:参考文献|比較表|検証条件|手順[：:])", text))
    if 230 <= len(text) <= 1550 and re.search(r"/\d{4,7}/index\.html?$", path):
        page("broken-localized-catalogue-description-followed-by-detached-comment-spam",
             "コメント:" in text
             and distinct(re.compile(r"よい用語にいる|汚さの時のそれ数|子供に耐えないボディ|"
                                     r"生ビールに最も良い中間の株|D['’]Urbervilles|システムとミルク|"
                                     r"少しほとんどの在庫"), text) >= 4)
    if 180 <= len(text) <= 850 and re.fullmatch(r"/[a-z]{3,24}/\d{3,9}/?", path):
        page("city-field-inserted-into-corrupted-pseudo-diary",
             bool(re.search(r"(?m)^[一-龯]{2,6}は\d{1,2}:\d{2}に帰宅しました$", text))
             and distinct(re.compile(r"いたずらなことをたくさん書いて|起きることができるとは思わない|"
                                     r"明日は世界です|それは去る儀式|今日は最後の\d時間|"
                                     r"包装しています(?:…|\.{3})包装しています"), text) >= 4)
    if 440 <= len(text) <= 4500 and "緯度/経度" in text:
        page("station-metadata-mixed-with-rotating-kindergarten-recruitment-queries",
             len(set(re.findall(r"保育(?:士|園|のお仕事)[^!\n、。]{0,15}情報!([^!\n]{1,17}駅)周辺!", text))) >= 4
             and distinct(re.compile(r"駅名\(ひらがな\)|鉄道名\(ひらがな\)|路線名\(ひらがな\)|"
                                     r"運営会社名\(ひらがな\)"), text) >= 3
             and "検索すると" in text and "ご訪問有難うございます" in text)
    if 450 <= len(text) <= 9000 and path == "/search":
        search_results = re.findall(r"(?m)^- .{6,140}$", text)
        joined_domains = set(re.findall(r"(?:\.{3}|。)([a-z0-9][-a-z0-9.]+\.[a-z]{2,8})(?:[/ >]|$)", text, re.I))
        page("search-feed-entirely-assembled-from-clipped-query-results",
             len(search_results) >= 6 and len(joined_domains) >= 5
             and dict(item.split("=", 1) for item in address.query.split("&") if "=" in item).get("fr") == "rss_krank"
             and not re.search(r"(?m)^(?:執筆|検索結果の考察|調査の目的|本記事)", text))
    if 550 <= len(text) <= 6500 and re.fullmatch(r"/\d{5,8}/?", path):
        questions = re.findall(r"(?m)^([^\n?]{5,56}\?)$", text)
        page("numeric-faq-page-assembled-from-unattributed-search-snippets",
             len(set(questions)) >= 8
             and (len(re.findall(r"(?m)^キャッシュ$", text)) >= 2
                  or len(re.findall(r"(?m)^引用[元:]?\s+https?://", text)) >= 5)
             and (max(Counter(line for line in text.splitlines() if len(line) >= 20 and line.endswith("。")).values(), default=0) >= 2
                  or len(re.findall(r"(?m)^[|]\s*[一-龯ぁ-ゖ]{2,12}\s*[|]", text)) >= 2)
             and not re.search(r"(?m)^(?:執筆|監修|運営について|よくあるお問い合わせの一覧)[\s:：]", text))
    if 650 <= len(text) <= 6500 and re.fullmatch(r"/\d{5,8}/?", path):
        questions = re.findall(r"(?m)^([^\n?]{5,85}\?)$", text)
        question_forms = re.compile(r"意味(?:は|ですか)\?|何詞\?|(?:なんと|どう|何て)読む\?|使い方は\?|違いは何ですか\?")
        page("keyword-faq-with-search-cache-controls-and-shifting-query-headings",
             len(set(questions)) >= 12 and distinct(question_forms, "\n".join(questions)) >= 5
             and len(re.findall(r"(?m)^キャッシュ$", text)) >= 3
             and not re.search(r"(?m)^(?:執筆|監修|回答者|出典|質問者|目次|著者)[\s:：]", text))
    if 650 <= len(text) <= 8000 and text.count("AV女優の") >= 5 and text.count("「「") >= 3:
        lines = [line for line in text.splitlines() if line.strip()]
        if (len(lines) >= 12
                and sum(line.startswith("AV女優の") for line in lines) >= 5
                and any("検索" in line and "?" in line and len(line) >= 75 for line in lines)):
            fragments = Counter(line[i:i + 24] for line in lines for i in range(len(line) - 23))
            page("affiliate-title-collage-with-search-keywords-and-recycled-sentence-fragments",
                 sum(count > 1 for count in fragments.values()) >= 18)
    if 1000 <= len(text) <= 8000 and re.fullmatch(r"/\d{5,8}/?", path) and "\nキャッシュ\n" in text:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        headings = [i for i, line in enumerate(lines) if 5 <= len(line) <= 90 and line.endswith("?")]
        page("numeric-landing-of-alternating-search-questions-and-cache-snippets",
             17 <= len(headings) <= 35 and headings[0] == 0 and 1 <= len(lines) - 1 - headings[-1] <= 4
             and sum(right - left >= 2 for left, right in pairwise(headings)) >= .8 * (len(headings) - 1)
             and not re.search(r"(?m)^(?:執筆|監修|回答者|出典|質問者|著者)[\s:：]", text))
    if 700 <= len(text) <= 4200 and "-info/" in path and "{stars}" in text:
        page("sightseeing-landing-filled-with-unexpanded-hotel-copy",
             text.count("n.a.") >= 2 and "周辺ホテル" in text
             and (text.count("街の中心まで") >= 3 or text.count("絶好のロケーション") >= 2)
             and bool(re.search(r"[ァ-ヺー]{3,}続きを読む[ァ-ヺー]{2,}", text)))
    if 230 <= len(text) <= 900 and path.endswith(".html"):
        page("local-nursing-recruitment-with-address-slots-and-no-position",
             bool(re.fullmatch(r"/([a-z]+)_([a-z]+)/\2_(\d+)_(?:\1)/\2_\3_\d+\.html", path))
             and distinct(re.compile(r"ご案内\|\|あなたがお住まいの住所情報|郵便番号\|\|〒|住所\(ひらがな\)|"
                                     r"お問い合わせ・ご登録はこちらから|直接聞きにくいことは全て代理交渉"), text) >= 4
             and bool(re.search(r"(?m)^[^\n]{4,34}の看護師さん(?:急募|求人|募集)", head))
             and "求人募集情報を検索中" in text)
    if 180 <= len(text) <= 4500 and path.endswith(".php") and len(re.findall(r"[A-Z][A-Z0-9-]{3,11}\d", text)) >= 2:
        page("catalogue-model-codes-spliced-into-the-middle-of-advice",
             bool(re.search(r"(?:過ごして|歩いて|楽しんで|考えて|向かって|見ていて)[^。!?\n]{0,12}"
                            r"[ァ-ヺ]{3,}\s*(?:トナーカートリッジ|電源アダプター|工具セット|純正インク)"
                            r"[^。!?\n]{0,55}[A-Z][A-Z0-9-]{3,11}\d(?: \d+個)?"
                            r"(?:と、|や、)[^。!?\n]{0,55}[A-Z][A-Z0-9-]{3,11}\d[^\n。!?]{0,12}"
                            r"(?:が目に見えて|に気づ|が変わ|を意識)", text))
             and not re.search(r"部品一覧|対応機種|商品仕様|おすすめ商品|取扱説明書", head))
    if 180 <= len(text) <= 12500 and re.fullmatch(r"(?:/wander)?/wander\.php", path):
        catalogue = re.compile(r"新品|中古|未開封|送料|正規品|定価|限定|様専用|完売|最終値下げ|税込|まとめ売り|"
                               r"日本未入荷|購入|商品番号|品番|DEADSTOCK|プリントTシャツ白size|"
                               r"(?:^|\s)[A-Z]{2,}[0-9-]{2,6}|[A-Z0-9]{5,12}\d|"
                               r"\d+\s*(?:cm|mm|mL|ml|ML|円|個)(?![ぁ-ゖ])")
        page("opaque-wandering-query-with-catalogue-items-inside-article-prose",
             bool(re.fullmatch(r"(?=.{20,80}$)(?=.*[a-z])(?=.*[0-9]{3})[A-Za-z0-9/-]+\.htm", address.query))
             and text.count("。") >= 4 and distinct(catalogue, text) >= 3)
    if (450 <= len(text) <= 4200 and re.fullmatch(r"/[a-z]{5,34}/?", path)
            and "RT:" in text and "https://t.co/" in head):
        numbered = re.findall(r"(?m)^RT: \d{1,2}/\d{1,2}(?: \d{1,2}:\d\d(?:頃)?[~〜]?)? ([A-Za-z][A-Za-z0-9 -]{4,32}?)(\d{1,2}) ", text)
        for label, count in Counter(label for label, _ in numbered).items():
            sequence = [int(num) for source, num in numbered if source == label]
            if count >= 7 and all(left - right == 1 for left, right in pairwise(sequence)):
                page("opaque-keyword-page-with-retweet-chain-and-unrelated-sale-card",
                     bool(re.search(r"(?mi)^.{0,20}(?:セール|値引き|プレセール).{0,90}"
                                    r"(?:(?:MAX\s*)?\d+%OFF|キャンペーン).{0,100}https://t\.co/", head))
                     and not re.search(r"(?m)^(?:出典|執筆|文[:：]|引用元|発言者|まとめ主)", head))
                break
    if (900 <= len(text) <= 6500 and re.fullmatch(r"/20\d{2}/\d{2}/\d{2}/[^/]+-\d{1,3}/?", path)
            and "カイロ" in path and "カイロプラクティック" in text):
        lines = text.splitlines()
        page("clinic-article-preceded-by-unrelated-video-title-collage",
             len(lines) >= 22
             and sum(bool(re.search(r"(?m)^【|[!?]{1,2}$|w{3,}|切り抜き|ゆっくり解説|コピペ|Part[.,]\d", line))
                     for line in lines[:15]) >= 6
             and distinct(re.compile(r"矯正|ぎっくり腰|側弯症|側彎症|椎間板|パーマー|脊椎指圧療法"), text[400:]) >= 4
             and len(re.findall(r"カイロプラクティック(?:\([^)\n]{2,20}\)|\s*「Chiropractic」)?[」 ]*(?:は|とは)", text[400:])) >= 3
             and not re.search(r"(?m)^(?:関連記事|ニュース一覧|他の動画|おすすめ動画|引用元|出典[:：])", head))
    if 350 <= len(text) <= 3500 and re.fullmatch(r"/[a-z]{4,20}(?:ken|fu|to|do)/[a-z]{3,28}(?:shi|cho|machi|mura|son|ku)/?", path):
        page("municipality-loan-landing-with-repeated-cta-and-spun-contract-copy",
             text.count("アコム自動契約機") >= 3 and text.count("アコムのお申込みはこちら") >= 2
             and distinct(re.compile(r"不審な足運び|カモフラージュの中身|お世辞なしで融資|お住いだったり氏名|"
                                     r"逐次監視を実践|審査ともいえる早さ|虚偽のお申し込みに触れいない"), text) >= 3)
    if 460 <= len(text) <= 4800 and re.fullmatch(r"/(?:av|video)/view/\d{4,7}\.html?", path):
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        page("catalogue-video-entry-with-empty-publication-fields-and-mismatched-related-blurbs",
             len(lines) >= 6 and lines[1:3] == ["公開:", "公開:"]
             and bool(re.search(r"関連(?:するAV作品|タグ、AV作品).{0,46}(?:ご紹介|紹介します)", "\n".join(lines[3:5])))
             and sum(len(line) >= 120 and line.count("。") >= 2 for line in lines[4:]) >= 3
             and not re.search(r"(?m)^(?:作品のあらすじ|本作の説明|一覧に戻る|作品について|購入情報)[\s:：]", text))
    if 400 <= len(text) <= 1550 and re.fullmatch(r"/(?:archives|entry)/\d{2,7}/?", path):
        page("affiliate-skeptical-testimonial-under-repeated-product-name",
             bool(re.search(r"(?m)^([^\n]{12,112})を買ってみた\s+検証\s*\([^)\n]{2,24}\)\s*$", head))
             and "本当の効果が知りたくて" in text and "こういう口コミもあったよ" in text
             and bool(re.search(r"本当のところどうなんだろうね[?？]?\s*インチキってことはないとは思うけど", text))
             and sum(line.startswith("「") for line in text.splitlines()) >= 2
             and bool(re.search(r"悪くないかもって気がするよね[。]?$", text)))
    if 600 <= len(text) <= 2600 and re.fullmatch(r"/(?:[a-z0-9_-]+/)?20\d{2}/\d{2}/\d{2}/[^/]+-\d{1,3}/?", path):
        page("dated-clinic-rewrite-with-garbled-back-pain-treatment-outline",
             "急性腰痛症" in head and "NSAIDs" in text
             and distinct(re.compile(r"腰部の疾患発病|の所苦痛|病状ば減少する|予後が好く椎間板|"
                                     r"だがしかしその中には|視察で異常が見当らない|疾病のケースでは安静時"), text) >= 4
             and distinct(re.compile(r"腰椎関節|疼痛|外科疾患|内臓疾患|椎間板|関節の捻挫|圧迫骨折"), text) >= 4)
        page("dated-manual-therapy-definition-with-reused-phrasing-and-keyword-tail",
             text.startswith("整体\n整体") and "民間療法、代替医療" in head and "大正時代" in head
             and distinct(re.compile(r"手技が治療の中心|着手方法の方法|背中の疼痛|"
                                     r"保険治病|代替医療を示す言葉|論理・術共に統一されていない"), text) >= 4
             and len(re.findall(r"(?m)^.{1,30}カイロプラクティック[・/]整体の", text[-500:])) >= 3)
    if 650 <= len(text) <= 4200 and re.fullmatch(r"/area/[a-z]{4,20}/[a-z]{3,28}/?", path):
        municipality = re.match(r"([一-龯ぁ-ゖ]{2,14}[市町村区])で車の鍵紛失、修理なら", head)
        page("vehicle-locksmith-municipality-slots-with-reused-geography-padding",
             bool(municipality) and text.count(municipality[1]) >= 7
             and distinct(re.compile(r"車の鍵紛失、修理対応地域|車の鍵紛失、修理対象地域|"
                                     r"作業車に各種機材の常備|工事保障させて頂|年間3万件以上の出動実績|"
                                     r"特殊機材で緊急対応|難易度が高く他社に断られた内容も対応"), text) >= 3
             and bool(re.search(r"(?m)^ご存知でしたか\?", text)))
    if 1400 <= len(text) <= 14000 and re.fullmatch(r"/error-while-parsing-data-\d{4,7}/?", path, re.I):
        lines = text.splitlines()
        page("parser-error-slug-with-duplicated-harvested-press-release",
             len(lines) >= 18 and 24 <= len(lines[0]) <= 145 and lines[0] == lines[1]
             and distinct(re.compile(r"公式パートナー|公式会場パートナー|授賞式|冠スポンサー|"
                                     r"最優秀賞|投票プロセス|メディア情報|プレスリリース"), text) >= 4
             and not re.search(r"(?m)^(?:提供元|記事提供|発表元|執筆|編集|出典|転載許可)[\s:：]", text))
    if 1150 <= len(text) <= 9500 and path.lower() == "/form/product/productdetail.aspx":
        args = address.query.split("&")
        page("product-detail-slots-filled-with-an-unrelated-travel-feature",
             {arg.split("=", 1)[0] for arg in args} >= {"pid", "cat", "vid", "shop"}
             and sum(bool(re.fullmatch(r"(?:pid|cat|shop)=[0-9]{1,12}", arg)) for arg in args) >= 3
             and distinct(re.compile(r"街並み|文化の担い手|路上|スラム街|街角|運河|路地|市場|"
                                     r"屋根裏|アーティストたち|ミュージシャン|部屋の間取り図"), text) >= 6
             and not re.search(r"商品詳細|販売価格|カートに入れる|商品番号|在庫状況|送付先|商品仕様|"
                               r"お問い合わせ|取材[・/／]文|執筆[:：]|文[=:：＝]", text))
    if 490 <= len(text) <= 3500 and re.fullmatch(r"/\d{3,7}\.html?", path):
        lines = text.splitlines()
        page("numbered-post-inserting-identical-headline-between-scraped-social-blocks",
             12 <= len(lines) <= 48 and 8 <= len(lines[0]) <= 45 and lines.count(lines[0]) >= 4
             and len(re.findall(r"(?m)^— .{1,40}\(@[A-Za-z0-9_]{2,20}\) 20\d{2}年", text)) >= 2
             and len(re.findall(r"pic\.twitter\.com/[A-Za-z0-9]{6,14}", text)) >= 2
             and bool(re.search(r"(?:t\.co|pic\.twitter\.com)/[A-Za-z0-9]{6,14}スポンサーリンク", text))
             and not re.search(r"(?m)^(?:編集|執筆|関連ツイート|読者の反応|投稿者[:：])", head))
    if 600 <= len(text) <= 9500 and re.fullmatch(r"/articles/(?:-|amp|gallery)/\d{5}/?", path):
        page("copied-automotive-article-with-replaced-publisher-credit",
             bool(re.search(r"(?m)^\(Clubpyme\)$", text))
             and text.count("|拡大|") >= 2
             and len(re.findall(r"(?:20\d{2}\.\d{1,2}\.\d{1,2})\s*(?:自動車ニュース|試乗記|デイリーコラム)", text)) >= 3)
    if 600 <= len(text) <= 15000 and re.fullmatch(r"/(?:qa|qanda|question)\.php", path, re.I):
        page("copied-question-results-with-repeated-category-and-timestamp-wrapper",
             bool(re.match(r"Yahoo!?知恵袋(?:\n|\s*$)", text))
             and len(re.findall(r"(?m)^- 投稿日時(?:\n| )- [A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} 20\d{2} \d{2}:\d{2}:\d{2}$", text)) >= 4
             and len(re.findall(r"(?m)^詳しくはこちら$", text)) >= 4
             and len(set(re.findall(r"(?m)^([^\n>]{2,25}) > [^\n]{2,85}$", text))) >= 3)
    if 350 <= len(text) <= 3900 and re.fullmatch(r"/20\d{2}/\d{2}/\d{2}/(?:post|article)-\d{2,6}/?", path):
        page("dated-post-filled-with-unattributed-clipped-related-story-summaries",
             len(re.findall(r"(?m)^.{4,120}(?:\.\.\.|…+|・・・)\s*$", text)) >= 5
             and bool(re.search(r"(?m)^スポンサーリンク$", head))
             and bool(re.search(r"(?m)^(?:記事を読む|詳細は次ページで)$", text))
             and sum(distinct(pattern, text) >= 2 for pattern in (
                 re.compile(r"監査法人|給与明細|会社の規則|取引先|法人税|名簿に登録"),
                 re.compile(r"キャスター|ワールドカップ|アナウンサー|ネイマール|報道ステーション|試合中"),
                 re.compile(r"元カノ|旦那|夫の|義兄|義母|いとこ|従弟|結婚祝い"),
             )) >= 3
             and not re.search(r"(?m)^(?:関連記事|関連投稿|todayのニュース|記事一覧|出典[:：]|著者[:：])", text))
    if 145 <= len(text) <= 460 and re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?", path):
        page("dormant-blog-with-only-a-scraped-affiliate-product-card",
             bool(re.match(r"この広告は、90日以上更新していないブログに表示しています。\n", text))
             and bool(re.search(r"(?m)^[^\n]{35,180}詳しくはこちら b y 楽 天$", text))
             and bool(re.search(r"【\d{1,3}P\d{1,2}[A-Za-z]{3}\d{2}】|"
                                r"(?m:^[【\[][^\n]{12,150}(?:詳しくはこちら b y 楽 天)$)", text))
             and "引用をストックしました" in text and text.endswith("限定公開記事のため引用できません。")
             and len(text.splitlines()) <= 7)
    if 850 <= len(text) <= 5500 and re.fullmatch(r"/[a-z]{4,24}/\d{2,7}/?", path):
        staffing = re.findall(r"(?m)^([^\n]{6,60}?求人) (紹介|登録無料|紹介手数料無し|仲介料金無し)\b", text)
        page("rotating-city-and-qualification-slots-in-night-work-recruitment",
             max(Counter(heading for heading, _ in staffing).values(), default=0) >= 3
             and len({call for _, call in staffing}) >= 3
             and distinct(re.compile(r"テレフォンレディ|チャットガール|チャトレ|メールレディ|"
                                     r"セクシーパブ|ガールズバー|カウンターレディ|コンパニオン"), text) >= 5
             and len(re.findall(r"(?m)^- [^\n]{4,65}求人$", text)) >= 8)
        introduction = re.match(r"([^\n\s]{1,13}) ([^\n]{2,35}?求人) 紹介\n", head)
        if introduction:
            location, offer = introduction.groups()
            heading = re.escape(f"{location} {offer}")
            page("rotating-night-work-locality-slots-without-individual-job-listings",
                 len(re.findall(rf"(?m)^{heading} (?:スマホで探せる!|メリット|デメリット|登録入口)$", text)) >= 3
                 and text.count(location + "の") >= 9
                 and distinct(re.compile(r"フロアレディ|カウンターレディ|セクシーパブ|ガールズバー|"
                                         r"キャバクラ|ナイトワーク|コンパニオン|ニュークラブ|チャットレディ"), text) >= 4
                 and not re.search(r"(?m)^(?:店舗名|勤務先|勤務地|雇用形態|勤務時間|待遇)[\s:：|]", text))
    if 1100 <= len(text) <= 22000 and re.fullmatch(r"/text/20\d{12}\.html?", path):
        timestamp_lines = re.findall(r"(?m)^\d{1,5} [^\n]{4,85}\d{2}/\d{2}/\d{2}[^\n]{1,15}\d{2}:\d{2}[^\n]*$", text)
        corrupted_metadata = re.compile(r"名[一-龯ぁ-ゖ]前[一-龯]?[ :]|前[一-龯]:|投[一-龯]稿[一-龯]?日|"
                                        r"投稿[一-龯]日[一-龯]?:|投稿日:[一-龯]\s|"
                                        r"\d{2}/\d{2}/\d{2}\([月火水木金土日][一-龯]\)")
        page("forum-montage-with-machine-inserted-characters-in-timestamps-and-handles",
             len(timestamp_lines) >= 8 and sum(bool(corrupted_metadata.search(line)) for line in timestamp_lines) >= 2)
    if 180 <= len(text) <= 2400 and re.fullmatch(r"/detail/\d{4,8}\.html?", path):
        page("storefront-collage-with-reused-sales-blurb-and-broken-localized-appliance-copy",
             distinct(re.compile(r"クッキングセンターには|各メーカーの IHクッキングヒーター|電気工事不要|"
                                     r"電源をつながればすぐ使える|掃除簡単に加えて"), text[:220]) >= 4
             and distinct(re.compile(r"爱动|多机能|渍け|茶炉|锅|京东|范囲|强すぎ|Kuc king|Kucking|いろいろな机能"), text[120:]) >= 4)
    if 240 <= len(text) <= 1250 and re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/[^/]+_[^/]+/?", path):
        page("underscore-query-post-with-unrelated-supplement-industry-fragments",
             not re.search(r"(?m)^出典|資料出所|以下引用|参考文献", text)
             and distinct(re.compile(r"産鉄分販売価格|サプリメント先進国|母子手帳に葉酸|"
                                     r"痛風協力医療機関|卸売販売・小売販売|健康食品・機器などは|"
                                     r"ブルーベリーだけにこだわらず|規制緩和はタイムテーブル"), text) >= 5
             and distinct(re.compile(r"あるといわれる。葉酸を体内|体内に摂取することで[^。\n]{9,35}育成を目指す|"
                                     r"(?:^|。)のサプリメント|摂取したら化粧品の通信販売|"
                                     r"はこれに対して健康食品"), text) >= 2)
    if 400 <= len(text) <= 5000 and re.search(r"/details/[^/]+/?$", path):
        catalogue_tail = text.rsplit("★", 1)[-1]
        page("catalogue-stitched-from-recurring-widgets-and-detached-garbled-copy",
             max(Counter(re.findall(r"★\s*もっと([^★\n]{3,28})を見る\s*★", text)).values(), default=0) >= 2
             and bool(re.search(r"\.\.\.★[^★\n]{5,40}★[^\n]{12,100}つぶやき[^\n]{4,60}\[DL版\]", text))
             and sum(line.endswith("。") for line in catalogue_tail.splitlines()) >= 5
             and max(Counter(re.findall(r"(?=([一-龯ぁ-ゖァ-ヺA-Za-z]{18}))", catalogue_tail)).values(), default=0) >= 2)
    if 140 <= len(text) <= 1000 and re.fullmatch(r"/archives/\d{3,9}/(?:キャプチャ|スクリーンショット)(?:-\d{1,3})?/?", path):
        page("orphan-image-capture-with-unlabelled-merged-headlines",
             bool(re.match(r"(?:キャプチャ|スクリーンショット)\n\(Visited \d+ times?, \d+ visits? today\)", text))
             and len(re.findall(r"(?m)^『[^\n]{6,100}(?:…|\.\.\.).{6,90}$", text)) >= 3
             and distinct(re.compile(r"炎上|判明|海外の反応|Facebook|2ch|を特定|の顔画像"), text) >= 4
             and "All rights reserved" in text)
    if 170 <= len(text) <= 1000 and re.fullmatch(r"/[a-z]{4,22}/\d{2,6}[a-z]{2,9}\d{7,16}\.html?", path):
        page("jewelry-product-specifications-joined-to-care-facility-prose",
             distinct(re.compile(r"スターリングシルバー|925刻印|ペンダントボックス|クラフトマンシップ|"
                                     r"メダル\s*\("), text[:260]) >= 4
             and distinct(re.compile(r"生活支援|生きがいづくり|暮らしぶりに合わせ|春の大運動会|"
                                     r"競技を考案|仲間づくりの場"), text[90:]) >= 4
             and not re.search(r"(?m)^(?:寄付|チャリティー|協賛|協力団体|お客様の声)[ :：]", text))
    if 1100 <= len(text) <= 5200 and re.fullmatch(r"/20\d{2}/\d{1,2}/?", path):
        page("monthly-diary-with-rewritten-paragraphs-and-supplement-bridges",
             distinct(re.compile(r"クリームを食べ|乳房の中に溶か|気が付いたら\dスパン|お蕎麦の配置|"
                                     r"スペシャルバスへ設置|真昼のスパン|建物今しがた|悠々する時間"), text) >= 4
             and distinct(re.compile(r"善玉菌のチカラの使用体験談|リリィジュについて|うるリノレンが欲しい|"
                                     r"黒酢の使用体験談|育毛剤について"), text) >= 2)
    if 280 <= len(text) <= 2400 and re.fullmatch(r"/category/[a-z][a-z0-9_-]{2,32}/?", path):
        lengths = Counter(map(len, text.splitlines()))
        page("category-page-made-of-identically-clipped-unattributed-news-leads",
             sum(n for width, n in lengths.items() if 30 <= width <= 85 and n >= 7) >= 8
             and sum(s.endswith(("。", "」", "…", "！", "？", "です")) for s in text.splitlines()) <= 3
             and distinct(re.compile(r"国会|首相|大統領|政府|国際機関|公開した|会談|グループ|自治体"), text) >= 5
             and not re.search(r"(?m)^(?:[>|\-•]|©|(?:出典|出所|著者|配信元)[ :：])", text))
    if 1450 <= len(text) <= 7600 and len(path.split("/")) <= 3:
        page("baseball-report-with-auto-filled-ecommerce-call-to-action",
             distinct(re.compile(r"甲子園|タイムリー|ホームラン|スタジアム|初回|スコアボード|投手"), text) >= 6
             and bool(re.search(r"(?m)^(?:安打|犠打|得点|外野フライ)(?:を)?通販で[^\n]{2,30}$", text))
             and bool(re.search(r"(?m)^先発メンバー\n(?:\d [一-龯] .{2,15}\n){4,}", text)))
    if 220 <= len(text) <= 1050 and re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?", path):
        page("pseudo-diary-with-search-term-and-recycled-quotation-footer",
             bool(re.search(r"(?m)^【今日の名言】.{7,100}$", text))
             and bool(re.search(r"(?:では|今日は).{0,35}この辺で[!！。].{0,22}(?:失礼|おいとま)", text))
             and distinct(re.compile(r"ご機嫌いかが|いかがお過ごし|お元気でしょうか|話があっちこっち|"
                                     r"言いたいことがありすぎ|会社の先生達の間でも|の間でも話題|周りで人気|"
                                     r"世間で話題|すでに調査済み|あとでググってみます"), text) >= 3
             and distinct(re.compile(r"おいどん|拙者|ぼくちん|あたい|Meは|俺は|私の|わたし"), text) >= 1)
    if 620 <= len(text) <= 2100 and re.search(r"/【[^/]*(?:浮気|離婚)[^/]*】", path):
        page("reordered-affiliate-script-with-rotating-detective-solicitation-fields",
             distinct(re.compile(r"いまの境遇と抱えてる悩み|こんなふうに生活がガラッと変わりました|"
                                     r"でも、いまいちなところもあるんじゃないの|やはり、良いところがあるんです|"
                                     r"最後にこのサービスの特徴をまとめると"), text) >= 5
             and "協会公認の探偵社を紹介してもらえる安心感がメリット" in text
             and len(re.findall(r"(?m)^・(?=.+)", text)) >= 16)
    if 600 <= len(text) <= 3800 and len(re.findall(r"(?m)^・[^\n]{5,140}$", text)) >= 16:
        page("recycled-advantages-and-disadvantages-script-with-broken-product-fields",
             distinct(re.compile(r"(?m)^いまの状況と抱えてる不満や悩み|^こんなふうに生活がガラッと変わ"
                                     r"|^でも、(?:イマイチ|いまいち)なところもあるんじゃないの"
                                     r"|^やはり、良いところがあるんです|^最後にこの商品の特徴をまとめると"), text) >= 4
             and bool(re.search(r"(?m)^→[^\n]{6,100}公式サイトはこちら$", text))
             and bool(re.search(r"(?m)^・[^\n]{3,35}(?:登録すると|選ぶと|お申し込みは)$|"
                                r"スキップ、球界、解約", text)))
    if 250 <= len(text) <= 1700 and re.fullmatch(r"/[a-z]{5,24}/page\d{1,6}\.html?", path):
        page("commercial-query-assembled-from-incompatible-product-review-fragments",
             bool(re.match(r"[^\n]{0,14}「[^\n」]{2,35}」(?:の|を)[^\n]{5,65}\n", text))
             and distinct(re.compile(r"死着|ノンパンクタイヤ|鞘と刃|ラティス|ミズノだけ|サクサクとして"), text) >= 5
             and len(re.findall(r"。", text)) >= 9 and len(text.splitlines()) <= 7
             and not re.search(r"(?m)^(?:関連商品|それぞれのレビュー|レビュー一覧|色違い|商品タイトル)[ :：]?", text))
    if 650 <= len(text) <= 3800 and (host.startswith("ja.") or path.startswith("/ja/")):
        page("localized-health-advice-with-broken-headings-and-inline-widgets",
             distinct(re.compile(r"スニファーの横に|自然風邪は風邪に|風邪の治療法が地平線上|"
                                 r"免疫力が低下している人システム|肺疾患を持つシステム|ウイルスを拾う"), text) >= 4
             and distinct(re.compile(r"すべて見る|\d分|\d\s+の\s*\d|フェイスマスク|手すり"), text) >= 4)
    if 170 <= len(text) <= 700 and re.fullmatch(r"/articles/[a-f0-9]{32}/?", path):
        page("disclosed-automatic-news-extract-with-clipped-source-join",
             text.startswith("From ") and "下記のテキストは自動要約によってまとめられました" in head
             and bool(re.search(r"(?m)^出典\s*:", text))
             and bool(re.search(r"(?m)^([^。\n]{2,7}の)[^。\n]{50,200}。\n\1[^。\n]{4,75}", text)))
    if 240 <= len(text) <= 1500 and re.fullmatch(r"/20\d\d-\d{2}-\d{2}/\d{3,8}/?", path):
        page("dated-watch-localization-with-repeated-mistranslated-specifications",
             "腕時計" in head and distinct(re.compile(r"表ファンのが好き|経典の製品|太陽絹面板|"
                                                       r"目盛、分秒採用|底透表|光芒を配布|バラの金の表殻"), text) >= 4
             and distinct(re.compile(r"防水|ケース|クリスタル|表径|表盤|時刻"), text) >= 4)
    if 450 <= len(text) <= 5200 and re.fullmatch(r"/page/\d{1,7}/?", path):
        page("watch-catalogue-with-incompatible-machine-rendered-specifications",
             text.count("腕時計") >= 5
             and distinct(re.compile(r"ケース|ベゼル|18(?:\s*ct|金|プラチナ)|時計市場|腕時計バンド|"
                                     r"ムーブメント|直径\d|表盤"), text) >= 3
             and distinct(re.compile(r"表出さと風格|手で鎖機械|腕間の上物|明らかによりジュエリー|"
                                     r"値段の悪い腕時計|小さい窓の突き進む|カキ式腕時計|80機のコア"), text) >= 3)
    if 160 <= len(text) <= 1300 and re.fullmatch(r"/recipes?/\d+/?", path):
        page("recipe-list-of-clipped-machine-localized-teasers",
             bool(re.match(r"[^。\n]{2,35}(?:isn|doesn|ain|hasn|wasn)\s*\n", text, re.I))
             and distinct(re.compile(r"任意の日|酵母風味|あなたが必要とするもの|食感と風味で爆発|"
                                     r"朝食としてのデザートは|成分のリスト"), text) >= 4
             and not re.search(r"(?m)^(?:材料[ :：]|作り方|レシピ一覧|関連レシピ)", text))
    if 170 <= len(text) <= 1250 and re.fullmatch(r"/[a-z]{6,25}/\d{4,8}\.html?", path):
        bids = re.search(r"(?m)^商品番号\s*:\s*[a-z0-9]{4,16}\s*\n価格\s*:\s*[\d,.]+", text, re.I)
        page("wholesale-product-labels-inserted-inside-fiction-morphemes",
             bool(bids) and len(re.findall(r"まとめ買い\d{1,3}個セット品", text)) >= 2
             and bool(re.search(r"一まとめ買い\d{1,3}個セット品緒|再[^。\n]{2,28}(?:アクリル|ケース|透明)び", text))
             and distinct(re.compile(r"と言いました|と思っていた|一緒に行|任務|会話の間|師が"), text) >= 3)
    if 420 <= len(text) <= 6500 and re.fullmatch(r"/[a-z][a-z0-9]{4,24}/\d{5,8}\.html?", path, re.I):
        injection = re.compile(r"(?:並行輸入品|\d{1,3}包(?:青汁)?栄養補助食品|(?:ローション|クリーム|美容液)\d{2,4}\s*ml|"
                               r"送料無料|送代引き手数料無料|[一-龯ァ-ヺー]{4,24}ダイエット[A-Z]{2,10}|"
                               r"[A-Z][a-z]{2,20}[A-Z]?[a-z]{0,16}\d{2,4})")
        offers = Counter(injection.findall(text))
        price_card = re.search(r"(?m)^商品番号\s*:\s*[a-z0-9]{4,18}\s*\n価格\s*:\s*[\d,.]+", text, re.I)
        page("numbered-catalogue-with-sales-terms-inserted-into-corrupted-fiction",
             bool(price_card)
             and max(offers.values(), default=0) >= 3
             and sum(count >= 2 for count in offers.values()) >= 2
             and len(re.findall(r"[ぁ-ゖ](?:[。,][ぁ-ゖ]|[。,][一-龯]|[一-龯][。,][ぁ-ゖ])|[。,][。,]", text)) >= 6
             and distinct(re.compile(r"と言いました|任務|プレイヤー|チームチャンネル|実力|NPC|ボス|boss|"
                                     r"決戦|モンスター|剣法|道弟子|夜未明|グランド義", re.I), text) >= 4
             and text.count("「") >= 2)
    if 340 <= len(text) <= 2600 and re.fullmatch(r"/[a-z]{3,12}_[a-z0-9]{1,3}/[A-Za-z0-9]{7,55}/?", path):
        page("encoded-locality-landing-with-substituted-buyback-product-template",
             bool(re.search(r"^[一-龯ぁ-ゖ]{2,14}(?:市|区|町|村)(?:[（(][一-龯ぁ-ゖ]{2,10}郡\s*)?で", head))
             and text.count("一括査定") >= 3
             and bool(re.search(r"一括査定(?:の|を使う)(?:利点|メリット)は何でしょう(?:か)?[?。]*\s*(?:ひとつは、)?業社に買い叩かれない事です。", text))
             and distinct(re.compile(r"何とか競り落としたいと思って参加|他店との競争に負けてしまうという危機|"
                                     r"複数の業社が競ってくれるので|すべてうまくいくようにするには時間も手間|"
                                     r"時間もかかるし手間もかかります|在庫状況、資金状況|"
                                     r"どれだけの値段になるか分からないので事前の調査も必要"), text) >= 2)
    if 1100 <= len(text) <= 4400:
        page("chiropractic-synonym-rewrite-with-unexpanded-debris",
             bool(re.search(r"民間療法.{0,65}代替医療[\s\S]{10,320}大正[\s\S]{1,780}(?:サブラクセーション|亜脱臼)"
                            r"[\s\S]{0,900}オステオパシー[\s\S]{0,580}(?:歪み(?:\([^)]{1,10}\))?[・と、]?ズレ|筋繊維|筋骨格)", text))
             and (distinct(re.compile(r"使用[しす]る(?:用語|言葉)でアメリカ|する(?:方法|こと)は異なる|"
                                      r"(?:民間療法\s*(?:\([^)]{3,20}\))?){2}|施術方法の対象とします|"
                                      r"論理の(?:混合形|ミッスク)|主に手足(?:で|による|を使った)矯正"), text) >= 2
                  or text.startswith("整体\n整体") and len(re.findall(r"(?m)^・$", text)) >= 5))
        page("back-pain-rewrites-reusing-numbered-diagnostic-slots",
             len(set(re.findall(r"(?m)^No\.5[1-7]\b", text))) >= 6
             and bool(re.search(r"膀胱直腸障害[\s\S]{100,1150}(?:ラセーグ|ラセグ)[\s\S]{80,2800}ニュートンテスト", text)))
        page("chiropractic-template-spliced-from-multiple-rewritten-definitions",
             text.count("カイロプラクティック") >= 8 and len(re.findall(r"ギリシャ語.{0,45}(?:手|技)", text)) >= 2
             and text.count("サブラクセーション") >= 3
             and distinct(re.compile(r"疾病症状原因|痛みを治療するうこと|施術のにアジャストメント|"
                                     r"代替医療(?:と|として)位置づけしています|矯正のに「アジャストメント|"
                                     r"パーマー.{0,25}が生み出された|専門的な着手計画|専門的な着手方法"), text) >= 2
             and bool(re.search(r"(?m)^(?:AB|CD|EF)\s*$", text) or re.search(r"\b(?:AB|CD|EF)$", text)))
        page("spun-clinic-definitions-with-an-unexpanded-figure-and-repeated-footer",
             "1895年" in head and ("パーマー" in head or "Palmer" in head)
             and text.count("カイロプラクティック") >= 8
             and distinct(re.compile(r"のと呼ばれるようになった|病気症状原因|調整のに|位置づけしています|"
                                     r"専門的な着手方法|入力してください|スペシャリストであり"), text) >= 3
             and bool(re.search(r"(?m)^(?:AB|CD|EF|図[0-9]+)$", text))
             and len(re.findall(r"(?m)^[^\n。]{4,38} +\.$", text[-600:])) >= 4
             and (text.count("背骨の歪みを直す") >= 3 or len(re.findall(r"(?m)^浜松市[南中西東]区 +", text)) >= 3))
    if 900 <= len(text) <= 4200 and re.fullmatch(r"/(?:[a-z0-9_-]+/)?20\d{2}/\d{1,2}/\d{1,2}/?", path):
        page("corrupted-numbered-clinical-outline-on-date-only-archive",
             len(set(re.findall(r"(?m)^No\.5[1-7]\b", text))) >= 6
             and bool(re.search(r"膀胱障害[・、]?直腸障害[\s\S]{500,3000}ニュートン[・ ]?(?:テスト|検査)", text))
             and distinct(re.compile(r"神経障害を可能性|とかがある状況にです|ほどで保存的なやり方|"
                                     r"発病している状況では|体を使わないようにすることができず|"
                                     r"仮定する箇所に骨盤"), text) >= 3)
    if 235 <= len(text) <= 900 and re.fullmatch(r"/[a-z0-9_-]+/20\d{2}/\d{1,2}/\d{1,2}/?", path):
        page("date-only-clinic-entry-with-placeholder-and-rewritten-medical-headings",
             bool(re.match(r"(?:ぎっくり腰|ギックリ腰|腰痛症)\nt\d{1,3}\n急性腰痛症。", text))
             and distinct(re.compile(r"ウェスト周り痛の時|重篤な時でが多く|内臓諸機関|姿勢で痛みが治癒しない|"
                                     r"視察で異常の見当たらない|疾患で、関節捻挫|ウェスト周辺あたり"), text) >= 3)
    if 560 <= len(text) <= 1850 and re.fullmatch(r"/[a-z0-9_-]+/20\d{2}/\d{2}/\d{2}/?", path):
        page("date-only-back-pain-archive-with-unexpanded-diagram-labels-and-spun-diagnosis",
             text.startswith(("ブログ ブログ ブログ\n", "ブログ\nブログ\nブログ\n"))
             and len(re.findall(r"(?m)^[a-z][0-9]{1,2}$", text)) >= 2
             and distinct(re.compile(r"ぎっくり腰|急性腰痛症|腰椎関節|後腹膜臓器|椎間関節の捻挫|NSAIDs"), text) >= 5
             and distinct(re.compile(r"腰周りあたり|ウェスト部分痛のケースには|大変な場合にが多く|"
                                     r"視察で異常個所の見当たらない|痛み発現した時の苦痛が激烈|"
                                     r"予後が好く椎間板病変|その中には、外科疾患のその中にも"), text) >= 3)
    if 95 <= len(text) <= 1300 and re.fullmatch(r"/archives/[0-9]{5,6}/?", path):
        page("game-antenna-landing-with-no-article-body-and-detached-headlines",
             bool(re.match(r"[A-Za-z0-9ァ-ヺー]{2,16}アンテナ\nフォローする\nホーム\n", text))
             and bool(re.search(r"(?m)^20\d{2}/\d{1,2}/\d{1,2}\n[^\n]{2,16}\nこのサイトの記事を見る\n", text))
             and 1 <= len(text.split("このサイトの記事を見る\n", 1)[-1].splitlines()) <= 7
             and sum(bool(re.search(r"\b(?:ゲーム|攻略)\b|[!?]|w{3,}|^【|←", line)) for line in text.splitlines()) >= 2
             and not re.search(r"(?m)^(?:執筆|本文|レビュー本文|投稿者[:：]|文[:：])", text))
    if 180 <= len(text) <= 1100 and re.fullmatch(r"/archives/[0-9]{2,7}/?", path):
        page("generic-free-shipping-search-wrapper-around-copied-item-description",
             bool(re.match(r"(?:送料無料|激安|格安)を調べてみました\n", text))
             and bool(re.search(r"(?m)^「(?:送料無料|激安|格安)」のいろいろな通販ショップのご紹介です。?$", text))
             and bool(re.search(r"(?m)^今日のアイテムは、.{18,170}(?:送料無料|激安|格安)です。", text))
             and bool(re.search(r"(?m)^ご紹介したのは、\n.{3,60}でお取り扱いしています。\n詳細は、以下のとおりです。", text))
             and bool(re.search(r"スマホ・PC・タブレットで検索\s*>\s*(?:送料無料|激安|格安)\s*$", text)))
    if 440 <= len(text) <= 2600 and re.fullmatch(r"/post[_-][0-9]{2,6}\.html", path):
        copied_essay_keyword = re.search(r"(?m)^以上が、(.{5,55} +.{2,20})を考えながら読んだ、", text)
        page("spaced-search-phrase-wrapped-around-copied-public-domain-essay",
             bool(copied_essay_keyword) and text.count(copied_essay_keyword[1]) >= 3
             and bool(re.search(r"(?m)^人口に膾炙[^\n]{5,65}\nについて考えながら", text))
             and "著作権切れ" in text and "道すがら読んだのが" in text
             and distinct(re.compile(r"であらう|ゐる|云つた|存しなかつた|発達したといふ|おいて浪漫主義"), text) >= 4
             and text.rstrip().endswith("いかがでしたか?"))
    if 150 <= len(text) <= 1100 and re.fullmatch(r"/[a-z]{3,12}/[a-z][0-9]{3,7}\.html", path):
        page("foreign-video-funnel-joined-directly-to-clipped-japanese-synopsis",
             bool(re.search(r"(?m)^(?:介绍|简介)[:：]", head))
             and distinct(re.compile(r"不用下载|在线毛片|免费看黄|能让大家在线观看|打包下载微信|老司机带你飙车"), text) >= 3
             and bool(re.search(r"[!.]{1,3}[一-龯ァ-ヺー]{2,14}の[一-龯ァ-ヺー・]{2,20}が[ぁ-ゖ一-龯]", text))
             and len(set(re.findall(r"(?m)^- (?:播放列表|内容介绍|相关影片|[a-z]{2,6}m3u8)$", text))) >= 3)
    if 900 <= len(text) <= 11000 and re.fullmatch(r"/entry[0-9]{3,7}/?", path):
        content_rows = text.splitlines()
        clipped_prompts = 0
        for j, line in enumerate(content_rows[:-1]):
            if not (22 <= len(line) <= 115 and line.endswith("...")):
                continue
            preview = re.sub(r"\s+", "", line[:-3])
            following = re.sub(r"\s+", "", "".join(content_rows[j + 1:j + 4]))
            if following.startswith(preview) and len(following) >= len(preview) + 9:
                clipped_prompts += 1
        page("numbered-entry-with-several-duplicated-clipped-qa-teasers",
             clipped_prompts >= 3
             and len(re.findall(r"[?？]", text)) >= 7
             and not re.search(r"(?m)^(?:質問日時|回答日時|回答者|出典URL|コメントを投稿|投稿者[:：])", text))
    if (400 <= len(text) <= 6500 and re.fullmatch(r"/[a-z0-9_-]+/20\d{2}/\d{2}/\d{2}/[^/]+-\d{1,3}/?", path)
            and "カイロ" in path and "1895年" in head and "パーマー" in head):
        page("mass-rewritten-clinic-article-with-repeated-definitions-and-damaged-seams",
             text.count("カイロプラクティック") >= 5
             and distinct(re.compile(r"疾病症状元|治療するうこと|それがあたえる健康|矯正のにアジャストメント|"
                                     r"専門的な着手計画|腰痛とは\?。|民間療法[（(][^)\n]+\)民間療法|"
                                     r"診察神経学的診察|記載されている記載されている|仕事を休業する仕事を休業する|"
                                     r"神経根症状がある神経根症状|主な症状を診断する治療者"), text) >= 3
             and distinct(re.compile(r"代替医療|世界保健機関|筋肉[・、]骨格|サブラクセーション|"
                                     r"脊椎矯正|マニピュレーション"), text) >= 4)
    if 550 <= len(text) <= 4500:
        expressions = (
            r"に両替したことってあります", r"思わず買いたくなってしまいました",
            r"それじゃ[、,]?また", r"曇りのち(?:[晴雨雪]|はれ)",
            r"(?:に興味があります|について[、,]あなたはどう思いますか)",
        )
        repeated = [len(re.findall(expression, text)) >= 2 for expression in expressions]
        page("assembled-diary-with-rotating-currencies-weather-and-product-cards",
             repeated[0] and repeated[1] and sum(repeated) >= 4
             and len(text.splitlines()) >= 22
             and len(re.findall(r"(?m)^(?:みなさん|皆さん|あしたは|[一-龯]{2,8}市)", text)) >= 6)
    if 230 <= len(text) <= 2200:
        chinese_lead, _, rest = text.partition("\n")
        opening = chinese_lead + rest.partition("\n")[0]
        page("gambling-keyword-preface-on-copied-japanese-feature",
             distinct(re.compile(r"时时彩|彩票控|信用卡充值|注册码|现金网"), opening) >= 3
             and len(re.findall(r"[ぁ-ゖァ-ヺ]", opening)) <= 4
             and len(re.findall(r"[ぁ-ゖァ-ヺ]", text[len(chinese_lead):])) >= 45
             and bool(re.search(r"「人民網日本語版」より|国際在線が報じた", text)))
    if 180 <= len(text) <= 620 and re.fullmatch(r"/[a-z]-[0-9]{3,5}\.php", path):
        page("short-letter-number-route-with-stitched-source-snippets",
             bool(re.search(r"【[^】]{6,70}】.{15,160}出典[ \t]*:[ \t]*[^\n。]{8,70}\?[^\n]{20,145}。\n特に", text))
             or bool(re.search(r"(?m)^(?P<query>[^\n、。:]{4,19})の作り方\s*\n(?P=query)作り方", text))
             and len(re.findall(r"(?m)^(?:PC版|左\s*:|〈メッセージ〉)", text)) == 3
             or "9手詰" in text and "棋士番号" in text and "県庁所在地です" in text
             and "手を合わせて礼拝" in text
             or len(re.findall(r"(?m)^[^\n。]{0,28}N700S", text)) >= 4
             and "乗車記" in text and "間接照明" in text and text.rstrip().endswith("まずは普通車。"))
    if 480 <= len(text) <= 3800:
        policy_lead = r"(?m)^([一-龯ァ-ヺA-Za-z]{2,18}) プラスチック利用方針\s*$"
        headings = re.findall(policy_lead, text[:470])
        lines = [row for row in text.splitlines() if len(row) >= 55]
        page("copied-corporate-policy-with-duplicated-promotions-and-broken-separators",
             len(headings) >= 2 and len(set(headings)) == 1 and host not in {"aeon.info", "www.aeon.info"}
             and len(re.findall(r"[一-龯ァ-ヺ]\?[一-龯ァ-ヺ]", text)) >= 6
             and distinct(re.compile(r"脱炭素型|資源循環型|再生PET樹脂|ボトル\s*to\s*ボトル|PB商品"), text) >= 4
             and sum(left[:32] == right[:32] for left, right in pairwise(lines)) >= 2)
        page("industrial-homepage-on-numeric-gambling-tag-page",
             bool(re.fullmatch(r"/tag/[0-9]{1,5}", path)) and bool(re.search(r"poker|casino|betting", host, re.I))
             and text.count("東栄電化") >= 3 and "東栄電化" in text[:420]
             and distinct(re.compile(r"休日予定表|アルマイトの製品化ガイドブック|機能アルマイト|表面処理の問題解決事例集"), text) >= 3
             and "ISO9001" in text and "ISO14001" in text)
        page("unlabelled-fragrance-and-food-promotions-spliced-at-clipped-line",
             bool(re.search(r"(?:から|にて|で|は|が)、[^\n]{0,55}(?:新作|新商品)フレグランス", head))
             and bool(re.search(r"(?:ローズ|ムスク|フローラル)[^\n]{10,160}\n株式会社[^\n]{2,45}(?:人気|バンド|タイアップ)", text))
             and distinct(re.compile(r"中華まん|トマトペースト|数量限定販売|商品概要"), text) >= 3
             and distinct(re.compile(r"(?m)^(?:商品名|価格|発売|販売元|公式サイト)[ :\t]*:"), text) >= 4
             and not re.search(r"(?m)^(?:関連記事|前の記事|次の記事|一覧に戻る|引用元)", text))
    if 85 <= len(text) <= 250:
        page("video-watch-route-containing-only-copied-channel-boilerplate",
             bool(re.fullmatch(r"/[a-z][0-9]{4,6}-video-[A-Za-z0-9_-]{3,16}UC[A-Za-z0-9_-]{18,28}-m[0-9]{4,6}\.html", path))
             and bool(re.search(r"全国の[^\n。]{2,25}(?:を探すなら|検索なら)", head))
             and distinct(re.compile(r"地域と施設カテゴリ|就職・転職|引越し・お部屋探し|全国の企業や学校"), text) >= 3
             and not re.search(r"動画の内容|視聴|撮影|字幕", text))
    if 180 <= len(text) <= 2400:
        page("stitched-retailer-snippets-under-search-tag-and-generic-shop-footer",
             bool(re.search(r"(?:詳細については、?当社のウェブサイトをご覧ください|"
                            r"についての他のすべては、?当社のウェブサイト上で見つけることができます)。?\s*$", text))
             and (bool(re.match(r"(?:以降|その後|一方)、", head))
                  and bool(re.search(r"/tag/[^/]*(?:ユニフォーム|ジャージ)[^/]*", path))
                  and distinct(re.compile(r"イタリア代表|メキシコ代表|ガンバ大阪|FCポルト|ブラジル代表"), text) >= 4
                  or "ポンパレモールに出店中" in text and "兄妹の可愛いリンクコーデ" in text
                  and distinct(re.compile(r"スリッポンスニーカー|食器|リュック|スリーパー|ひな祭り"), text) >= 4))
    if 660 <= len(text) <= 3000 and re.fullmatch(r"/[a-z]-[0-9]{3,6}\.html?", path):
        page("booking-and-guest-response-fragments-with-interleaved-pagination-label",
             len(re.findall(r"(?<![a-z])Next(?![a-z])", text)) >= 3
             and len(re.findall(r"(?m)^.{0,110}(?:Next|ご投稿|お越し|あらかじめご了承ください).{0,125}$", text)) >= 6
             and (text.count("席数に限り") >= 2 or text.count("あらかじめご了承ください") >= 2)
             and len(re.findall(r"(?:ご滞在|ご宿泊|ご来館|ご再訪|ご投稿)", text)) >= 5
             and bool(re.search(r"(?:いただき|頂き|賜り)\s*(?:誠に|本当に)ありがとうございました", text))
             and not re.search(r"(?m)^(?:投稿者|回答日|宿泊日|旅行のタイプ|口コミ一覧)[ :：]", text))
    if 520 <= len(text) <= 4200 and re.fullmatch(r"/[a-z]-[0-9]{3,6}\.html?", path):
        page("scraped-segments-separated-by-repeated-inline-pagination",
             len(re.findall(r"(?<=[。!?])[ \t]{0,3}Next(?![A-Za-z])", text)) >= 3
             and not re.search(r"(?m)^(?:通信販売事業者|お客様レビュー一覧|ご利用ガイド)[ :：]", text))
    if 1600 <= len(text) <= 6900 and "1895年" in text[:750] and "パーマー" in text[:750]:
        page("rewritten-clinic-definitions-with-copied-back-pain-heading-order",
             text.count("カイロプラクティック") >= 8
             and len(re.findall(r"ギリシャ語.{0,65}(?:手|技)", text)) >= 2
             and bool(re.search(r"腰(?:痛|部).{0,16}ガイドラインんでは", text))
             and bool(re.search(r"2004年の(?:欧州(?:ヨーロッパ)?|ヨーロッパ)委員会.{0,105}84\s*%.{0,26}23\s*%", text))
             and (text.count("世界保健機関") + text.count("WHO") >= 2 or "米国での腰痛事情" in text)
             and distinct(re.compile(r"欧州ヨーロッパ|米国アメリカ|為ににひきおこ|"
                                     r"骨格ヘルスケア|緊張性腰痛|骨格系健康管理|"
                                     r"症状まれに|腰\(こし\)の(?:病気|疼痛|症状)"), text) >= 2)
    if 750 <= len(text) <= 12500 and "お金" in text:
        board_dates = re.findall(r"(?m)^20[0-9]{2}/[0-9]{2}/[0-9]{2} \([A-Z][a-z]{2}\) [0-9]{2}:[0-9]{2}:[0-9]{2}$", text)
        if len(set(board_dates)) >= 4:
            cash_claims = re.compile(r"(?:使い[切き]れないほど|ただで|連絡(?:した|する)だけで|連絡をしてみたら|"
                                     r"一括で返済|即日大金|年収の何倍|母子家庭で[0-9]{1,2}歳の娘)")
            page("forum-cash-scam-posts-with-recycled-testimonials",
                 len(cash_claims.findall(text)) >= 7
                 and distinct(cash_claims, text) >= 4
                 and (len(re.findall(r"(?m)^\*\.[A-Za-z0-9.-]+$", text)) >= 4
                      or len(re.findall(r"(?m)^.{4,65} - .{1,40} URL$", text)) >= 4)
                 and len(re.findall(r"(?:お金をもら|お金が振り込|大金を手に入れ|金額が振り込)", text)) >= 3)
    if 650 <= len(text) <= 16000 and "Reviews:" in text:
        empty_date_fields = re.findall(r"(?m)^[1-5](?:\.[0-9])? -\s*\n\"([0-9]+)\"\nby[^\n]{1,90}\n, に書かれています$", text)
        review_subjects = re.compile(r"スマホ|フィルム|断線|Wi-Fi|ブルートゥー?ス|ケース|レンズ|ステアリング|"
                                     r"ヘルメット|スニーカー|ペンラ|妊娠|アクキー|抹茶|ティーパック|ザリガニ|"
                                     r"吸盤|フラッシュ|サプリ|エアフィルター|内径|カーゴパンツ|ニベア|フレア")
        page("numbered-product-review-splice-with-missing-dates",
             len(set(empty_date_fields)) >= 6
             and distinct(review_subjects, text) >= 4
             and bool(re.search(r"(?m)^Reviews:\s*\n[1-5](?:\.[0-9])? -", text))
             and bool(re.search(r"(?m)^[1-5] -\s*\Z", text)))
    if 1500 <= len(text) <= 11000 and "ハンドメイド・手作り・クラフト作品の販売サイト" in head:
        page("discount-catalogue-title-repeated-in-unrelated-flowchart-guide",
             len(re.findall(r"[0-9]{2}%以上節約[^\n]{5,160}通販\| *\(\)", text)) >= 2
             and distinct(re.compile(r"フローチャート|図記号|分岐線|矢印|図形|図表|凡例"), text) >= 5
             and text.count("フローチャート") >= 6
             and len(re.findall(r"(?m)^- .{4,100}$", text[-950:])) >= 5)
    if 950 <= len(text) <= 14000 and "出会い" in head:
        local_dating = re.match(r"([一-龯]{2,5})(?:の|で|[ \t]+)出会い", head)
        if local_dating:
            local_term = re.escape(local_dating.group(1))
            repeated_phrases = re.compile(local_term + r"(?:の|で|[ \t]+)出会い")
            page("local-dating-keywords-injected-into-unrelated-snippets",
                 len(repeated_phrases.findall(text)) >= 12
                 and distinct(repeated_phrases, text) >= 2
                 and len(re.findall(r"(?m)^.{1,28}" + local_term + r"(?:の|で)出会い\s*$", text)) >= 5
                 and len(re.findall(r"(?m)^[^。\n]{1,24}" + local_term + r"(?:の|で)出会い\s*$", text)) >= 3
                 and distinct(re.compile(r"借金|家具|水族館|銀行|乗車|工事|宝石|カレー|夕食|旅行|給料|設備"), text) >= 5)
    if 310 <= len(text) <= 2300:
        topical_headline = text.split("\n", 1)[0]
        unrelated_hooks = re.compile(r"【心理テスト】.{0,45}(?:性格|深層心理)|"
                                     r"(?:インボイス制度|確定申告).{0,50}(?:副業|納税額|せどり)")
        clinic_outline = re.compile(r"^(?:肩[こ凝]り|頭痛|腰痛|肩凝り)(?:[^\n]{0,25})\n")
        clinical_terms = re.compile(r"肩[こ凝]り|頸椎|僧帽筋|骨格|頭痛|治療|肩こり|薬物療法|"
                                    r"一次性頭痛|二次性頭痛|基礎疾患|群発性頭痛|鎮痛剤|急性腰痛")
        page("viral-or-tax-headline-joined-to-unrelated-clinic-outline",
             bool(unrelated_hooks.search(topical_headline)) and not clinical_terms.search(topical_headline)
             and bool(clinic_outline.match(text[len(topical_headline) + 1:]))
             and distinct(clinical_terms, text) >= 5
             and bool(re.search(r"(?m)^(?:肩[こ凝]り|頭痛|腰痛).{0,14}(?:とは[?。]?|治療[。]?|改善しよう|改善方法[。]?)$", text)))
    if (700 <= len(text) <= 4200 and not host.endswith((".lg.jp", ".go.jp", ".gouv.fr"))
            and re.fullmatch(r"/e[0-9]{4}/gikai-radio/(?:r[0-9]{2}-)?[a-z0-9-]{2,32}\.html", path)):
        page("government-radio-notice-and-page-chrome-rehosted-on-unrelated-domain",
             bool(re.match(r"ここから本文です。\nページ番号:[0-9]{5,8}\n掲載日:20[0-9]{2}年", text))
             and distinct(re.compile(r"埼玉県議会|県民の皆さま|GOGOMONZ|FM NACK5|県議会公式X"), text) >= 4
             and len(re.findall(r"(?m)^\|.{1,60}\|.*議員", text)) >= 3
             and "より良いウェブサイトにするためにみなさまのご意見をお聞かせください" in text[-150:])
    if 1200 <= len(text) <= 22500 and re.fullmatch(r"/page/[0-9]{1,4}-[0-9]{1,2}/?", path):
        page("translated-tattoo-list-mirror-with-repeated-literal-field-phrasing",
             len(re.findall(r"(?m)^[0-9]{1,2}\. ?[^\n]{2,65}(?:タトゥー|入れ墨)", text)) >= 17
             and len(re.findall(r"(?m)^入れ墨:", text)) >= 17
             and len(re.findall(r"(?m)^意味:", text)) >= 7
             and len(re.findall(r"インクを塗(?:って|りました)|埋め込まれて|[。]\.", text)) >= 6
             and bool(re.search(r"ラッパー|シンガーソングライター", head)))
    if 950 <= len(text) <= 6800 and len(re.findall(r"(?:稼げるバイト|日給[0-9]+万)", text)) >= 6:
        region = r"(?:関西|関東|東海|東北|九州|四国|北陸|北海道|[一-龯]{2,5}(?:市|県|地方))"
        misplaced_region = re.compile(r"(?:色[々ん]な" + region + r"がある|"
                                      r"銀行は" + region + r"を禁止|"
                                      r"通販サイト.{0,18}" + region + r"になるのか|"
                                      + region + r"は年齢、学歴、職歴などを問|"
                                      + region + r"が広がった背景には賃金低下)")
        keyword_headings = re.findall(r"(?m)^.{0,30}ダブルワーク +稼げるバイト +[^ \n]{1,12} +日給[0-9]+万 +"
                                      r"バイト +" + region + r" +(?:高収入自宅|在宅高収入) +(?:職業|仕事)[^\n]{0,25}$", text)
        page("job-keyword-lists-and-regional-labels-substituted-into-prose",
             len(set(keyword_headings)) >= 2 and distinct(misplaced_region, text) >= 3
             and distinct(re.compile(r"アフィリエイト|住民税|日給|本業|職業|経理|普通徴収"), text) >= 5)
    if 210 <= len(text) <= 950 and re.fullmatch(r"/[0-9]{3,5}\.html", path):
        affiliate_cues = re.compile(r"教材|講座|トレード手法|効果あり|効果的|ほんとのところ|いかさま|"
                                    r"怪しすぎ|評判になって|噂になって|経歴が興味深い|話題になって")
        pasted_meal = re.search(r"(?m)^.{0,26}(?:お呼びがかかり|無理やり付き合わされて)\n"
                               r".{2,65}(?:昼ご飯|夕食|お昼ご飯)を食べ.{0,12}\n"
                               r"(?:第一印象|見た瞬間|見た感じ).{2,36}\n"
                               r".{2,65}(?:が最高|もうサイコー).{0,20}$", text)
        page("affiliate-pitch-spliced-to-place-and-meal-diary-template",
             distinct(affiliate_cues, text) >= 3
             and (pasted_meal or bool(re.search(r"(?m)^【(?:複数行|一行)置換[A-Za-z0-9]{0,5}】$", text)))
             and bool(re.search(r"(?m)^(?:また、?食べ|もう一度食べ|最後まで読んでくれてありがとう|"
                                r"ブログはおわり|この時間はこんなとこ)", text)))
    if 580 <= len(text) <= 3800 and re.fullmatch(r"/blog-entry-[0-9]{1,6}\.html", path):
        author_panel = re.search(r"(?m)^Author:\S{1,25}$", text)
        if author_panel:
            introduction = text[:author_panel.start()].rstrip()
            catalogue = text[author_panel.end():]
            page("clipped-affiliate-introduction-and-unrelated-sales-snippet-catalogue",
                 125 <= len(introduction) <= 420 and introduction[-1] not in "。.!?)]」』"
                 and bool(re.search(r"マニュアル|痩せるプログラム|痩せられるプログラム|この教材", introduction))
                 and distinct(re.compile(r"生年月日:|血液型:|住んでるところ:|趣味:"), catalogue[:140]) >= 3
                 and len(re.findall(r"(?m)^.{37,180}(?:\.{3}|・{3}|…)\s*$", catalogue)) >= 4
                 and distinct(re.compile(r"相場|億円稼ぐ|アフィリエイト時代|名門私立|通常パッケージ版|"
                                         r"恋愛成功法|FXノウハウ|トレール機能"), catalogue) >= 5)
    if 650 <= len(text) <= 12500 and re.fullmatch(r"/[0-9]{14,19}", path):
        posts = [line for line in text.splitlines() if line]
        page("unattributed-keyword-social-splice-with-homonym-and-inserted-advert",
             len(posts) >= 12 and sum(len(line) > 185 for line in posts) <= 3
             and len(re.findall(r"風俗|デリヘル|ソープ", text)) >= 8
             and bool(re.search(r"(?m)^【[^】]{3,25}イベント開催】.{0,80}(?:[0-9]{1,2}月|[0-9]{1,2}/[0-9]{1,2})", text))
             and bool(re.search(r"同時押し地帯.{0,28}フルヘルス", text))
             and bool(re.search(r"(?m)^(?:今、WEB会議中|まとめ発信)|フォロワー外から失礼", text))
             and not re.search(r"(?m)^(?:本人の投稿|引用元[:：]|投稿日時[:：]|コメント欄)$", text))
    if 190 <= len(text) <= 570:
        page("affiliate-review-template-with-generic-judgment-and-missing-product-field",
             bool(re.search(r"(?m)^友達の話では[、,].{6,120}(?:ようですが|ですが)[、,]?\s*$", text))
             and bool(re.search(r"(?:プロの視点|プロしか知らない).{1,55}(?:なのは|だというのは)(?:確か|本当)", text))
             and bool(re.search(r"(?:ぶっちゃけた話|公式ダウンロードサイトは大丈夫).{0,8}(?:\.{3}|…|・{3})", head))
             and bool(re.search(r"(?:○{3}を□{3}|一からネットで集めてみるとやっぱり苦労)", text))
             and bool(re.search(r"(?:納得できました|改めて知りました)。o\(\^▽\^\)o\s*$", text)))
    if 170 <= len(text) <= 650:
        page("affiliate-review-with-fake-product-endorsement-decisions",
             bool(re.search(r"で、?\s*知られている、?\s*[^\n]+さんが、?\s*いろいろと話題になって", head))
             and bool(re.search(r"さんの経歴や、?\s*「[^」]+」\s*暴露話を見てみると", text))
             and bool(re.search(r"言ってるけど、?\s*そんな効果あるのかな[あぁ]。?", text))
             and bool(re.search(r"本当なら魅力あるよね。?\s*やってみようかな[ー〜~]?\s*欲しくなってきたな[ー〜~]?\s*買ったらいい感じかも\s*$", text)))
    if 550 <= len(text) <= 3800 and "販売価格" in head:
        page("unrelated-newswire-story-injected-between-investment-offers",
             distinct(re.compile(r"トレーダー|投資法|トレードの知識|相場で勝つ"), head) >= 3
             and bool(re.search(r"<\s*br\s*>|(?m:^>\s*$)", text))
             and len(re.findall(r"販売価格[^。\n]{0,80}(?:無料|送料)", text)) >= 2
             and bool(re.search(r"販売価格[\s\S]{0,260}(?:国土交通省|警察庁)[\s\S]{60,2200}"
                                r"《レスポンス[^》]{0,30}》[\s\S]{0,180}販売価格", text)))
    if 160 <= len(text) <= 1100:
        page("affiliate-pitch-with-reused-forum-rumor-and-fake-skepticism",
             bool(re.search(r"さんの噂が[、,\s]+2(?:ch\b|ちゃんねる)", text, re.I))
             and bool(re.search(r"いろいろ言われている[\s\S]{0,52}本当の(?:評価|評判)はどうなんだろう", text))
             and bool(re.search(r"悪評やクレームは[、,\s]+見当たらなかったから", text))
             and (bool(re.search(r"(?:体験談|クチコミ|口コミ|購入者)[\s\S]{0,100}(?:苦情|実践|購入|買って|試して)", text))
                  or bool(re.search(r"言ってるけど[\s\S]{0,180}実践方法[\s\S]{0,180}初心者でもできるのか"
                                    r"[\s\S]{0,180}試した人はどうなのかな", text))))
        page("affiliate-product-slot-with-repeated-unresolved-skepticism-and-stock-ending",
             bool(re.search(r"(?m)^[^\n、。]{6,48}が、?\n2ch\s*\(2ちゃんねる\)でも\s*噂になって(?:います|るみたい)。$", text, re.I))
             and bool(re.search(r"これが本当なら、?\s*試してみる価値はあるかな[あぁ]。?\n(?:欲しく|気に)なってきたな[ー〜~]?", text))
             and (bool(re.search(r"言ってるけど\nそれが問題なんだよね[えぇ]?。\n本当に効果があるか\nどうなんだろうね[ー〜~]?", text))
                  and bool(re.search(r"いろいろ意見が、?\nわかれているみたいだね。", text))
                  or bool(re.search(r"言ってるけど\.{3}\n本当に効果があるかどうかはわからないという評判", text))
                  and bool(re.search(r"(?m)^⇒効果あり\?\s*購入者の体験談をみてみる$", text))))
        if re.match(r"/(?:entry/)?20\d{2}/\d{1,2}/\d{1,2}/", path):
            page("affiliate-offer-with-unanswered-skeptical-review-script",
                 bool(re.search(r"(?m)^(?:今.{0,24}(?:話題になっている|売れている)|購入者はどうだったのか)", text))
                 and bool(re.search(r"信じてもいいのかな[ぁあ]?", text))
                 and (bool(re.search(r"という人にもって[、,]?[ \t]*\n嘘じゃないよね", text))
                      and bool(re.search(r"実際に勝てた人っているの.{0,4}\s+体験談や口コミが知りたい", text))
                      and bool(re.search(r"(?m)^たぶん買っちゃうと思う[ｗw]?$", text))
                      or "実践者の口コミ、評価を確認" in text and "インチキとかではないみたい" in text
                      and bool(re.search(r"(?m)^[・.](?:\s*\n[・.]){3,}\s*\nこのところ、", text))
                      and bool(re.search(r"(?m)^⇒.{4,90}の詳しい内容はココをクリック", text))))
    if 900 <= len(text) <= 4600 and "No.51" in text and "No.57" in text:
        outline = list(re.finditer(r"(?m)^No\.(5[1-7])[ \t]*\n"
                                   r"(緊急性|神経[学的]+(?:診察|検査)|反射|知覚|筋力|鑑別診断|治療)", text))
        if len(outline) == 7 and [int(m[1]) for m in outline] == list(range(51, 58)):
            page("mechanically-rewritten-clinic-article-with-reused-diagnostic-outline",
                 bool(re.search(r"骨髄AVM[\s\S]{0,300}(?:心内膜炎|急性の溶血反応)", text[:outline[0].start()]))
                 and "Crossed SLR" in text[outline[4].end():outline[5].start()]
                 and bool(re.search(r"仙腸骨関節[\s\S]{0,140}ニュートン", text[outline[5].end():outline[6].start()]))
                 and "パラセタモール" in text[outline[6].end():])
    if 240 <= len(text) <= 5000 and re.fullmatch(r"/[a-z][a-z-]{3,22}/[0-9]{4,5}[a-z]{4}[a-z0-9]{7,25}/?", path):
        page("copied-retail-specification-on-fabricated-outlet-item-route",
             (text.startswith("商品説明\n") and text.count("\n★") >= 3
              and bool(re.search(r"ふ増の[^\n。]{2,30}テープ|[ァ-ヶ]{3,}(?:増属|府族)パーツ", text)))
             or len(set(re.findall(r"\bB0[A-Z0-9]{8}\b", text))) >= 4 and "© 熱販売" in text
             and distinct(re.compile(r"並行輸入品|SWIMWEAR|サミフェス|トレーニング練習|ボートロッカー", re.I), text) >= 3)
    if 220 <= len(text) <= 3200 and re.fullmatch(r"/[a-z0-9]{3,45}\.html?", path, re.I):
        endings = re.findall(r"(?m)^[^\n。]{10,140}。([^\n。!?]{3,24})$", text)
        page("unrelated-affiliate-search-terms-inserted-at-consecutive-paragraph-ends",
             len(endings) >= 4
             and distinct(re.compile(r"お試し|取り扱い店|通販|最安値|クーポン|無利息"), " ".join(endings)) >= 2
             and len(re.findall(r"結婚相談所|脱毛\s*失敗|であい|保険料|消費者金融|育毛剤", " ".join(endings))) >= 2)
    if 440 <= len(text) <= 3600 and re.fullmatch(r"/[0-9]{4,5}[a-z][a-z0-9]{10,13}/[a-f0-9]{5,9}\.html?", path):
        page("used-fashion-listing-appended-to-unrelated-beverage-stock-update",
             bool(re.match(r"\|[^\n]{8,80}\|\n\|[\d-]+[A-Za-z]{2,6}\|\n\|[\d,]+円 [\d,]+円\|\n商品説明", text))
             and distinct(re.compile(r"ポリエステル|出品[し致]|ショルダー|身幅|袖丈|アウター"), text[:650]) >= 3
             and distinct(re.compile(r"ビタミンC|微炭酸|[0-9]+ml|茶葉|ほうじ茶|[0-9]+種類の植物", re.I), text[-480:]) >= 4
             and len(re.findall(r"入荷(?:致し|し|いたし)", text[-480:])) >= 2)
    if 600 <= len(text) <= 4000 and len(paragraphs) >= 12:
        lines = text.splitlines()
        page("unlabelled-diary-search-and-product-snippets-with-recycled-opening-line",
             len(lines) >= 18 and 9 <= len(lines[0]) <= 55 and lines[0] == lines[-1]
             and len(re.findall(r"定額制(?:出会い系)?サイト|出会い系サイト", text)) >= 3
             and distinct(re.compile(r"ハイドロキノン|保湿効果|ジムリーダー|ポケットモンスター|"
                                     r"フィニアスとファーブ|しりとり|利用規約の細部"), text) >= 4
             and bool(re.search(r"(?:教養の美しさ|左右もし[、,]|という方には定額制出会い系|"
                                r"勉強して先生になれるくらい)", text)))
    if 180 <= len(text) <= 950 and re.fullmatch(r"/[a-z0-9]{6,20}/?", path, re.I):
        page("clipped-finance-and-office-notes-with-detached-work-from-home-query",
             text.startswith("→") and bool(re.search(r"(?m)^(?:主婦|在宅)\s*(?:副収入|副業)\s*(?:在宅|収入)$", text))
             and distinct(re.compile(r"サブプライム|投資先|業績が悪く|経常利益"), text[:300]) >= 2
             and bool(re.search(r"マニュアルとは\s*1[.．].{4,65}2[.．].{4,72}3[.．]", text))
             and bool(re.search(r"(?m)^までには[一-龯ぁ-ゖ]{4,18}", text)))
    if 200 <= len(text) <= 1800:
        search_sections = list(re.finditer(r"(?m)^([^\n。!?]{5,38})[ \t]*(?:に関するはなし|に関する質問|関連NEWS)[ \t]*$", text))
        if len(search_sections) >= 3 and len({m[1].strip() for m in search_sections}) == 1:
            term = search_sections[0][1].strip()
            page("search-query-reused-as-article-question-and-news-template-slot",
                 text.count(term) >= 5 and bool(re.search(r"Google\s*blogより|Yahoo!?知恵袋より", text, re.I))
                 and bool(re.search(r"(?m)^(?:→|⇒)[^\n。]{4,50}$", text))
                 and bool(re.search(r"教えて下さい。|教えてください。|はじめまして。", text))
                 and text.rstrip().endswith("..."))
        page("placeholder-fields-left-in-fabricated-affiliate-endorsement",
             distinct(re.compile(r"良い評価というのは|体験者に喜ばれている|評価されている理由は|"
                                 r"結構見つけ難かった|高い効果があると確信|やらない理由が見当たらない"), text) >= 4
             and bool(re.search(r"評価されている理由は.{0,30}[○〇◯]{2,}を[○〇◯]{2,}する", text)))
    if host.endswith(".edu") and path == "/index.php" and "=" not in address.query:
        page("unrelated-retail-fragment-at-coded-education-site-entry",
             len(address.query) >= 20 and bool(re.fullmatch(r"[a-z]{4}[-/][a-z0-9/-]{16,70}", address.query))
             and (bool(re.match(r"購入者さん\n投稿日\s*[:：]\s*20\d{2}年", text))
                  and "実用品・普段使い" in text and text.endswith("PAGE TOP")
                  or "カテゴリトップ >" in text and "【送料無料】" in text and "所収記事を短くまとめたもの" in text))
    if 200 <= len(text) <= 3200 and re.fullmatch(r"/vod[-/]detail[-/]id[-/]\d{4,9}\.html?", path, re.I):
        page("native-film-synopsis-glued-to-repeated-foreign-streaming-keywords",
             bool(re.match(r"[^\n《]{2,25}提供《([^》]{2,40})》", text))
             and distinct(re.compile(r"在线播放|迅雷资源|高清未删减|百度云蓝光|高清在线观看"), head) >= 3
             and bool(re.search(r"在线观看(?=[一-龯]{2,6}[ァ-ヶ]{3}|[ぁ-ゖァ-ヶ]{2,6})", head)))
    if 230 <= len(text) <= 1900 and re.fullmatch(r"/detail/\d{4,9}\.html?", path, re.I):
        page("rehosted-video-description-with-mid-clause-keyword-and-scraper-boilerplate",
             bool(re.search(r"[ぁ-ゖ一-龯]になって(?:出租屋|在线播放|未删减|高清观看)[^。]{1,24}。", head))
             and distinct(re.compile(r"功能対象外|機能対象外商品|特典・セット商品|数量限定版|予約商品"), head) >= 2
             and bool(re.search(r"喜欢请分享给你的小伙伴.{0,20}请记住本站", text))
             and len(re.findall(r"(?im)^(?:百度|谷歌|必应|搜狗|奇虎|神马)\s*sitemap", text)) >= 3
             and "若本站收录内容无意侵犯" in text)
    if 1200 <= len(text) <= 6500 and host and re.search(r"(?:^|&)m=20\d{4}(?:&|$)", address.query):
        page("dated-affiliate-archive-stitches-medical-tests-payment-products-and-gifts",
             distinct(re.compile(r"がん検診|羊水検査|絨毛検査|微小欠失|検査結果も採血から"), text) >= 3
             and distinct(re.compile(r"ポイントが付|カードではポイント|法人口座|プレミアムゴールドカード|現金精算"), text) >= 3
             and distinct(re.compile(r"美白有効成分|メラニン|シミを|ブライトニング|チェストベリー|モイストアップ美容"), text) >= 3
             and distinct(re.compile(r"お中元|送料別|お届け日指定|クール便対象|のし紙|お祝いのギフト"), text) >= 3
             and bool(re.search(r"(?m)^(?:商品番号|[A-Z]{2,12}\.\d{1,4}[ァ-ヶ]{4,})", text)))
    if 500 <= len(text) <= 6500 and host and re.search(r"(?:^|&)m=20\d{4}(?:\d{2})?(?:&|$)", address.query):
        ad_starts = [m.start() for m in re.finditer(r"(?m)^(?:東京で家賃|空室状況は|回線COMのクラウドPBX|"
                                                    r"ビジネスフォンをポケットに|クリクラは|ひざ・肩・腰)", text)]
        page("date-archive-splicing-beauty-promotions-rental-housing-and-telephony",
             len(ad_starts) >= 3
             and distinct(re.compile(r"体験セット|抗菌タオル|初回購入特典|コスメアワード|アプリ会員登録"), text) >= 3
             and distinct(re.compile(r"シェアハウス|空室状況|家具家電付|敷金礼金なし|仲介手数料"), text) >= 3
             and distinct(re.compile(r"クラウドPBX|内線通話|IP電話機|ビジネスフォン|コールセンター業務"), text) >= 3)
        page("date-archive-splicing-water-delivery-and-unrelated-health-products",
             distinct(re.compile(r"サーバーレンタル料が無料|サーバー本体|水と冷水|電気代も約"), text) >= 3
             and distinct(re.compile(r"ヒアルロン酸.{0,10}100mg|サプリメントは稀有|日本薬師堂|関節の痛みを|ペプチド"), text) >= 2
             and bool(re.search(r"(?m)^多くのお客様に\d+つの理由で選ばれています", text)))
    if 150 <= len(text) <= 1650 and path in {"", "/"}:
        locality_keyword = re.search(r"(?m)^([ぁ-ゖァ-ヺ一-龯]{2,15}出会い)でが文字化けした", text)
        page("local-dating-keyword-injected-into-detached-diary-and-beauty-clips",
             bool(locality_keyword) and text.count(locality_keyword[1]) >= 3
             and text.count("文字化けした理由がわかりません") >= 2
             and len(re.findall(r"(?m)^[?]{2}画像は[^\n]{4,60}", text)) >= 2
             and distinct(re.compile(r"そばかす|色素細胞|活性酸素|日光|老化"), text) >= 3)
    if 230 <= len(text) <= 2800 and text.rstrip().endswith("期間限定!お金儲け情報"):
        page("media-scrape-with-unrelated-make-money-footer",
             (bool(re.search(r"(?m)^動画ID[:;]\s*[A-Za-z0-9_-]{11}\n説明[:;][^\n]{55,400}\n"
                             r"投稿者[:;]\s*\S[^\n]{0,40}\n期間限定!お金儲け情報$", text))
              and 5 <= len(text.splitlines()) <= 10
              or len(re.findall(r"(?m)^RSS:[^\n]{5,80}$", text)) >= 3
              and len(re.findall(r"(?m)^スポンサーリンク\s+説明[:;][^\n]{12,110}$", text)) >= 2))
    if 800 <= len(text) <= 5000 and re.fullmatch(r"/archives/post-[0-9]{3,7}\.html", path):
        advice = re.search(r"(?m)^([ぁ-ゖァ-ヺ一-龯]{4,30})\n\1は、[^\n。]{12,85}。\s*以下が\1[^\n]{8,70}。$", text[-930:])
        if advice:
            discussion = text[:len(text) - len(text[-930:]) + advice.start()]
            closing_bullets = text[len(discussion):]
            page("unattributed-forum-exchange-with-automatically-appended-generic-advice",
                 len(discussion.splitlines()) >= 25
                 and len(re.findall(r"(?m)^.{5,42}$", discussion)) >= 17
                 and not re.search(r"(?m)^(?:投稿者|引用元|出典|返信日時|ID[:：]|[0-9]+[:：]|[→>]{2})", discussion)
                 and len(re.findall(r"(?m)^- [ぁ-ゖァ-ヺ一-龯ー]{2,18}:[^\n]{10,110}。$", closing_bullets)) >= 5
                 and bool(re.search(r"(?m)^これらのヒントを実践することで、[^\n]{10,90}できます。\nコメント$", closing_bullets)))
    if 240 <= len(text) <= 1700 and path in {"", "/"}:
        page("generated-short-diary-with-repeated-locality-and-unrelated-padded-prompts",
             bool(re.match(r"(?:みなさま|皆様)、こんにちは。\n(?:悲しい|困った|嫌な)ことはありませんでしたか\?", text))
             and bool(re.search(r"(?m)^明日の([^\nは]{3,16}[市町村区])は、[^\n]{3,40}だそうですよ。$", text))
             and len(re.findall(r"(?m)^.{5,42}$", text)) >= 17
             and len(re.findall(r"(?m)^.{4,44}\?\s*$", text)) >= 4
             and distinct(re.compile(r"エアリーシェイプ|リセッタソフト|現状維持でしょうか|人違いだよ|通貨がいいとか|"
                                     r"(?:\d{1,2}時)に(?:口論|入れていた予約)|名残惜しいですが、また次回"), text) >= 5)
    if 700 <= len(text) <= 8000 and path in {"", "/"}:
        page("blanked-nutrition-and-diary-montage-with-missing-phrase-slots",
             len(re.findall(r"(?m)^(?:中に|を飲むと|を始める前の|で栄養素が|は少しだけ|がオススメする)[^\n]{4,95}$", text)) >= 4
             and distinct(re.compile(r"中に を飲む|そのものよりも一緒に|食、食を|食を抜いて、|始める前のなら、|"
                                     r"食後のって|名義はのまま|こうしたの知識|生活習慣とづくり"), text) >= 4
             and distinct(re.compile(r"たんぱく質|栄養素|摂取カロリー|リバウンド|ドカ食い|肥満"), text) >= 4
             and distinct(re.compile(r"就職|資格をと|正社員|不景気|手に職"), text) >= 3)
    if 700 <= len(text) <= 5200 and re.fullmatch(r"/[^/]{4,30}/\d{4,10}/(?:[^/]*t-shirt|hoodie|sweat)/[^/]+/[^/]+/?", path, re.I):
        page("apparel-listing-padded-with-copied-medical-prose-and-embedded-drug-promotion",
             bool(re.search(r"(?:シアリス|バイアグラ|レビトラ|タダラフィル)\s*通販(?:性機能|勃起|がん|副作用)(?:障害|不全|治療|として|の)", text))
             and distinct(re.compile(r"外科手術|放射線治療|ホルモン療法|ホスホジエステラーゼ|骨盤内臓器|がんサバイバー"), text) >= 4
             and bool(re.search(r"(?m)^\|Size\|\|Body length \(cm\)\|\|", text)))
    if 250 <= len(text) <= 2600 and re.fullmatch(r"/feed/[0-9]{8,9}/?", path):
        lines = text.splitlines()
        page("numbered-feed-of-spliced-forum-headlines-with-recurring-tail",
             22 <= len(lines) <= 65 and max(map(len, lines)) <= 142
             and len(set(lines) & {"関西圏大学ちゃんねる", "既婚者たちのまとめ", "すまいる(^-^)ぶろぐ"}) >= 2
             and len(set(lines[-14:]) & {"26になるけど一生結婚出来る気がしない", "結婚できるかな?",
                                        "好きな子とデートしたんだけど", "街コン一人で行ってきた"}) >= 3
             and max(map(len, lines[-5:])) < 74)
        video_topics = distinct(re.compile(r"ドラレコ|車載映像|フルビデオ|動画|映像|運転|大失敗|わろた|w{3,}"), text)
        page("numbered-feed-of-detached-video-and-forum-threads",
             len(lines) >= 10
             and (len(lines) >= 12 and len(lines[0]) >= 15 and lines[1] == "1000mg" and video_topics >= 4
                  or len(lines) >= 22 and "FX&バイナリーまとめアンテナ" in lines
                  and "恋人探しのお手伝い" in lines
                  and distinct(re.compile(r"介護職|求人|新卒採用|一般内科|薬剤師|美容師"), text) >= 2
                  or len(lines) >= 40
                  and len(set(lines) & {"気団談", "鬼女速", "おうち速報", "子育てちゃんねる",
                                        "本当にやった復讐 まとめ", "キチガイママまとめ保管庫"}) >= 3
                  and sum(line.startswith(("「", "『")) for line in lines[12:]) >= 7
                  or len(lines) >= 18 and lines[1] == "芸能人の気になる噂"
                  and len(re.findall(r"w{3,}", text)) >= 5 and "オラウータン" in text))
        page("numbered-forum-feed-mixing-unrelated-headlines-after-standalone-publisher-label",
             12 <= len(lines) <= 36 and all(4 <= len(line) <= 105 for line in lines)
             and lines[1] in {"大艦巨砲主義", "哲学ニュースnwk", "キニ速"}
             and sum(bool(re.search(r"[!?←→]|w{2,}|(?:か|だろ|教えてくれ|語るスレ)[。…]*$", line))
                     for line in lines[2:]) >= 6
             and sum(line.count("。") for line in lines) <= 3)
        page("numbered-game-feed-with-forum-headlines-and-no-original-article",
             len(lines) >= 16 and 4 <= len(lines[1]) <= 60
             and bool(re.search(r"(?:まとめ(?:ブログ|サイト)?|速報|攻略情報|攻略通信|攻略チャンネル)", lines[1]))
             and distinct(re.compile(r"ガチャ|イベキャラ|デッキ|PSR|フリクエ|サーヴァント|艦娘|"
                                     r"戦果ランキング|メダル|イベント|シンデレラキャラバン|コラボ"), text) >= 4
             and sum(bool(re.search(r"[!?]|\.{3}|(?:かな|だろう|なんだ|クレメンス|w{2,})[!?]*$", s)) for s in lines[3:]) >= 8
             and sum(s.count("。") >= 2 for s in lines) <= 1
             and not re.search(r"(?m)^(?:まとめコメント|本文|執筆|文[:：]|投稿日時|レビュー本文|出典URL)", text))
        page("numbered-game-feed-of-unattributed-chat-snippets",
             9 <= len(lines) <= 32
             and lines[0].startswith("【")
             and bool(re.search(r"攻略まとめ(?:速報)?|まとめ速報", lines[1]))
             and (sum(bool(re.search(r"[!?]|(?:だろ|けど(?:ね)?|かね|模様|だよ|と思う)[。…]*$", line))
                      for line in lines[2:]) >= 5
                  or ("地球防衛軍" in lines[1] and "EDF" in lines[0]
                      and sum(bool(re.search(r"[!?]|だろうか|たっけ|けどね", line)) for line in lines[2:]) >= 3))
             and (distinct(re.compile(r"アーマー|輸送船|ドローン|リバシュ|コスモノーツ|ビークル|出オチ"), text) >= 4
                  or distinct(re.compile(r"ガシャ|音ゲー|恒常|ボーダー|コミュ|イベ曲|ライブ|チケット|ロードマップ"), text) >= 4)
             and not re.search(r"(?m)^(?:本文|執筆|文[:：]|投稿日時|レビュー本文|出典URL|ID[:：]|\d+[:：])", text))
    if 300 <= len(text) <= 2400 and re.fullmatch(r"/[a-z]{2}/video/[0-9]{4,8}/?", path):
        page("bulk-scraped-media-synopsis-with-corrupted-translation-shell",
             bool(re.search(r"(?m)^平均 スコア [0-9.]+ / [0-9.]+$", head))
             and len(re.findall(r"(?m)^(?:ティポ|状態|EPS) [^\n]{1,30}$", head)) >= 2
             and bool(re.search(r"すべての概要はサードパーティのサイトから取得されています", text[-650:]))
             and bool(re.search(r"スペルミス、切断されたテキスト|ロボットを回すとき", text[-650:])))
    if 900 <= len(text) <= 3800:
        sales_bullets = re.search(r"(?m)^こんなふうにガラッと生活が変わりました!$\n"
                                 r"(?P<benefits>(?:^・[^\n]{4,140}\n){5,12})", text)
        page("buyback-endorsement-with-contradictory-persona-and-pasted-benefit-bullets",
             bool(sales_bullets) and len(re.findall(r"(?m)^・[^\n]{4,130}$", text)) >= 19
             and distinct(re.compile(r"不用品買取|出張査定|買取実績|査定金額|出張買い取り|処分費用"), text) >= 5
             and bool(re.search(r"(?:パパ|お父さん)です。.{2,22}(?:親子|家族).{0,9}暮らし", head))
             and bool(re.search(r"女性のひとり暮らしなので", text[sales_bullets.end():]))
             and bool(re.search(r"(?m)^・[^。\n]{0,7}(?:フレンチ|イタリアン)$", sales_bullets["benefits"]))
             and bool(re.search(r"費用が高く[^。\n]{2,32}買えなくなった", sales_bullets["benefits"])))
    if 900 <= len(text) <= 9500:
        closing = text[-2100:]
        page("unrelated-article-padded-with-repeated-instant-loan-campaign",
             bool(re.search(r"(?m)^これも面白いキャッシングニュース.{0,20}闇金で金を借りて", closing))
             and distinct(re.compile(r"ブラック融資|ソフト闇金|ソフトヤミ金|即日融資|キャッシング"), closing) >= 4
             and len(re.findall(r"(?m)^ブラック融資[^\n]{8,50}$", closing)) >= 4
             and (len(re.findall(r"(?m)^ソフト(?:闇金|ヤミ金)$", closing)) >= 4
                  or distinct(re.compile(r"ビットキャッシングにお任せ|闇金イズにご連絡|闇金イズならだれでも"), closing) >= 2)
             and distinct(re.compile(r"国際|政府|感染|山火事|映画|動画|芸能|フォロワー|大統領|俳優|インフルエンサー"),
                          text.split("これも面白いキャッシングニュース", 1)[0]) >= 1)
        page("moving-quote-doorway-with-copied-provider-ads-and-spun-advice",
             bool(re.match(r"引越し侍は、全国の引越し業者の中から", head))
             and "ズバット引越し比較" in head
             and bool(re.search(r"2011年8月実施の利用者アンケート.{0,220}LIFULLだけのお得なプレゼント",
                                text[:1200], re.S))
             and text.count("引越し業者") >= 8
             and distinct(re.compile(r"息づいていますよね|額面の違い|同一ではありません|運輸数の豊富な"
                                     r"|引き移る住宅|コンディションを通信会社|最終現場に近づくほど|完全タダなので"
                                     r"|頼れる方の頭数|さりとて、引越し"), text[650:]) >= 3)
    if 420 <= len(text) <= 4200:
        page("clipped-machine-localized-mobile-data-offers-in-multiple-languages",
             text.count("トラフィックカード") >= 7
             and distinct(re.compile(r"3つの演算子|キャリアの交通カード|費用対効果が高い|"
                                     r"トラフィックカードの関税パッケージ|どのように多くのお金を充電|総てのトラフィック"), text) >= 3
             and bool(re.search(r"\.\.\.\s*[^\n]{0,65}(?:總流量|流量充值|手機流量|流量套餐)", text))
             and bool(re.search(r"流量(?:套餐|不夠)[\s\S]{0,220}\.\.\.\s*多くのユーザー", text)))
        page("vehicle-trade-in-paragraphs-with-corroborated-thesaurus-rewrite",
             bool(re.search(r"車検証を整えて臨席(?:すべきです|しましょう)", text))
             and bool(re.search(r"出張買取(?:査定)?(?:自体)?は(?:無料|ただ)です", text))
             and distinct(re.compile(r"競合入札|下取りに出す|査定額そのもの|買取相場|利用料金を申しだされる|"
                                     r"費用などを強要される|中古車一括査定|提携している車買取"), text) >= 3)
        page("mechanical-topic-replacements-in-a-trading-tutorial",
             bool(re.search(r"バーチャル体験できる[^。\n]{2,15}トレード", text))
             and bool(re.search(r"確定申告[\s\S]{0,450}損益通算", text))
             and len(re.findall(r"退会方法トレード|動画サイト(?:素人女優|アイドル)|自動売買アイドル|"
                                r"有料サイトグラビアアイドル|FXセクシー女優", text)) >= 6)
    if 230 <= len(text) <= 1250 and re.match(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?$", path):
        duplicate_question = re.search(r"(?m)^([^\n。!?]{6,38}に関する質問)[ \t]*\n"
                                       r"[^\n]{15,160}\n\1[ \t]*\n([^\n]{40,360})$", text)
        page("clipped-electronics-question-under-repeated-unrelated-product-keyword",
             bool(duplicate_question) and bool(re.search(r"CDレコーダー|ダブルCDタイプ|HDDに記録", duplicate_question[2]))
             and bool(re.search(r"(?m)^→[^\n。]{4,45}$", text))
             and bool(re.search(r"ダンベル|筋肉をつけたい|パンプアップ|筋トレ|バーンマシーン", text[:700]))
             and text.rstrip().endswith("..."))
    if 180 <= len(text) <= 2400 and re.fullmatch(r"/(?:what-(?:is|are)|how-do-you)(?:-[a-z]{2,22}){3,12}/?", path):
        translated_title = re.match(r"([^\n。]{5,95}(?:ですか|しましたか|ますか)\?)\s*\n"
                                    r"(歴史|ワールドビュー|化学|企業財務|科学|健康)\s*/\s*2022[ \t]*\n", text)
        if translated_title:
            title_subject = re.split(r"の(?:意味|違い|理由|方法)は", translated_title[1], maxsplit=1)[0]
            title_terms = set(re.findall(r"[一-龯ァ-ヶー]{2,}", title_subject)) - {"何", "何年", "誰"}
            if pair := re.fullmatch(r"([一-龯]{1,8})と([一-龯]{1,8})", title_subject):
                title_terms.update(pair.groups())
            translation = text[translated_title.end():]
            page("machine-localized-answer-attached-to-an-unrelated-question-and-category",
                 bool(title_terms) and not any(term in translation for term in title_terms)
                 and bool(re.search(r"^[^。\n]{2,65}(?:は|のレベルが)[^。\n]{6,140}", translation))
                 and bool(re.search(r"と考えられています|可能性が(?:あり|あると)|発生する病状|"
                                    r"認証する最良の方法|によって製造された製品|(?:出荷|製品)には", translation)))
    if 220 <= len(text) <= 1500 and re.fullmatch(r"/cat[0-9]{4,6}/post_[0-9]{1,4}\.html?", path):
        page("wedding-planning-article-with-unrelated-stock-image-on-counterfeit-outlet",
             bool(re.search(r"coach|outlet|sneaker|designerbag", host, re.I))
             and bool(re.match(r"([^\n。]{8,70})\n\1[、,]", text))
             and distinct(re.compile(r"結婚式余興|フラッシュモブ|式場|招待客|代行会社|友人の協力"), text) >= 3
             and bool(re.search(r"(?m)^参照\s*:\s*(?:https?://)?[1-4]\.bp\.blogspot\.com/[^\n]+"
                                r"/(?:sweets|vegetable|food)[_-][a-z_0-9-]+\.(?:png|jpe?g)\s*$", text)))
    if 500 <= len(text) <= 5200 and re.fullmatch(r"/[a-z]{7,22}/[a-z]{8,24}[0-9]{6}\.html?", path, re.I):
        page("retailer-copy-on-random-dictionary-item-route",
             (distinct(re.compile(r"在庫確認|正規取扱店|在庫の変動|あんしんプラス|初期不良補償制度|紛失補償制度|"
                                  r"国内買付|追跡サービス付き|海外買付|関税・送料込み|関税手続き"), text) >= 5
              and distinct(re.compile(r"サイズチャート|■仕様・素材|■品番|■商品説明|■カラー|本物保証制度"), text) >= 2)
             or ("室本鉄工" in text[-500:] and distinct(re.compile(r"コンプレッサ|圧縮空気|空気工具|替刃"), text[-550:]) >= 3
                 and distinct(re.compile(r"在庫の変動|在庫を確認|在庫状況|ご注文前|BUYMA|サイズチャート|"
                                         r"買い付け|ジョガーパンツ|スニーカー|ポリエステル"), head) >= 3)
             or ("ニュースレターの内容は" in text and "著作権は引用元" in text
                 and "ふるさと納税" in text[-800:] and "全機種対応" in text[-800:]
                 and "スマホケース" in text[-800:] and bool(re.search(r"-[0-9]{6,10}\b", text[-200:]))))
    if 180 <= len(text) <= 1500 and re.fullmatch(r"/view/\d{5,10}\.html?", path):
        page("automatically-collected-video-copy-with-unattributed-synopsis-and-scraper-notice",
             bool(re.search(r"(?m)^友情提示:请勿长时间观看影视", text[-500:]))
             and bool(re.search(r"(?m)^免责声明:本站所有内容均来源于互联网相关站点自动搜索采集", text[-500:]))
             and bool(re.search(r"(?m)^相关事项:如果本站采集的链接地址", text[-500:]))
             and bool(re.search(r"アニメ化|テレビアニメ|放送開始|公開中|作品紹介|キャラクター", text[:800])))
    diary_date = re.match(r"/(20\d{2})/\d{1,2}/\d{1,2}/?$", path)
    if diary_date and 260 <= len(text) <= 2800:
        catalogue = list(re.finditer(r"(?m)^著者[^\s。]{50,180}(?:。[^\s。]{2,60})?$", text))
        later = [y for y in re.findall(r"(?m)^.{5,75}\b(20\d{2})年\s*\d{1,2}月号$", text)
                 if int(y) >= int(diary_date[1]) + 5]
        page("dated-personal-blog-with-much-later-joined-catalogue-credits",
             len(catalogue) >= 2 and len(later) >= 2 and "。" in text[:catalogue[0].start()]
             and not re.search(r"(?m)^(?:追記|更新|参照|関連商品|参考文献)", text))
    if 180 <= len(text) <= 1900 and re.search(r"/image[-_]?\d{1,6}/?$", path):
        clipped_junctions = re.findall(r"(?m)\.{3}[^。\n]{9,85}\n", text)
        page("empty-image-attachment-with-clipped-and-merged-headline-teasers",
             len(clipped_junctions) >= 4 and len(re.findall(r"(?m)^.{10,140}\.{3}", text)) >= 4
             and not re.search(r"(?m)^(?:写真|図版|キャプション|関連記事|記事一覧)[ :：]", head))
    if 350 <= len(text) <= 2800 and re.fullmatch(r"/word/\d{3,8}/?", path):
        handles = set(re.findall(r"(?m)^@[a-zA-Z0-9_]{2,30}$", text))
        page("keyword-only-landing-assembled-from-disconnected-social-posts",
             len(handles) >= 9 and len(re.findall(r"(?m)^.{2,23}\n@[a-zA-Z0-9_]{2,30}$", text)) >= 8
             and len(re.findall(r"(?m)^.{1,40}\n@[a-zA-Z0-9_]{2,30}\n[^\n]{1,32}\n@[a-zA-Z0-9_]{2,30}$", text)) >= 2
             and not re.search(r"(?m)^(?:執筆|取材|投稿者|記事本文|プロフィール|転載元)", head))
    if 850 <= len(text) <= 4000 and re.fullmatch(r"/(?:pk/[^/]+|kwd\.php)/?", path):
        continuations = re.findall(r"\.{3}\s*(more|»続きを読む)", text, re.I)
        page("keyword-page-with-unlabelled-clipped-source-paragraphs",
             (len(continuations) >= 4 or len(continuations) >= 3 and len(set(continuations)) >= 2)
             and head.count("。") >= 3 and not re.search(r"記事一覧|検索結果|関連記事|新着記事", head[:100]))
    if source_power := re.search(r"(?mi)^动\s*力[ :：]+(\d{2,3})\s*V(?:AC)?\b", text):
        page("bilingual-catalogue-with-incompatible-power-specs",
             distinct(re.compile(r"动\s*力|工作压力|储\s*油\s*量|吐出油量|重\s*量"), text) >= 4
             and not re.search(r"別売|選択可能|によって異な|切り替え式|变压器", text)
             and any(power != source_power[1] for power in
                     re.findall(r"(?i)単相\s*(\d{2,3})\s*V電源対応", text[source_power.end():])))
    page("title-repeated-in-pitch", BOOK.search(text) and len(IN_MARKETING.findall(text)) >= 3
         and distinct(IN_MARKETING, text) >= 2 and bool(audit.PUBLISHER_LINKS.search(text)))
    page("app-installer-slot", bulk_search and APP_PITCH.search(text) and (
         search_count >= 2 or len(audit.SEARCH_DATE.findall(text)) >= 2 or topics >= 2))
    page("song-download-slot", SONG_PITCH.search(text) and (bulk_search or search_count >= 2))
    page("dating-platform-and-audience", (
         re.fullmatch(r"/(?:[^/]+/)?deai\d+/?", path)
         and (len(DATING_PITCH.findall(text)) + len(DATING_ACTION.findall(text)) >= 3
              or text.count("出会") >= 5 and len(DATING_PITCH.findall(text)) >= 1
              or text.count("出会") >= 3 and any(
                  count >= 3 for count in Counter(
                      re.findall(r"([ァ-ヶ]{2,10}[ぁ-ゖ]{1,4})(?=で)", text)).values()))
         or len(DATING_PITCH.findall(text)) >= 6
         and len(re.findall(r"[ぁ-ゖァ-ヶ一-龯]{2,9}(?:出会い|女性|人妻|主婦)", text)) >= 10))
    page("retailer-query-and-count", RETAIL_RESULT.search(text) and (
         bulk_search or SYNTHETIC_PATH.search(path) or topics >= 2))

    testimonials = defaultdict(set)
    for author, quote in gate.TESTIMONIAL.findall(text):
        testimonials["".join(quote.split())].add(author)
    page("testimonial-same-text-different-name", any(len(names) >= 2 for names in testimonials.values()))

    localized = {
        "unexpanded-numeric-placeholder": list(structural.numeric_placeholder_spans(raw)),
        "heading-splits-word": list(structural.inserted_heading_spans(raw)),
        "impossible-calendar-values": [
            m.span() for m in re.finditer(r"[１２12][０-９0-9]{3}\s*年\s*[１-９1-9][０-９0-9]{1,3}\s*月", raw)
            if gate.BROKEN_MONTH.search(normalize(m[0]))
        ],
        "replacement-character-runs": [m.span() for m in gate.REPLACEMENT.finditer(raw)],
        "film-affiliate-slot": [
            m.span() for m in re.finditer(r"[^。！？\r\n]{1,220}", raw)
            if FILM_PITCH.search(normalize(m[0]))
        ] if distinct(FILM_PITCH, text) >= 2 else [],
    }
    findings.update((pattern, spans) for pattern, spans in localized.items() if spans)

    # Scraped catalogues, generated help archives, and doorways found after the inventory.
    review_runs = len(PRODUCT_VOICE.findall(text))
    page("scraped-review-aggregation", len(REVIEW_JOIN.findall(text)) >= 3 and review_runs >= 6
         or field_count >= 3 and len(REVIEW_JOIN.findall(text)) >= 2 and review_runs >= 3
         or SYNTHETIC_PATH.search(path) and len(MARKET_LISTING.findall(text)) >= 3)
    page("synthetic-catalog-montage", len(PRICE_CARD.findall(text)) >= 2
         or field_count >= 3 and (
             len(MARKET_LISTING.findall(text)) >= 2 or
             SYNTHETIC_PATH.search(path) and len(set(REVIEW_JOIN.findall(text))) >= 2)
         or SYNTHETIC_PATH.search(path) and GIFT_OPENING.search(head)
         and len(MARKET_SPECS.findall(text)) >= 3 and len(paragraphs) >= 5)
    page("local-moving-route-template", bool(LOCAL_MOVING.search(head)) and
         len(LOCAL_MOVING.findall(text)) >= 3 and distinct(BATCH_OFFER, text) >= 3
         and re.search(r"/(?:area_[a-z]+|pref_[a-z]+)/", path))
    page("search-query-directory-montage", DIRECTORY.search(head) and
         (len(re.findall(r"(?m)^[（(][^）)\n]{6,36}[）)]", text)) >= 4
          or len(re.findall(r"(?m)^[（(][^）)\n]{4,22}[）)]", text)) >= 2 and notices >= 4)
         and len(text) >= 700)
    page("repeated-broken-literal-phrases", distinct(BROKEN_LITERAL, text) >= 2)
    page("stitched-broken-inline-terms", distinct(BROKEN_INLINE, text) >= 3 and (
         distinct(BROKEN_MONTAGE, text) >= 1 or SYNTHETIC_PATH.search(path)
         and (field_count >= 1 or len(SERP_COUNTS.findall(text)) >= 2)))
    page("trending-query-in-unrelated-blog", UNRELATED_BLOG_TITLE.search(head)
         and "知恵袋" in text and len(re.findall(r"関連動画|この情報|こちらをご確認|悩みを解消", text)) >= 2)
    page("unrelated-services-on-generated-directory", path.endswith("/index.php") and
         {"category_id", "category_sub_id"} <= {p.split("=", 1)[0] for p in address.query.split("&")}
         and distinct(DESIGN_SERVICE, head) >= 2 and distinct(CONSULT_SERVICE, text) >= 2)
    detached_numbers = DETACHED_SENTENCE_NUMBER.findall(text) if NUMBERED_SNIPPET_ROUTE.fullmatch(path) else []
    page("sentence-numbered-snippet-montage", len(detached_numbers) >= 4
         and len(set(detached_numbers)) >= 3 and "参考文献" not in text)
    if (ranking := RANKING_REVIEW_HEAD.search(text)) and (credit := RANKING_REVIEW_LINK.search(text)):
        glued_review = re.match(r"。?[一-龯ぁ-ゖァ-ヺ]", text[credit.end():credit.end() + 2])
        # The same montage also survives when the affiliate credit keeps its newline.
        clipped_review = (
            text.startswith("。") and 16 <= ranking.start() <= 115
            and text[:ranking.start()].count("。") >= 2
            and bool(re.match(r"\s*また(?:も|ぜひ)?利用(?:したい|します|させて)", text[credit.end():]))
        )
        page("single-affiliate-ranking-review-join", text.count("。") >= (6 if glued_review else 8))
        page("short-affiliate-ranking-card-with-fused-shopping-reviews",
             170 <= len(text) <= 500 and len(text.splitlines()) <= 8 and (glued_review or clipped_review)
             and text.count("。") >= 3 and re.fullmatch(r"/entry/20\d{2}/\d{2}/\d{2}/\d{6}/?", path))
    elif RANKING_REVIEW_HEAD.search(head):
        page("single-affiliate-ranking-review-join",
             "ちょっとお待ちを!詳しく見る前に!" in head
             and "詳しくは下記↓をご覧下さいませ。" in head
             and "キャンペーン中なのでお早めに" in head and text.count("。") >= 8)
    page("regional-search-doorway-with-pasted-office",
         "動画を見ます" in text and "詳細について" in text
         and "当事務所" in text and "事務所所在地" in text
         and bool(re.search(r"(?:事務所所在地|事務所所在地のご案内)\s*〒?\s*\d{3}-\d{4}", text))
         and len(re.findall(r"会社設立|登記申請|開業支援", head)) >= 4)
    trading_tail = text[-1800:]
    page("trading-signal-pitch-on-translated-article",
         bool(re.search(r"Telegram(?:の)?(?:チャネル|チャンネル)", trading_tail, re.I))
         and trading_tail.count("トレーディングシグナル") >= 2
         and bool(re.search(r"\d+%から\d+%の利益|短期間で巨額の利益", trading_tail))
         and "VIP" in trading_tail
         and bool(re.search(r"失効した患者|令状のない患者|確かに.{0,12}(?:導入|利用します)", text[:max(0, len(text) - 400)])))
    sale_titles = Counter(re.findall(
        r"(?m)^【[^】\n]{0,32}(?:送料無料|バーゲン)[^】\n]{0,20}】[^\n。]{15,180}$", text))
    page("repeated-sale-title-inside-pasted-clinic-article",
         any(count >= 3 for count in sale_titles.values())
         and bool(re.search(r"当サイトは[^。\n]{2,55}(?:医院|クリニック)[^。\n]{0,24}が運営", text))
         and "診療時間" in text and "関連記事" in text)
    diary_wrapper = re.match(
        r"20\d{2}年\d{1,2}月\d{1,2}日の(?P<author>[^\n]{2,24})のブログ\s*\n"
        r"(?P<title>(?P=author)の「[^\n]{1,100}」)\s*\n"
        r"本日次のブログは(?P=author)です[。.]?\s*\n"
        r"(?:[^\n]{1,90}\n(?P<official>https?://[^\n ]+/official/diary/[^\n ]+)\n)?"
        r"ブログの概要\s*\n", head)
    page("full-diary-in-republication-template", diary_wrapper is not None
         and len(text) - diary_wrapper.end() >= 220
         and (diary_wrapper["official"] or bool(re.search(
             r"(?m)^引用元:\s*" + re.escape(diary_wrapper["title"]) + r"\s*\Z", text))))
    page("engagement-gated-clickbait",
         bool(re.search(r"続きを見るには.{0,10}いいね[!！]?[』」]?をクリック", text))
         and bool(re.search(r"いいねを押すと.{0,12}ボタンが表示", text))
         and bool(re.search(r"(?:話題になっています|驚愕の真相|閲覧注意)", head)))
    local_listing = re.search(
        r"(?m)^([一-龯々ヶケ]{2,8})[ \t〜~:：]{0,5}(?:割り切り出会い掲示板|の出会いを調査)", text)
    if local_listing:
        local_query = re.escape(local_listing[1]) + r"の(?:割り切り|出会い)"
        page("regional-dating-query-in-unrelated-fragments",
             len(re.findall(local_query, text)) >= 7
             and len(re.findall(r"(?:でした|ました|です|ようです|たら|です[)）])" + local_query, text)) >= 2)
    market_footer_start = text.rfind("Source:")
    if market_footer_start > 0:
        footer = text[max(0, market_footer_start - 800):market_footer_start]
        footer_links = Counter(re.findall(r"https?://[^\s<>()]+", footer))
        page("reposted-market-news-with-duplicated-conversion-footer",
             "暗号通貨" in text and "時価総額" in text
             and footer.count("無料でLINE") >= 2 and "メルマガ" in footer
             and sum(count >= 2 for count in footer_links.values()) >= 2)
    paywall = re.search(r"この記事は会員限定です.{0,30}続きをお読みいただけます", text)
    if paywall:
        article = re.search(r"https?://([a-z0-9.-]+)/[^\s]+", text[:paywall.start()], re.I)
        if article and article[1].lower().removeprefix("www.") != host.removeprefix("www."):
            before_paywall = text[article.end():paywall.start()]
            after_paywall = text[paywall.end():]
            page("external-article-with-copied-paywall",
                 "ログイン" in after_paywall[:300] and "残り" in after_paywall[:200]
                 and any(clause.strip() + "。" in after_paywall
                         for clause in before_paywall.split("。") if 20 <= len(clause.strip()) <= 200))
    placeholder = re.search(
        r"(?im)^copyright[ @©].{6,160}(?:rights reserved[.]?)\s*\n"
        r"(?P<body>吾輩は猫である。名前はまだない。どこで生[ま]?れたか)", raw)
    if placeholder:
        findings["literary-placeholder-after-site-footer"] = [(placeholder.start("body"), len(raw))]
    if re.fullmatch(r"/(?:feed|site_id)/\d+/?", path):
        feed_lines = [line.strip() for line in text.splitlines() if line.strip()]
        headline_markers = re.compile(r"[!?…]|w{3,}|笑{2,}|[←→]")
        page("headline-only-feed-montage",
             len(feed_lines) >= 20 and all(len(line) < 140 for line in feed_lines)
             and sum("。" in line for line in feed_lines) * 5 <= len(feed_lines)
             and sum(bool(headline_markers.search(line)) for line in feed_lines) * 2 >= len(feed_lines))
        feed_credits = re.findall(
            r"(?m)^(?:[^\n。！？]{2,29}(?:ちゃんねる|速報|通信|アンテナ|備忘録)|"
            r"【[^】\n]{2,16}】(?:これは面白い|これはすごい)[^\n]{1,16}。)$", "\n".join(feed_lines[:12])
        )
        board_credits = sum(bool(re.fullmatch(
            r"(?:easterEgg|日本人難民|怒り新党|すまいる\([^)]{2,10}\)ぶろぐ|"
            r"スカッと速報(?: - .{4,30})?)", line, re.I)) for line in set(feed_lines[:14]))
        page("numeric-feed-with-detached-headlines-and-no-article",
             (path.startswith("/site_id/") and len(feed_lines) >= 26
              and sum(len(line) >= 110 for line in feed_lines) <= 2
              and sum(bool(re.search(r"^【(?:画像|動画|速報|朗報|悲報|写真|音声)", line))
                      for line in feed_lines) >= 6)
             or (len(feed_lines) >= 30
              and sum(len(line) >= 100 for line in feed_lines) <= 5
              and sum(bool(re.search(r"[!?…]|\.{3}|w{2,}|^画像[>＞]", line)) for line in feed_lines)
                  * 3 >= len(feed_lines)
              and sum(bool(re.search(r"^[^。!?\n]{2,35}(?:速報|まとめ|ちゃんねる|おかると|アンテナ)$", line))
                      for line in feed_lines[:18]) >= 2)
             or (len(feed_lines) >= 23 and sum(len(line) >= 145 for line in feed_lines) <= 1
              and ((11 * sum(line.count("。") >= 2 for line in feed_lines) <= len(feed_lines) + 5)
                   or (len(feed_lines) >= 38
                       and sum(line.count("。") >= 3 for line in feed_lines) * 8 <= len(feed_lines)
                       and sum(bool(re.search(r"速報|まとめ|ちゃんねる|備忘録|事件簿|通信|ねた|アンテナ", line))
                               for line in feed_lines[:20]) >= 3))
              and sum(bool(re.search(r"[→…!?]|\.{3}|w{2,}|攻略|速報|まとめ", line))
                      for line in feed_lines) >= max(4, len(feed_lines) // 12))
             or (len(feed_lines) >= 26 and distinct(re.compile(r"[!?…]|\.\.\.|w{2,}|[←→]"), text) >= 2
                 and len(set(feed_credits)) >= 3 and max(map(len, feed_lines)) < 140
                 and sum(len(re.findall(r"。+(?=[^。]|$)", line)) >= 2 for line in feed_lines) <= 3)
             or (len(feed_lines) >= 12 and all(len(line) <= 150 for line in feed_lines)
                 and re.search(r"(?m)^[^。！？\n]{3,55}(?:攻略まとめ速報|攻略まとめ班|ゲーム速報|攻略速報)\s*$", text)
                 and sum(bool(re.search(r"ガチャ|攻略|熟度|ミッション|周回|育成|レイド|キャラ|ログボ", line))
                         for line in feed_lines) >= 6
                 and sum(line.endswith("。") for line in feed_lines) * 5 <= len(feed_lines))
             or (20 <= len(feed_lines) <= 32 and max(map(len, feed_lines)) <= 100
                 and bool(re.search(r"(?m)^(?:なんJ\s+PRIDE|わんこーる速報|暇つぶしニュース|"
                                    r"まとめアンテナ|キニ速)\s*$", "\n".join(feed_lines[:8])))
                 and sum(bool(headline_markers.search(line)) for line in feed_lines) >= 7
                 and sum(line.count("。") >= 2 for line in feed_lines) <= 1)
             or (len(feed_lines) >= 30 and board_credits >= 3
                 and sum(len(line) >= 120 for line in feed_lines) <= 2
                 and sum(bool(headline_markers.search(line)) for line in feed_lines) >= 6))
    for locality, hits in Counter(re.findall(
            r"([一-龯々ヶケ]{2,8})の出会い(?=[。!…\s]|$)", text)).items():
        if hits >= 4 and text.count(locality + "する") >= 2 and text.count(locality) >= 12:
            page("place-used-as-verb-in-keyword-spam", True)
            break
    product_titles = Counter(re.findall(
        r"(?m)^[^\n。]{8,120}(?:ハンドバッグ|長財布|ジャケット|スニーカー|コントローラー)[^\n。]{0,25}$", text))
    page("repeated-product-title-in-copied-sports-article",
         any(hits >= 3 for hits in product_titles.values())
         and len(re.findall(r"ホークス|バファローズ|優勝|リーグ|NPB|プロ野球|延長戦|先発", text)) >= 8
         and len(re.findall(r"(?m)^\|[^\n]{0,40}\|\|[^\n]*(?:バッグ|タンス|靴|家具|ベッド|流し台)", text)) >= 2)
    rare_import = re.search(r"国内ではなかなか手にはいらない\s*希少なデザイン", text)
    if rare_import:
        catalog_tail = text[rare_import.end():]
        page("unrelated-catalog-after-rare-import-pitch",
             "未発売品" in catalog_tail[:220] and "お取り寄せ" in catalog_tail[:250]
             and sum(len(line) >= 95 for line in catalog_tail.splitlines()) >= 3
             and distinct(re.compile(r"レンズキャップ|成犬用|フライパン|業務用|CDプレーヤー|焼物皿"), catalog_tail) >= 3)
    supplement_intro = re.search(r"コラーゲン|サプリメント|栄養ドリンク", head)
    if supplement_intro:
        speakers = Counter(re.findall(r"(?m)^([一-龯々ぁ-ゖァ-ヶ]{2,5})「", text))
        page("staged-dialogue-leading-to-supplement-pitch",
             sum(turns >= 4 for turns in speakers.values()) >= 2
             and "カロリー" in text and bool(re.search(
                 r"こちらで.{0,36}(?:コラーゲン|サプリメント|栄養ドリンク).{0,20}ご紹介", text[-300:])))
    page("anonymous-forum-opening-in-feed-wrapper",
         bool(re.search(r"(?m)^1\.\s*匿名@ガールズちゃんねる\s*$", head))
         and bool(re.search(r"(?m)^20\d{2}/\d{2}/\d{2}\([^\n]{1,4}\) \d{2}:\d{2}:\d{2}\s*\n"
                            r"続きを読む\s*\nSource:\s*がーるずレポート", text)))
    news_end = re.search(r"(?m)^★☆★[ \t]*(?:\r?\n|$)", raw)
    if news_end:
        intro, bait = normalize(raw[:news_end.start()]), normalize(raw[news_end.end():])
        if (re.search(r"(?:新聞|通信).{0,25}配信", intro) and "headlines.yahoo.co.jp/" in intro
                and len(re.findall(r"一括(?:見積り?|申し込み?|登録)|売却査定|下取り|買取り", bait)) >= 5
                and re.search(r"単語の羅列|いった調べ方|キーワードを", bait)):
            findings["news-reprint-before-vehicle-search-keyword-block"] = [(news_end.end(), len(raw))]
    page("full-personal-post-with-reprint-credit",
         path.startswith("/個人ブログ/") and len(text) >= 420
         and bool(re.search(r"(?m)^掲載元:[^\n]{8,180}\s*\n"
                            r"※各著作権は各ブログ運営者様に帰属します[。.]?\s*\Z", text)))
    page("translated-tutorial-with-reversed-dimensions",
         bool(re.search(r"/[^/]*(?:consejos|trucos|presentaciones)-[^/]+", path, re.I))
         and bool(re.search(r"垂直線の場合:[^\n]{5,120}「高さ」を「0」", text))
         and bool(re.search(r"水平線の場合:[^\n]{5,120}「幅」を「0」", text)))
    page("foreign-gambling-brand-repeated-in-copied-prose",
         len(re.findall(r"(?:\d{2,4}bet|[a-z]{2,12}博彩)[^\n。]{0,40}(?:体育在线投注|唯一授权牌照)", text, re.I)) >= 2)
    page("adult-locality-keyword-in-unrelated-opening-hours",
         "感染" in text and "方針" in text and "内閣" in text
         and bool(re.search(r"夜の([一-龯々]{2,8})のセフレは\d{1,2}時まで", text))
         and text.count("セフレ") >= 3)
    page("dating-testimonial-joined-to-local-news",
         bool(re.search(r"[一-龯々]{2,8}市(?:の近く|の近辺).{0,45}セフレ", head))
         and bool(re.search(r"(?m)^.{0,35}(?:事故|火災).{0,35}(?:避難訓練|周辺住民)", text[180:]))
         and distinct(re.compile(r"消防|避難場所|避難訓練|住民「|市の職員"), text) >= 3)
    page("pet-service-definition-in-generated-diary",
         path.endswith(".html") and "この記事へのトラックバック一覧" in text
         and bool(re.search(r"ペット葬儀とは.{8,110}サービスです", head))
         and bool(re.search(r"ネオペットの勉強.{0,180}ネオペットの学習", text, re.S)))
    retail_heading = head[:190]
    page("retail-keyword-heading-over-copied-fiction",
         bool(re.search(r"/(?:res/)?file/\d{8}/\d{10,}\.html?$", path))
         and any(hits >= 3 for hits in Counter(re.findall(
             r"(?:プラダ|ルイヴィトン|シャネル|グッチ)(?:財布|カバン|バッグ)(?:新作|激安|通販)", retail_heading)).values())
         and len(re.findall(r"[一-龯々]《[ぁ-ゖ]{1,10}》", text)) >= 3 and len(re.findall(r"「", text)) >= 3)
    if reprint_end := re.search(r"著作権保護のため.{0,15}記事の一部のみ表示", text):
        racing_footer = text[reprint_end.end():]
        page("copyright-limited-reprint-with-racing-signup",
             bool(re.search(r"(?m)^Source:[^\n]{4,100}\s*\n", racing_footer))
             and "万馬券" in racing_footer and "無料登録" in racing_footer)
    page("sports-report-in-source-only-wrapper",
         bool(re.fullmatch(r"/sp/archives/\d+/?", path))
         and bool(re.match(r"出典元:[^\n]{6,120}\n", head))
         and distinct(re.compile(r"引退会見|内野手|球団|本塁打|打点|チーム|リーグ|試合|選手権|準決勝"), text) >= 5
         and text.count("。") >= 6)
    page("generated-items-route-with-products-inside-prose",
         bool(re.search(r"/(?:get/)?[a-z0-9_-]{8,}items\.html?$", path, re.I))
         and len(re.findall(r"(?m)^(?:[A-Za-z][A-Za-z ]{2,40} - |新品未使用|未使用品|限定品)", text)) >= 4
         and text.count("。") >= 5
         and distinct(re.compile(r"けど|くなっ|ちゃう|わたし|あの人|だったら"), text) >= 3)
    market_samples = set(re.findall(r"https?://([a-z0-9.-]+)/sample/([A-Z0-9_-]{5,})", text))
    market_purchases = set(re.findall(r"https?://([a-z0-9.-]+)/buy/([A-Z0-9_-]{5,})", text))
    page("syndicated-market-report-with-offsite-sales",
         any(publisher.removeprefix("www.") != host.removeprefix("www.")
             for publisher, _ in market_samples & market_purchases)
         and "サンプルのPDFコピーを入手" in text
         and "このレポートを" in text and "私たちに関しては" in text)
    # Same-host archive witnesses document this path as a third-party story mirror.
    page("witnessed-personal-story-mirror",
         host.removeprefix("www.") == "hessionchiro.com"
         and bool(re.fullmatch(r"/archives/cat\d+-\d+\.html", path))
         and len(text) >= 400 and text.count("。") >= 5)
    page("trading-software-pitch-with-diary-filler",
         "マニュアルの内容をみてみる" in head
         and "買いシグナル" in text and "売りシグナル" in text
         and distinct(re.compile(r"FX初心者|同じように稼げる|全自動|ポジポジ病"), text) >= 2
         and bool(re.search(r"(?m)^.{0,30}温泉.{0,25}行ってきました", text)))
    if (diary_footer := text.find("この記事のトラックバックURL:")) > 0:
        before_footer = text[:diary_footer]
        page("stock-diary-with-car-link-keyword-list",
             "家族と" in head and bool(re.search(r"話(?:を)?していた", head))
             and distinct(re.compile(r"車検料金|売却廃車|フロントテーブル|の値段|パチンコ"), before_footer) >= 4)
    # The archived numbered routes carry a rotating third-party cinema review series.
    page("witnessed-cinema-review-mirror",
         host.removeprefix("www.") == "hotel-hangzhou.com"
         and bool(re.fullmatch(r"/\d{4,7}\.html", path))
         and len(text) >= 250 and "映画" in text and text.count("。") >= 4)
    fulfillment = re.compile(r"同梱不可|代引不可|返品種別[ABC]|送料込み|送料無料|在庫限り")
    if len(fulfillment.findall(text)) >= 5:
        repeated_cards = Counter(line.strip() for line in text.splitlines()
                                 if 18 <= len(line.strip()) <= 150 and "。" not in line)
        page("repeated-catalog-cards-inside-technical-article",
             any(amount >= 2 for amount in repeated_cards.values())
             and len(re.findall(r"(?m)^\d{1,2}-\d{1,2}(?:-\d{1,2})? [^\n]{2,70}", text)) >= 3
             and text.count("。") >= 10)
    page("empty-bibliography-and-spliced-reference-snippets",
         bool(re.fullmatch(r"/[a-z]{6,30}\d{4,}\.html", path, re.I))
         and text.count("『』") >= 3 and text.count("•") >= 5
         and len(re.findall(r"[\U0001f300-\U0001faff]", text)) >= 4
         and bool(re.search(r"参考文献 \[ *\]|アーカイブス.{0,25}閲覧", text)))
    page("local-fitness-pitch-after-unrelated-howto-bait",
         len(text) <= 550 and "パーソナルトレーニングは" in text and "出張しています" in text
         and bool(re.search(r"(?:移行する|交換する|移す)方法", head))
         and distinct(re.compile(r"マイル|スターバックス|航空券|ポイントカード"), head) >= 2
         and sum(line.count("、") >= 6 for line in text.splitlines()) >= 1)
    page("bare-forum-replies-on-third-party-site",
         "(5ch newer account)" in head
         and not re.search(r"(?:^|\.)(?:5ch\.net|2ch\.sc)$", host)
         and len(text.splitlines()) >= 12 and bool(re.search(r"(?m)^>>\d+\s*$", text)))
    if re.fullmatch(r"/archives/\d+\.html", path):
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        outlets = re.compile(r"まとめ|速報|ニュース|ちゃんねる|2ch|通信")
        article_like = sum("。" in line or len(line) > 120 for line in lines)
        outlet_counts = [sum(bool(outlets.search(line)) for line in lines[parity::2])
                         for parity in (0, 1)]
        page("alternating-headline-and-source-montage",
             len(lines) >= 60 and article_like * 5 <= len(lines)
             and abs(outlet_counts[0] - outlet_counts[1]) >= 12
             and len(lines) - len(set(lines)) >= 4)
    teaser_end = re.search(r"それでは(?:早速|さっそく).{0,16}(?:見ていきましょう|見てみましょう)[。!！]", text)
    if teaser_end:
        teaser, promotion = text[:teaser_end.start()], text[teaser_end.end():]
        page("unanswered-query-before-unrelated-clickthrough",
             len(text) <= 700 and "この記事を読むと" in teaser and teaser.count("?") >= 3
             and bool(re.search(r"(?:マスク|送料無料).{0,20}\d+円|\d+円で発売中", promotion))
             and "クリックしてね" in promotion and len(promotion.strip()) <= 130)
    page("rotating-review-bait-with-scam-objection",
         len(text) <= 550 and bool(re.search(r"今[、,]売れているっていう", head))
         and "試してみたくなっちゃった" in text and bool(re.search(r"私[、,]単純かな[?？]", text))
         and bool(re.search(r"インチキ[、,・]詐欺", text))
         and "詳しいレビューはあるのかな" in text and "絶対に試してみたい" in text)
    # Cached pages corroborate short, uncredited wire-style news on this archive.
    page("witnessed-uncredited-news-mirror",
         host == "doala37.hatenablog.com" and path.startswith("/entry/")
         and "90日以上更新していないブログ" in head and "引用をストックしました" in text
         and distinct(re.compile(r"報道陣|発表|方針|明らか|公開|開通|予定|教育委員会"), text) >= 3)
    if head.lstrip().startswith("0\n"):
        broadcast_credit = re.search(r"(?:テレビ東京|テレビ朝日|NHK|日本テレビ|TBS)(?:が(?:まとめた|取材)|の調べ)", text)
        page("broadcast-transcript-with-preserved-video-markup",
             broadcast_credit is not None and not host.endswith(("tv-tokyo.co.jp", "tv-asahi.co.jp",
                                                                  "nhk.or.jp", "ntv.co.jp", "tbs.co.jp"))
             and len(re.findall(r"(?m)^※[「『]", text)) >= 2
             and len(re.findall(r"#[一-龯ぁ-ゖァ-ヺ]{2,}", text[-220:])) >= 3)
    first_line = head.partition("\n")[0][:190]
    if 420 <= len(text) <= 2300 and re.search(r"(?m)^.{2,45}駅\([^)\n]{3,35}\)\s*$", head):
        page("dating-station-doorway-with-scraped-question-and-corrupted-answer",
             bool(re.search(r"(?mi)^pick\s*up\s*\n(?:【|\[)質問", text))
             and len(re.findall(r"(?m)^.*(?:おすすめ出会い系|©|All Right Reserved)", text)) >= 3
             and distinct(re.compile(r"はすべて琴ですか|私のやの|日付を持つことを払った|"
                                     r"をするたりを行う|パートナーは受胎|しょである|は成長します多くの"), text) >= 2)
    if 250 <= len(text) <= 1700 and "スーパーコピー時計" in text:
        page("counterfeit-watch-keyword-inside-broken-brand-review",
             bool(re.search(r"(?:時計製造|ウォッチ製造)の職人技", text))
             and len(re.findall(r"ムーブメント|ダイヤル|レトログラード|ムーンフェイズ", text)) >= 7
             and distinct(re.compile(r"はによって制御|昼も夜もポップアップ|難しいシンフォニー|"
                                     r"時計製造の伝統に追加|職人技と優れた高貴な"), text) >= 2)
    if 600 <= len(text) <= 6800 and re.fullmatch(r"/\d{3,9}\.html?", path):
        page("numbered-page-entirely-composed-of-keyword-matched-social-posts",
             text.startswith("関連ツイート\n")
             and len(re.findall(r"(?m)^— .{2,65}\(@[a-z0-9_]{2,30}\)\s+[a-z]+ \d{1,2}, 20\d\d$", text, re.I)) >= 7
             and len(re.findall(r"(?m)^https?://(?:www\.)?(?:twitter\.com|x\.com)/[^/\s]+/status/\d+\s*$", text)) >= 3
             and not re.search(r"(?m)^(?:本文|執筆|文|取材|編集部)[：:]", text))
    if 145 <= len(text) <= 700 and re.fullmatch(r"/[a-z]{3,16}-[a-z]{3,16}/[0-9]{3,8}[a-z]{3,8}[0-9]{4,15}\.html?", path):
        page("opaque-retail-page-with-unlabelled-news-after-product-description",
             distinct(re.compile(r"化粧箱|新品|着用可能|上級者|お使い頂けます|紳士用|検品"), text[:230]) >= 3
             and len(re.findall(r"(?m)^-\s*\n-\s*\n", text)) >= 2
             and distinct(re.compile(r"応募要項|取り組みを紹介|従業員や家族|コンクール|締切|ニュース"), text[-280:]) >= 3)
    dated_vendor_archive = (
        350 <= len(text) <= 5200 and re.fullmatch(r"/[a-z][a-z0-9_-]{1,25}/?", path)
        and re.fullmatch(r"m=(?:19|20)[0-9]{4}(?:[0-9]{2})?", address.query)
    )
    if dated_vendor_archive and not re.search(r"(?m)^(?:出典|執筆|取材|商品一覧|各店舗からのお知らせ)[ :：]", text):
        page("dated-archive-joins-independent-housing-energy-and-gaming-pitches",
             bool(re.search(r"住宅(?:会社|展示場)", head)) and "家づくり計画書" in head
             and bool(re.search(r"電気代.{0,35}(?:寄付|社会貢献)|再生可能エネルギー", text))
             and bool(re.search(r"ポーカー.{0,20}スロット|スロット.{0,20}ポーカー", text))
             and bool(re.search(r"仮想通貨.{0,30}景品|景品.{0,30}仮想通貨", text))
             and bool(re.search(r"お試し無料会員登録|登録用URL|メールアドレス入力欄", text)))
    if 950 <= len(text) <= 5200 and re.fullmatch(r"/[a-z][a-z0-9_-]{1,25}/?", path):
        page("dated-promotion-archive-collage-with-duplicated-product-introduction",
             bool(re.fullmatch(r"(?:paged=\d{1,6}&)?m=(?:19|20)\d{4}(?:\d{2})?(?:&paged=\d{1,6})?",
                               address.query))
             and len(first_line) >= 24 and text.count(first_line) >= 2
             and distinct(re.compile(r"保湿クリーム|シャンプー|高速Wi-Fi|土地の価格|WEBコーダー|"
                                     r"スパンデックス|加圧シャツ|エステメニュー|保育士の求人"), text) >= 5
             and not re.search(r"今月のまとめ|商品一覧|過去のお知らせ", text[:200]))
        page("dated-promotional-archive-with-unlabelled-unrelated-vendor-catalogue",
             bool(re.fullmatch(r"m=(?:19|20)[0-9]{4}(?:[0-9]{2})?", address.query))
             and distinct(re.compile(r"祝花おまとめ|フラワーギフト|ナイトブラ|バストアップ|作務衣|"
                                     r"リゾートバイト|PG2 MARINE RICH|プロテオグリカン|体圧分散|"
                                     r"高反発マットレス|夕張メロンアイス|高弾性"), text) >= 6
             and (bool(re.search(r"(?:応募資格|休日|給与).{0,60}(?:[0-9]+\s*円|優遇|即日)", text))
                  or len(re.findall(r"(?:税込[0-9,]+円|送料込み価格|賞味期間|お届け可能期間)", text)) >= 3)
             and not re.search(r"(?m)^(?:出典|執筆|取材|商品一覧|各店舗からのお知らせ)[ :：]", text))
    if 900 <= len(text) <= 3000 and re.fullmatch(r"/[a-z]+/\d{1,6}/?", path):
        title = first_line.removesuffix(" 紹介")
        page("recruitment-doorway-with-repeated-query-and-swapped-locality",
             title != first_line and bool(re.search(r"求人|募集", title))
             and len(re.findall(rf"(?m)^{re.escape(title)} (?:メリット|デメリット|良い部分|悪い部分|まとめ)$", text)) >= 4
             and len(re.findall(r"求人紹介サイト|求人仲介サイト|バイト求人|バイト紹介サイト", text)) >= 2
             and len(re.findall(r"お金を.{0,6}稼|給料が高|賃金が高|時給が高", text)) >= 4)
    if 600 <= len(text) <= 5200 and re.search(r"無料|夢|電話", head):
        page("fortune-query-placeholders-in-place-of-readings-and-practitioners",
             len(re.findall(r"(?:はじめて)?電話(?:\d{1,4}年|\d{1,2}月|[子丑寅卯辰巳午未申酉戌亥]年|うお座)", text)) >= 3
             and distinct(re.compile(r"霊能者|霊視|夢占い|本当に当た|鑑定|掲示板"), text) >= 3
             and len(re.findall(r"(?:\d{4}年\d{1,2}月\d{1,2}日|[子丑寅卯辰巳午未申酉戌亥]年|\d{1,2}月)師", text)) >= 2)
    if re.fullmatch(r"/date/20\d\d/\d{1,2}/?", path) and 550 <= len(text) <= 3500:
        page("blog-archive-with-repeated-sentence-shells-and-unrelated-query-inserts",
             len(re.findall(r"(?m)^.{1,65}(?:苦労してるんだろうな|って、あまり稼げないイメージ|あなたのイメージはどうですか|"
                             r"をやっていました)[^。\n]{0,36}[。!?]?[ \t]*$", text)) >= 6
             and len(re.findall(r"(?m)^(?:まちがってますか|想定外に楽しかったですよ)[。!?]?$", text)) >= 3
             and distinct(re.compile(r"味噌汁|先物|体型維持|サヨ|預金|弁護士|テンプレート|自動ドア|体重計"), text) >= 5)
    if 380 <= len(text) <= 2800 and re.search(r"/20\d\d-\d\d-\d\d/?$", path):
        page("localized-magazine-with-preserved-layout-directive-and-separate-teaser",
             "{loadposition intext}" in text and "(出典)" in text[-90:]
             and (text.count("写真の後に続きを読む") >= 2
                  or bool(re.search(r"また興味があるかもしれません|別の.*に興味", text))))
    if "extracted by:2chまとめ抽出器" in text.casefold() and len(text) <= 1300:
        page("automatically-extracted-forum-lines-without-thread-continuity",
             bool(re.search(r"(?m)^(?:旧スレ|前スレ)$", text)) and "test/read.cgi/" in text
             and sum(8 <= len(line) <= 72 for line in text.splitlines()) >= 7
             and not re.search(r"(?m)^\s*\d{1,5}[:：]|\bID:", text))
    if 130 <= len(text) <= 650 and re.fullmatch(r"/[a-z]+/\d{2,6}[a-z]{3,8}\d{5,15}/?", path):
        page("machine-localized-retail-copy-in-opaque-numeric-route",
             distinct(re.compile(r"川をチューブダウン|太陽に浴びる時|事前テスト済みのビニール|"
                                     r"フロートトリップ|涼しさを保ちます|街中にはバズ|浮かぶ楽しい時間"), text) >= 4
             and bool(re.search(r"インチ|カップホルダー|セットには", text)))
    if 130 <= len(text) <= 560 and re.fullmatch(r"/entry/20\d\d/\d{1,2}/\d{1,2}/\d+/?", path):
        page("supplement-snippets-with-fragmented-and-reused-first-line",
             distinct(re.compile(r"ダイエット商品|酵素|乳酸菌|サプリメント|カロリー|果実"), text) >= 5
             and distinct(re.compile(r"新発売は、医師|サプリメントの用語を収録|円高のこのタイミングではおすすめ|"
                                     r"を飼う上で、監修した|果実となり.{0,18}にんにく"), text) >= 3)
    if re.fullmatch(r"/places/\d+/?", path):
        venues = [line for line in text.splitlines() if 24 <= len(line) <= 175 and line.count("。") >= 1]
        categories = (r"家具|リネン|インテリア雑貨", r"古本|本屋|書店|問題集",
                      r"イタリアン|アラカルト|パスタ", r"そば|蕎麦|十割",
                      r"中華|餃子|チャーハン", r"ハンバーガー|アメリカ料理")
        page("single-place-entry-with-unlabelled-descriptions-of-unrelated-venues",
             len(venues) >= 7 and sum(bool(re.search(cue, text)) for cue in categories) >= 5
             and len(re.findall(r"こちらのお店|店内|料理店|本屋さん|お店です", text)) >= 6
             and not re.search(r"(?m)^(?:周辺のお店|関連スポット|他の施設|施設名|口コミ一覧|住所|地図|[|｜]店舗名)", text))
        dining_categories = (r"ラーメン|中華そば", r"つくね|串料理|串揚げ", r"欧州バル|フランス料理|スペインバル",
                             r"ダーツ|ビリヤード", r"阿波牛|ステーキ|鉄板焼")
        page("single-restaurant-record-made-of-unlabelled-multiple-venue-blurbs",
             len(venues) >= 7 and len(venues) >= len(text.splitlines()) - 1
             and sum(bool(re.search(cue, text)) for cue in dining_categories) == len(dining_categories)
             and sum(bool(re.search(r"店です|お店|使われ|完備|カクテル|料理", line)) for line in venues) >= 5
             and not re.search(r"(?m)^(?:周辺のお店|関連スポット|他の施設|施設名|口コミ一覧|住所|地図|[|｜]店舗名)", text))
        page("single-venue-record-assembled-from-unlabelled-shop-blurbs",
             len(venues) >= 7 and len(venues) >= len(text.splitlines()) - 2
             and distinct(re.compile(r"お寿司|イタリア|アラビアータ|そば|和食|牧場|焼酎|スコッチ|カクテル|タイ古式|"
                                     r"キャス・キッドソン|インテリア|スペインチョコ|ガレット|炉端焼き"), text) >= 5
             and bool(re.search(r"タイ古式マッサージ|雑貨|アイテムがラインナップ|家具|インテリア", text))
             and bool(re.search(r"お店|料理店|バーです", first_line))
             and not re.search(r"(?m)^(?:周辺のお店|関連スポット|他の施設|施設名|口コミ一覧|住所|地図|[|｜]店舗名)", text))
        page("single-shop-with-unlabelled-venue-montage-including-play-facility",
             len(venues) >= 7 and len(venues) >= len(text.splitlines()) - 1
             and bool(re.search(r"パン(?:屋|が並ぶ|はつい)", first_line))
             and distinct(re.compile(r"遊具|遊園地|アスレチック|利用料金"), text) >= 3
             and distinct(re.compile(r"居酒屋|ラーメン|地元グルメ|お食事どころ|レストラン"), text) >= 4
             and not re.search(r"(?m)^(?:周辺のお店|関連スポット|他の施設|施設名|口コミ一覧|住所|地図|[|｜]店舗名)", text))
        dining = re.compile(r"お店|料理|レストラン|パスタ|リガトーニ|ラーメン|カフェ|ダイニングバー|バーです|居酒屋|マスター")
        retail = re.compile(r"スポーツ用品|家電量販店|眼鏡店|書店です|携帯ショップ|実用衣料|トレーニングジム|服飾雑貨|園芸用品")
        cards = text.splitlines()
        page("single-venue-record-mixing-unlabelled-dining-and-retail-cards",
             5 <= len(cards) <= 13 and all(25 <= len(l) <= 160 and l.endswith(("。", "!")) for l in cards)
             and sum(bool(dining.search(line)) for line in cards) >= 4
             and any(retail.search(line) and not dining.search(line) for line in cards[1:-1])
             and not re.search(r"(?m)^(?:大通り|近隣|周辺|関連|近くの|全館|同じ建物|店舗情報|各施設|徒歩)|"
                               r"ショッピングモール|テナント|同フロア|フードコート|商業施設|.{1,10}内にある.{0,5}店", text))
        variety = (r"鯛(?:めし|をまるごと)|土鍋ご飯|釜飯を",
                   r"クラフトビール.{0,30}(?:ワイン|パスタ)|ビアバル",
                   r"懐石料理店|昼懐石|京懐石",
                   r"吸血鬼|ヴァンパイア|不思議の国.{0,20}レストラン")
        page("single-dining-venue-made-from-unlabelled-competing-restaurant-descriptions",
             5 <= len(venues) <= 10 and len(venues) >= len(text.splitlines()) - 1
             and all(any(re.search(pattern, line) for line in venues) for pattern in variety)
             and not re.search(r"(?m)^(?:周辺|関連|施設名|店舗一覧|住所|地図|各店舗)|フードコート|ホテル内", text))
        page("single-attraction-record-with-unlabelled-museum-and-park-blurbs",
             len(venues) >= 5 and len(venues) >= len(text.splitlines()) - 1
             and bool(re.search(r"昆虫専門博物館|昆虫博物館|昆虫館", first_line))
             and distinct(re.compile(r"昭和初期|戦国時代|歴史を紹介|発掘調査|武家屋敷|茶室|友好庭園"), text) >= 5
             and bool(re.search(r"公園。|公園でありながら|発掘調査.*公園", venues[-1]))
             and not re.search(r"(?m)^(?:周辺のお店|関連スポット|他の施設|施設名|口コミ一覧|住所|地図|[|｜]店舗名)", text))
    if re.fullmatch(r"/detail/\d{5,9}\.html?", path):
        page("retail-introduction-with-unrelated-machine-translated-product-name",
             100 <= len(text) <= 550 and text.count("バーベキューコンロ") >= 2
             and bool(re.search(r"(?m)^[^。\n]{15,80}(?:はさみ|ハサミ)[^。\n]{10,80}$", text))
             and distinct(re.compile(r"抗腐食性|スティンスチール|魚骨|鶏の骨肉"), text) >= 2
             and bool(re.search(r"価格\s*[:：]\s*[¥￥]\s*\d", text)))
        page("localized-product-card-with-repeated-word-and-foreign-characters",
             120 <= len(text) <= 850 and bool(re.search(r"([^ぁ-ゖ\s。]{2,5})\1{3,}", text))
             and distinct(re.compile(r"简|缩|测|织|帘|门|网|宽|调"), text) >= 2
             and bool(re.search(r"価格\s*[:：]\s*[¥￥]\s*\d", text))
             and bool(re.search(r"サイズ|送料|激安|通販", head)))
    if re.fullmatch(r"/archives/\d+/?", path) and "転載元:" in text:
        page("forum-reprint-interrupted-by-unlabelled-headline-block",
             bool(re.search(r"(?m)^[^\s]{4,55}[!?]{1,3}\n(?:-\s*【[^\n]+\n){8,}", text[:1800]))
             and bool(re.search(r"転載元:\s*https?://[^/\s]+/test/read\.cgi/", text))
             and not re.search(r"関連記事|オススメ記事|おすすめ記事|人気記事", text[:800]))
    if re.fullmatch(r"/archive/\d{4}/\d{1,2}/\d{1,2}/?", path) and "引用をストックしました" in text:
        article = text.split("引用をストックしました", 1)[0]
        page("dated-blog-excerpt-with-broken-nutrition-word-slots",
             85 <= len(article) <= 450
             and distinct(re.compile(r"サプリ|カプセル|ジュース|栄養|カロリー|オーガニック|成分"), article) >= 5
             and distinct(re.compile(r"ビタミンと面して|栄養はカロリーになっ|サプリやジュースであっても|"
                                     r"ソムリエをふせ|キレイへジュースに成分"), article) >= 3)
    if 900 <= len(text) <= 4500 and re.fullmatch(r"/tag/[^/]+/?", path):
        page("tag-landing-with-mixed-qa-and-mechanically-broken-quotation",
             len(re.findall(r"[一-龯ぁ-ゖ]{2,20}。\s*[ぁ-ゖ]", text)) >= 8
             and distinct(re.compile(r"ってどういうこと|子どものころ|教頭|相談室|ここでは|回答は期待|"
                                     r"自分の事は自分で|次のようになれます"), text) >= 5
             and distinct(re.compile(r"の。?[一-龯]+(?:とは何か|などして)。を|言わ。自分の|毒\s+親とは。|"
                                     r"大人自身がに応え|毒親って。|なったのかそこを突き詰め"), text) >= 3)
    route_parts = path.strip("/").split("/")
    if re.fullmatch(r"/[a-z]{3,20}/[0-9]{3,6}/?", path) and 280 <= len(text) <= 1900:
        dating_labels = Counter(re.findall(r"[一-龯々]{2,6}の出会い(?:掲示板)?", text))
        page("regional-search-labels-grafted-onto-unrelated-prose",
             any(count >= 4 for count in dating_labels.values())
             and distinct(re.compile(r"そのような線を言う|謙虚な出会い|相手がごめんなさい|"
                                     r"管理していただきたいと思います|夢だったのか|時計ブランド|"
                                     r"ロレックス|趣味のトーナメント|両方を一度にチェック"), text) >= 2
             and not re.search(r"(?m)^(?:掲示板へようこそ|利用規約|投稿日時[：:]|書き込む)", text))
    if len(route_parts) == 2 and route_parts[0] == route_parts[1] and " " in route_parts[0]:
        page("repeated-query-path-with-medical-snippet-splices",
             1000 <= len(text) <= 6500 and "おすすめ商品" in text
             and len(re.findall(r"\.{3}|[!?] ", text)) >= 8
             and distinct(re.compile(r"症状|病気|治療|診断|ウイルス|感染"), text) >= 5
             and distinct(re.compile(r"写真集|怪物|ライトカバー|ゲージ|製鋼大敗|早くでないかな"), text) >= 3)
    if re.match(r"^/20\d\d/\d{1,2}/\d{1,2}/", path):
        if 650 <= len(text) <= 3900 and re.search(r"/post-[0-9]+/?$", path):
            headlines = [line.strip() for line in text.splitlines() if line.strip()]
            page("dated-post-composed-of-standalone-headlines",
                 len(headlines) >= 25 and sum(len(line) > 108 for line in headlines) <= 2
                 and sum(bool(re.search(r"^(?:[【\[]|(?:ワイ|俺|女|男)「)|[←→]|w{3,}|\.{3}", line))
                         for line in headlines) * 3 >= len(headlines)
                 and text.count("。") * 4 <= len(headlines)
                 and not re.search(r"記事一覧|新着記事|ニュース一覧|関連記事|ランキング", first_line))
        page("automatic-forum-harvest-wrapped-as-a-video-summary",
             len(text) >= 650 and text.rstrip().lower().endswith("powered by auto youtube summarize")
             and "\n" in text)
        page("mechanical-news-reprint-with-title-repeated-around-single-reaction",
             18 <= len(first_line) <= 120 and 440 <= len(text) <= 2900
             and "ニュース配信元:" in text and f"「{first_line}」への、ネット民の反応\nまとめ" in text
             and f"以上、{first_line}のまとめでした。\nSource:" in text)
    if "This is description" in text and text.rstrip().lower().endswith("powered by auto youtube summarize"):
        comments, _, description = text.partition("\nThis is description\n")
        footer = re.search(r"(?m)^>>(\d+) ([^\n]+)\n>>\1 ([^\n]+)\n>>\1 ([^\n]+)\n"
                           r"powered by Auto Youtube Summarize\s*\Z", description, re.I)
        page("video-description-wrapped-in-stock-comment-thread",
             bool(footer) and set(footer.groups()[1:]) == {"おつおつ", "ありがとう", "おつかれ。いつもありがと"}
             and distinct(re.compile(r"この動画消されないよな|の動画は良作が多い|"
                                     r"って動画が話題らしいぞ|わたしの名はすず|俺の名はちずむ|"
                                     r"いまきた 説明文ないの|にもやってるtvとかがパクる|なんだかんだでいい動画"), comments) >= 2)
    if re.fullmatch(r"/\d{4,7}", path) and 700 <= len(text) <= 9000:
        page("machine-translated-battery-guide-with-product-funnel-residue",
             "バッテリーイーター" in text and "スタートフォトギャラリー" in text
             and distinct(re.compile(r"selbtständig|空携帯電話のバッテリーを吸う|"
                                     r"バッテリーはせいぜい1日までに通常続きます|"
                                     r"ここに愛が特に重要であるアクティブ|値が付けられたアプリケーション"), text) >= 3)
    if re.fullmatch(r"/archives/\d{6}", path) and 100 <= len(text) <= 340:
        page("numbered-video-teaser-without-a-main-entry",
             bool(re.search(r"(?m)^20\d{2}/\d{1,2}/\d{1,2}$", head))
             and bool(re.search(r"(?m)^admin\n記事を読む\n(?:[^\n。]{12,95}\n){3,}", text))
             and "で栄養" in "\n".join(text.splitlines()[:2]))
    if re.fullmatch(r"/20\d\d/\d{1,2}/\d{2,6}\.html?", path):
        page("watch-review-with-counterfeit-brand-inserted-into-material-specification",
             "腕時計" in first_line
             and bool(re.search(r"[ァ-ヺー・]{6,36}スーパーコピー\s*\d{1,2}K", text))
             and bool(re.search(r"\b([A-Za-z]{3,16})\s+\1\s+(?:Collection|Women|Series)", text, re.I))
             and bool(re.search(r"直径\d+(?:\.\d+)?メートルの防水性", text)))
    if code := re.fullmatch(r"/(\d{1,3}[a-z]{2,6}\d{2,7})/?", path, re.I):
        catalog_title = re.search(r"(?m)^\|タイトル\|\|([^|\n]{12,140})\|[ \t]*$", text)
        if catalog_title and first_line.startswith("【"):
            lead_title = first_line.partition("】")[2].strip()
            review_title = catalog_title[1].strip()
            body = text[len(first_line):catalog_title.start()]
            page("catalog-review-with-conflicting-title-and-stitched-links",
                 bool(lead_title) and lead_title not in review_title and review_title not in lead_title
                 and text.rstrip().endswith("\n" + first_line) and review_title in body
                 and bool(re.search(rf"(?im)^\|(?:品番|商品コード)\|\|{re.escape(code[1])}\|[ \t]*$", text))
                 and len(re.findall(r"(?m)^-[ \t]*\n[^\n]{10,100}$", body)) >= 8)
    page("marketplace-review-of-other-product",
         ((field_count >= 2 or "関連コメント" in head and "メーカー希望小売価格" in head)
          and any(title.search(first_line) and topic.search(text[180:]) and detail.search(text[180:])
                  for title, topic, detail in PRODUCT_REVIEW_TOPIC_MISMATCHES))
         or ((field_count >= 2 or "ネットショップ全体での類似商品の価格比較" in text)
             and (MARKETPLACE_REVIEW_ROUTE.search(path)
                                  or path.endswith(".php") and MARKETPLACE_PICKUP_QUERY.fullmatch(address.query))
             and len(set(MARKETPLACE_REVIEW_LABEL.findall(text))) >= 2))
    if re.fullmatch(r"/pickup/[A-Za-z][0-9]{5,11}/?", path):
        page("marketplace-review-cards-mix-unrelated-product-categories",
             bool(re.search(r"(?m)^この製品をおすすめするレビュー[ \t]*$", head))
             and len(re.findall(r"(?m)^[0-5]\.\d{2}\([0-9]+\)[ \t]*$", text)) >= 3
             and len(re.findall(r"(?m)^¥[0-9,]+[ \t]*$", text)) >= 3
             and len(re.findall(r"(?m)^[a-zA-Z0-9_-]{2,22}さん[ \t]*$", text)) >= 3
             and sum(bool(group.search(text)) for group in (
                 re.compile(r"魚探の振動子|スルハル|釣り糸"),
                 re.compile(r"ブラシの消耗|交換用ブラシ|本体も元気に動作"),
                 re.compile(r"ジュウシマツ|ケージに取り付けられ|鳥かご"),
                 re.compile(r"お尻に塗|顔に塗|手荒れ|美容液"),
             )) >= 3)
    if re.fullmatch(r"/article_[^/]{12,195}\.html?", path):
        lines = text.splitlines()
        page("machine-search-phrase-and-clipped-question-grid",
             4 <= len(lines) <= 16 and len(text) <= 1500 and len(lines[1]) >= 7
             and lines[0].startswith(lines[1]) and len(lines[0]) - len(lines[1]) >= 7
             and lines[2] in {"関連した質問など", "関連する質問など", "関連質問"}
             and sum(line.startswith("|") and "→||" in line and line.endswith("→|")
                     for line in lines[3:]) >= 3
             and len(re.findall(r"\.\.\.→[|]", text)) >= 2)
    page("retail-rewrite-with-name-placeholder", SHOPPING_SEARCH_HEAD.search(head)
         and len(SHOPPING_OFFER.findall(text)) >= 2 and text.count("%%%name%%%") >= 2)
    page("keyword-question-diary", host in {"oakley--sunglasses.net", "www.oakley--sunglasses.net"}
         and re.fullmatch(r"/(?:page/)?\d+/?", path) and len(first_line) <= 32
         and re.search(r"(?:さよ|ば[ぃい]ば)", text.strip().rsplit("\n", 1)[-1])
         and text.count("?") >= 6)
    page("comma-joined-scrape-journal", (SCRAPE_JOURNAL_ROUTE.fullmatch(path)
         or path.endswith("/page.php") and re.match(r"^[0-9a-f]{6}=", address.query))
         and len(re.findall(r"[。！？?!], +", text)) >= 8)
    page("repeated-dating-query-at-line-end",
         host.removeprefix("www.") in {"usami21.com", "climax-pa.jp", "p-pr.info", "selpoi.jp"}
         and any(count >= 3 for count in Counter(DATING_KEYWORD_TAIL.findall(text)).values())
         and sum(0 < len(line) <= 30 for line in text.splitlines()) >= 14)
    page("query-sitemap-snippet-footer", QUERY_SITEMAP.search(text[-500:])
         and len(re.findall(r"\. (?=[ぁ-ゖァ-ヺ一-龯])", text)) >= 4)
    if NUMBERED_SNIPPET_ROUTE.fullmatch(path):
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        questions = sum(len(line) <= 100 and line.endswith("?") for line in lines)
        minimum = 4 if host == "thefatjewish.merchline.com" else 5
        page("translated-faq-stuffing", questions >= minimum and questions * 4 >= len(lines))
    page("repurposed-article-with-promotional-tail", 20 <= len(first_line) <= 125
         and first_line.endswith("。") and text.strip().endswith("\n" + first_line)
         and TERMINAL_PROMO.search(text[-430:-len(first_line)]))
    page("suitcase-locality-skincare-montage", "スーツケース" in path
         and "レンタル" in path and "送料無料" in head and "送料無料を作" in text
         and sum(token in text[600:] for token in ("ヒアルロン酸", "美容液", "ビタミン", "肌")) >= 3)
    page("spun-prose-in-unsourced-quote-frames", host.endswith((".hatenablog.com", ".hatenadiary.jp"))
         and len(SOURCELESS_QUOTE_LEAD.findall(text)) >= 4 and len(SOURCELESS_QUOTE_CLOSE.findall(text)) >= 3
         and not re.search(r"出典[：:]|引用元[：:]|参考文献", text))
    page("scrape-page-with-fake-rating", FAKE_RATING_ROUTE.fullmatch(path)
         and FAKE_RATING_HEAD.match(head) and "| SiteMap" in text[-170:])
    prefixes = CATEGORY_AD_PREFIX.findall(text)
    page("advertising-words-prefixed-to-unrelated-sentences", len(prefixes) >= 25
         and len({prefix.lower() for prefix in prefixes}) >= 4 and len(prefixes) * 5 >= text.count("。"))
    if card := LOCATION_CARD.search(text):
        pitch = text[:card.start()]
        after = text[card.end():].lstrip()
        page("location-card-in-generic-commerce-copy",
             (pitch.count(card[1]) >= 2 and len(LOCATION_COMMERCE.findall(pitch)) >= 3)
             or (card.start() < 100 and after.startswith("出会い系サイトのまとめ")
                 and after.count("出会い") >= 4)
             or (card[1] in head and "看護師" in pitch and "求人サイト" in pitch
                 and "ハローワーク" in text and "求人" in after))
    page("affiliate-testimonial-with-spun-impression", AFFILIATE_TESTIMONIAL.search(text)
         or all(fragment in text for fragment in AFFILIATE_SKEPTICAL))
    page("synthetic-answers-on-opaque-route", re.fullmatch(r"/[a-zA-Z0-9]{8,14}/?", path)
         and "Model" in text and len(MODEL_TURNS.findall(text)) >= 3)
    page("marketplace-results-with-fake-ratings", RATING_RESULT_HEADER.search(text)
         and ((path.endswith(".php") and re.fullmatch(r"[a-z0-9_-]{3,30}", address.query, re.I))
              or ("user ratings" in head and path in {"/", ""} and "求人" in text and "株式会社" in text)))
    page("query-collage-with-source-metadata", path.endswith("/article.php")
         and re.match(r"^[0-9a-f]{6}=[^&]+", address.query)
         and sum(bool(pattern.search(text)) for pattern in QUERY_METADATA) >= 2)
    page("regional-loan-affiliate-bracket", REGIONAL_LOAN_ROUTE.search(path)
         and "WEB完結申込" in head and "▼▽▼▽▼" in head and "▼▽▼▽▼" in text[-260:]
         and re.search(r"簡易審査|借入.{0,12}ご確認", text[-260:]))
    leading_sentence = head.partition("。")[0]
    page("recycled-appraisal-article", re.fullmatch(r"/id-\d{2,8}(?:/|\.html?)?", path)
         and 28 <= len(leading_sentence) <= 135 and text.strip().endswith(leading_sentence + "。")
         and len(set(re.findall(r"査定額|一括査定|下取り|買取業者|買取店|査定", text))) >= 3)
    page("clipped-pseudo-diary-with-pr-footer", path.startswith("/entry/")
         and PR_MARKUP_FOOTER.search(text[-380:]) and len(PSEUDO_DIARY_TRANSITION.findall(text)) >= 2)
    page("doorway-with-query-list-and-repeated-title", len(first_line) >= 14
         and text.strip().endswith(first_line) and len(DOORWAY_ENTRY.findall(text)) >= 2
         and sum(0 < len(line) <= 29 for line in text.splitlines()) >= 13)
    if AMAZON_SCRAPE_ROUTE.fullmatch(path):
        block = head.splitlines()
        page("scraped-amazon-reviews-under-repeated-product-title", len(block) >= 3
             and block[0] == block[2] and re.fullmatch(r"[\d,]+円", block[1])
             and len(AMAZON_CUSTOMER.findall(text)) >= 2)
    page("cross-category-listing-with-food-footer", head.startswith("ヤフオク!")
         and re.search(r"(?m)^[1-5]\.\d\d[ \t]*$", head)
         and CATALOG_SHIPPING_FOOTER in text[-1250:])
    page("multiple-product-term-collisions",
         any(distinct(pattern, text) >= 2 for pattern in PRODUCT_TERM_COLLISIONS))
    page("search-prompts-in-résumé-advice", len(RESUME_QUERY_AD.findall(text)) >= 2)
    page("electronics-support-source-montage", path.startswith("/categories-top/")
         and "モバレコTOP" in head and "Internet Explorer" in text and "カプコン" in text)
    page("water-server-copy-with-wall-renovation-footer",
         len(re.findall(r"(?:ウォーター|水素水)サーバー", head)) >= 2
         and "外壁塗装" in text[-1500:] and "一括見積もり" in text[-1100:]
         and bool(municipality_route(url)))
    page("repeated-job-doorway-headings",
         max(Counter(JOB_DOORWAY_HEADING.findall(text)).values(), default=0) >= 3
         and (len(re.findall(r"(?m)^- [^\n]{3,55}求人[ \t]*$", text)) >= 5
              or (re.fullmatch(r"/[a-z]+/\d{3,6}/?", path) and "掲載してる求人サイト" in text[-650:])))
    page("dating-brand-keyword-carpet", len(text) <= 650
         and (host.endswith((".cms.am", ".sphere.sc")) or len(re.findall(r"[\uff61-\uff9f]", raw)) >= 15)
         and len(re.findall(r"出会|会える|登録", text)) >= 4
         and max(Counter(ROTATING_DATING_BRAND.findall(text)).values(), default=0) >= 4)
    page("download-snippets-in-generated-archive", bulk_search and DOWNLOAD_SCRAPE_ROUTE.fullmatch(path)
         and text.count("ダウンロード") >= 8
         and len(re.findall(r"(?m)^- [^\n]{10,90}(?:ダウンロード|トレント)[^\n]*$", text)) >= 3)
    page("downloadable-course-affiliate-endorsement", "効果の口コミにつながる気になる話" in head
         and "FacebookやTwitterを調べ" in head and "リンク先は公式サイトですので" in text[-300:])
    page("unrelated-retail-copy-stitch", re.search(r"商品|サプリ|通販|価格|情報を検索", head)
         and any(title.search(head) and len(set(body.findall(text[450:]))) >= 2
                 for title, body in RETAIL_SPLICE_TOPICS))
    page("casino-affiliate-with-pasted-operator-terms", "賭け条件" in head and "ボーナス" in head
         and re.search(r"本規約の現在の条件|当社は定期的に更新を確認", text[-1300:])
         and re.search(r"(?:カジノ|casino)", path, re.I))
    if len(text) >= 500 and distinct(WALL_LOCAL_TERMS, text) >= 3:
        place = municipality_route(url)
        page("municipality-pitch-with-unrelated-generic-prose",
             place and all(part not in text for part in place)
             and (len(WALL_LOCAL_TERMS.findall(text)) >= 8 or len(gate.PROMOTION.findall(text)) >= 3))
    if local_title := LOCAL_BUYBACK_TITLE.match(head):
        town = local_title[1]
        page("local-buyback-with-substituted-town",
             (town in path or GENERATED_CARD_ROUTE.search(path)) and text.count(town) >= 3
             and len(LOCAL_MAILIN.findall(text)) >= 2 and re.search(r"買取|買い取|買取り", head))
    page("synthetic-marketplace-review-layout",
         ((distinct(SHIPPING_FIELDS, head) >= 4 and len(REVIEW_SCORE_ROW.findall(text)) >= 3
           and AMAZON_CUSTOMER.search(text))
          or (GENERATED_CARD_ROUTE.search(path) and len(AMAZON_CUSTOMER.findall(text)) >= 2
              and re.search(r"(?m)^[\d,]+円[ \t]*$", head) and distinct(COMMERCE_CARDS, text) >= 3)))
    page("scraped-article-with-catalog-cards", GENERATED_CARD_ROUTE.search(path)
         and distinct(COMMERCE_CARDS, text) >= 5 and distinct(SCRAPED_EDITORIAL, text) >= 3
         and len(re.findall(r"(?m)^(?:◆|◎|\||[※★])", text)) >= 5)
    page("rewritten-pseudo-diary-with-affiliate-graft",
         (len(text) < 4300 and len(COMMON_DIARY_PIVOTS.findall(text)) >= 3
          and len(DISJOINT_AFFILIATE.findall(text)) >= 2
          and len(re.findall(r"(?m)^.{8,70}[?？!！]$", text)) >= 3)
         or (path.startswith("/entry/") and text.rstrip().endswith("?[PR]")
             and "詳しい方がいらっしゃいましたらぜひ教えてください" in text[-380:]))
    page("legal-fraction-rewritten-as-calendar-date",
         len(set(re.findall(r"自己破産|差押|押収|強制執行|債務者|免責", text))) >= 4
         and re.search(r"(?:の|残りの)3月4日(?:において|に対し|が|を)(?:[^。\n]{0,28})(?:差押|押収|給料|給与)", text))
    page("debt-advice-with-incompatible-word-substitutions",
         len(set(re.findall(r"返済|審査|ブラックリスト|自己破産|キャッシング", text))) >= 4
         and len(set(re.findall(r"人間信頼見識|返済能力[^。]{0,30}お金を引き戻す|お金を引き戻すことが出来る返済"
                                r"|遅延の測量|キャッシングの消費|所定の品評", text))) >= 2)
    page("job-site-portal-with-generic-ranked-pitches",
         "アクセスキーワードコンテンツ" in head and "求人サイト" in head
         and "もっとランキングを見る" in text[-800:] and "RSSリーダーで購読" in text[-450:])
    page("diary-with-erased-subject-slots", len(text) <= 3600
         and len(re.findall(r"(?m)^(?:を|から|が|です[♪☆]|も控えて)", text)) >= 6
         and len(re.findall(r"(?m)^.{4,55}[♪☆!？?]", text)) >= 5
         and re.search(r"時間[^\n]{0,12}(?:–>|->)", head))
    page("repeated-streaming-query-in-spun-text", len(first_line) <= 75
         and re.search(r"動画[ \t]+無料$", first_line) and text.count(first_line) >= 2
         and "レンタルDVDショップ" in text and "タダ視聴" in text and "時点の情報です" in text)
    page("forum-pasted-paid-manual-pitch", host.endswith(".teacup.com") and path.endswith("/bbs")
         and len(set(re.findall(r"馬券投資|手堅く月\d+万円|マニュアル|通信販売|お申込み|購入者|郵送", text))) >= 3
         and "新着の記事から" in head)
    page("streaming-signup-spliced-to-retailer-cards",
         "新規登録なら31日間無料トライアルで見放題" in head
         and len(set(re.findall(r"商品内容|Blu-ray|正規品|ご購入はご遠慮|仕様|商品説明", text[170:]))) >= 3)
    page("regional-repair-pitch-with-recycled-city",
         re.fullmatch(r"/glass/[a-z]+/[a-z-]+-shi/?", path)
         and len(re.findall(r"[一-龯]{2,12}市(?:で|の|出張| ガラス)", head)) >= 2
         and "ガラス屋" in head and "ガラス屋" in text[-420:])
    page("appraisal-query-joined-to-literature", "ガリバー旅行記" in text
         and re.search(r"pixiv|小人国|風刺小説", text)
         and len(set(re.findall(r"中古車|査定額|買取|一括査定", text))) >= 3)
    page("recruiting-article-with-retailer-graft", path.endswith(".php")
         and re.fullmatch(r"[a-z0-9]{7,28}/[a-z0-9]{7,25}", address.query, re.I)
         and "人材業界専門エージェント" in text
         and len(set(re.findall(r"最終値下げ|家具|棚|ローテーブル|花瓶|骨董品|送料無料", text))) >= 3)
    if 560 <= len(text) <= 6500 and re.fullmatch(r"/(?:report|view|item|detail)\.php", path):
        page("coded-retail-query-with-merchandise-inserted-into-an-unrelated-diary",
             bool(re.fullmatch(r"[a-z]{3,8}-\d{5,7}[a-z0-9]{3,12}/[a-z0-9]{2,12}", address.query))
             and distinct(re.compile(r"大人気新品|専用|新品未仕立|新品・未使用|新品タグ付き|"
                                     r"最終値下げ|送料無料|中古美品"), head) >= 3
             and distinct(re.compile(r"誕生日|留学|シナモンロール|日記|旅先|思い出|祝っていただ"), text[300:]) >= 3
             and len(re.findall(r"(?m)^[^。\n]{4,80}(?:バッグ|ダウン|シューズ|セット|アイフォンケース|チェア)"
                                r"[^。\n]{0,22}$", text)) >= 3)
    page("furniture-rewrite-with-unrelated-odor-article",
         len(set(re.findall(r"内装に[^。]{0,8}執念|第三国心情|緑が映える白を行為|内装を放棄", head))) >= 2
         and len(set(re.findall(r"加齢臭|体臭|ニオイ|消臭|タバコやお酒", text))) >= 3)
    if host == "mono.flier.jp" and re.fullmatch(r"/aws/rev/\d+\.php", path):
        marker = REVIEW_HEADLINES_MARKER.search(raw)
        if marker and sum(5 <= len(line.strip()) <= 70 for line in raw[marker.end():].splitlines()) >= 8:
            findings["unrelated-review-headlines-after-product-review"] = [(marker.start(), len(raw))]
    if re.search(r"/dmm-?bgame-", path) and "ジャンル" in text and "メーカー" in text:
        if note := AFFILIATE_EDITOR_NOTE.search(raw):
            findings["unrelated-plots-in-affiliate-editor-note"] = [note.span()]
    if host in {"kandou10.jp", "www.kandou10.jp"} and TEMPLE_DIRECTORY_ROUTE.fullmatch(path):
        listing = TEMPLE_LISTING.search(raw)
        if listing and (description := TEMPLE_DESCRIPTION.search(raw, listing.end())):
            if raw.count("。", description.start()) >= 3:
                findings["directory-description-after-listing"] = [(description.start(), len(raw))]
    return findings


def paired_findings(records, pairs):
    """Return witnessed spans where the swapped fields match a particular spam type."""
    for pair in pairs:
        for left, right, a, b, changes in pair["witnesses"]:
            if not changes or min(len(a), len(b)) < 32:
                continue
            text = tuple(map(normalize, (a, b)))
            both = lambda pattern: all(pattern.search(side) for side in text)
            patterns = []
            local = structural.exact_locality_variation(*text)
            if local and both(structural.LOCAL_SERVICE):
                patterns.append("location-in-reused-intro")
            if local and both(gate.COMMERCIAL_BODY) and both(TRANSIT_FIELDS):
                patterns.append("station-table-with-generic-pitch")
            if (local and both(JOB) or len(pair["witnesses"]) >= 2
                    and both(LOCAL_TARGET) and both(JOB) and both(REPEATED_LANDING_QUERY)):
                patterns.append("location-query-service-combination")
            if both(LOCAL_TARGET) and (both(LOANS) or both(LOAN_SLOTS)) and (
                    local or len(pair["witnesses"]) >= 2 and both(LOAN_SLOTS)):
                patterns.append("locality-route-with-generic-body")
            if both(BOOK) and both(IN_MARKETING):
                patterns.append("title-repeated-in-pitch")
            if both(APP_PITCH):
                patterns.append("app-installer-slot")
            if both(SONG_PITCH):
                patterns.append("song-download-slot")
            if both(FILM_PITCH):
                patterns.append("film-affiliate-slot")
            if both(DATING_PITCH):
                patterns.append("dating-platform-and-audience")
            if both(RETAIL_RESULT) and pair["a"]["host"] != pair["b"]["host"]:
                patterns.append("retailer-query-and-count")
            if both(EDITORIAL) and (both(FIELD) or both(gate.PRICE_KEYS) or
                    len(changes) >= 4 and both(re.compile(r"セット|送料無料|型番|配送"))):
                patterns.append("catalog-in-news")
            if not local and gate.multi_edit_witness(a, b):
                if both(BOOK_PARAPHRASE) and both(BOOK):
                    patterns.append("fluent-paraphrase-campaign")
                elif both(SEMANTIC_SWAP) or both(audit.MALFORMED_QUERY) or len(changes) >= 5:
                    patterns.append("keyword-replacement-across-topics")
            for key, start, surface in (("a", left, a), ("b", right, b)):
                row = pair[key]["row"]
                if patterns and row in records and records[row]["text"].startswith(surface, start):
                    for pattern in patterns:
                        yield row, pattern, (start, start + len(surface))


def specialist_overlays(records, pairs=(), reference_offers=(), *, include_review=False,
                        structural_evidence=None):
    """Collect original-offset evidence. Supply the already computed structural results when available."""
    results = defaultdict(lambda: defaultdict(set))
    structure = (structural.structural_overlays(records, pairs, reference_offers)
                 if structural_evidence is None else structural_evidence)
    for row, record in records.items():
        for pattern, spans in page_findings(record["text"], record["url"]).items():
            if include_review or pattern not in REVIEW_ONLY:
                results[row][pattern].update(spans)
    for row, marks in structure.items():
        for reason, spans in marks.items():
            if pattern := STRUCTURAL.get(reason):
                results[row][pattern].update(spans)
    for row, span in structural.regional_profile_intro_overlays(records, relaxed_profiles=True).items():
        results[row]["regional-landing-with-profile-stream"].add(span)
    for row, pattern, span in paired_findings(records, pairs):
        if include_review or pattern not in REVIEW_ONLY:
            results[row][pattern].add(span)
    return {row: {key: sorted(spans) for key, spans in marks.items()} for row, marks in results.items()}


# A flattened headline relay or an empty image attachment can yield only cards
# and widget extracts. Suppress those captured fragments during sentence selection.
# Other specialists can independently establish generated spam on the same page.
EXTRACTION_ONLY = {
    "single-status-route-with-a-keyword-selected-post-collection",
    "feed-item-made-of-an-outlet-credit-and-disconnected-headlines",
    "outbound-article-relay-with-headlines-in-place-of-the-story",
    "attachment-body-made-of-clipped-excerpts-glued-to-next-headlines",
    "attachment-page-with-merged-headline-teasers",
    "orphan-image-capture-with-unlabelled-merged-headlines",
    "empty-image-attachment-with-clipped-and-merged-headline-teasers",
    "numeric-feed-with-detached-headlines-and-no-article",
    "short-repost-feed-without-article-or-post-boundaries",
    "feed-entry-filled-exclusively-with-mixed-standalone-headlines",
    "numbered-forum-feed-mixing-unrelated-headlines-after-standalone-publisher-label",
    "numbered-game-feed-with-forum-headlines-and-no-original-article",
    "game-antenna-landing-with-no-article-body-and-detached-headlines",
    "browser_compatibility_notice",
    "forum-copy-notice-after-discussion",
    "heading-splits-word",
    "heading_inserted_into_katakana",
    "literary-placeholder-after-site-footer",
    "repeated_store_app_navigation",
    "retailer_repeated_widget",
    "review-platform-attribution-boilerplate",
    "unexpanded-numeric-placeholder",
    "unexpanded_numeric_placeholder",
} | {name for name, _, _ in REPEATED_PAGE_BOILERPLATE}


def blocking_spans(findings, length):
    """Convert confirmed spam evidence to document exclusions and keep extraction offsets."""
    return {reason: spans if reason in EXTRACTION_ONLY else [(0, length)]
            for reason, spans in findings.items() if spans and reason not in REVIEW_ONLY}
