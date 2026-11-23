"""Apply reviewed URL scopes for spam and corpus source formats in the pinned FineWeb2 snapshot."""

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .regional_rewrite import municipality_route


DEFAULT_REGISTRY = Path(__file__).with_name("spam_publisher_blocklist.json")
HEADLINE_NETWORKS = {"warotamaker.com", "warotamaker2.com", "warotagamer.com"}
HEADLINE_FORM = "reviewed-headline-feed-route"
SOCIAL_FORM = "reviewed-social-keyword-roundup-route"
SOURCE_FORM_STAGES = {HEADLINE_FORM: "headline_navigation", SOCIAL_FORM: "social_keyword_roundup"}
SOCIAL_ROUNDUPS = {
    ("jazong.com:nineteen-digit-tweet-search-pages", "jazong.com", "nineteen_digit_tweet_scrape", None, None, ""),
    ("voyalamoda.com:fragmented-post-montage", "voyalamoda.com", "numbered_slug", "/t", 19, ""),
}
ARCHIVE_DATE = re.compile(r"(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])?")
ARCHIVE_PAGE = re.compile(r"[1-9][0-9]{0,5}")
ROUTE_SHAPES = {
    "localized_duga24_gallery": re.compile(r"/Duga/Duga24/gallery24[0-9]{3}/index\.html"),
    "dated_funeral_word_salad": re.compile(r"/201[34](?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])\.html"),
    "numbered_affiliate_course_reviews": re.compile(r"/(?:韓国語|英語|ダンス)/[0-9]{4}"),
    "foreign_host_retail_namespace": re.compile(
        r"/(?:daishinshop/[0-9]{4}[a-z]{4}[0-9]{4}-[0-9]{7}|ikebe-rockhouse/[0-9]{5}[a-z]{4}[0-9]{6})\.htm"
    ),
    "generated_resale_post": re.compile(r"/s[a-z0-9]{0,3}ux[a-z0-9]{4,6}/post\.htm"),
    "four_digit_clipped_snippet_html_route": re.compile(r"/[a-z]-[0-9]{4}\.html"),
    "three_digit_clipped_snippet_php_route": re.compile(r"/[a-z]-[0-9]{3}\.php"),
    "clipped_snippet_php_route": re.compile(r"/[a-z]-[0-9]{4,5}\.php"),
    "three_digit_root_affiliate": re.compile(r"/[0-9]{3}"),
    "six_digit_video_catalogue_view": re.compile(r"/av/view/[0-9]{6}\.html"),
    "six_digit_media_teaser_archive": re.compile(r"/archives/[0-9]{6}"),
    "copied_automotive_article": re.compile(r"/articles/(?:-|amp|gallery)/[0-9]{5}"),
    "five_digit_root_article": re.compile(r"/[0-9]{5}"),
    "regional_vehicle_locksmith": re.compile(r"/area/[a-z]{4,20}(?:ken|fu|to|do)/[a-z]{3,28}(?:shi|cho|machi|mura|son|ku)"),
    "earnings_slots": re.compile(r"/cate_[a-z0-9]{8}/cont_[a-z0-9]{8}"),
    "station_loan_money": re.compile(r"/([a-z]+)/(\1_[0-9]{1,3})/\2_money[0-9]{1,4}\.html"),
    "station_loan_yushi": re.compile(r"/([a-z]+)/(\1_[0-9]{1,3})/\2_yushi[0-9]{1,4}\.html"),
    "auction_lot": re.compile(r"/[^/]{2,55}-rc-[0-9]{2}"),
    "encoded_tag_slug": re.compile(r"/tag/[a-z0-9-]{2,110}-(?:[a-f0-9]{2}){5,55}"),
    "dated_mahjong_snippets": re.compile(r"/20[0-9]{2}/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/"
                                           r"[^/]{2,60}雀荘[^/]{4,65}"),
    "green_juice_doorway": re.compile(r"/美味しい青汁[^/]{5,50}"),
    "dated_clinic_rewrites": re.compile(r"/20[0-9]{2}/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/"
                                        r"(?=[^/]*(?:整体|矯正|カイロ))[^/]{2,75}-[0-9]{1,3}"),
    "regional_board_landing": re.compile(r"/(?:line/[^/]{1,10}lineid交換募集掲示板/[^/]{2,15}lineid交換募集掲示板"
                                         r"|sirouto/[^/]{1,10}素人掲示板/[^/]{2,15}素人掲示板)"),
    "localized_dti_detail": re.compile(r"/Dti/[A-Za-z]{3,24}[0-9]/[0-9]{4,5}/index\.html"),
    "localized_mgs_detail": re.compile(r"/Mgs/Mgs[0-9]/gallery[0-9]{3,5}/index\.html"),
    "cloned_outlet_item": re.compile(r"/(?:a-price/[0-9]{5}[a-z]{4}[0-9]{13}"
                                    r"|egaos/[0-9]{4}[a-z]{8}[0-9]{4})"),
    "fashion_listing_codes": re.compile(r"/[0-9]{4,5}[a-z][a-z0-9]{10,13}/[a-f0-9]{5,9}\.html?"),
    "dictionary_retail_items": re.compile(r"/[a-z]{7,22}/[A-Za-z]{8,24}[0-9]{6}\.html"),
    "translated_question_articles": re.compile(r"/(?:what-(?:is|are)|how-do-you)(?:-[a-z]{2,22}){3,12}"),
    "station_childcare_jobs": re.compile(r"/([a-z]{3,16}(?:ken|fu|to|do))/(\1_[0-9]{1,3})/\2_kyujin[0-9]{1,4}\.html"),
    "night_work_slots": re.compile(r"/(?:livechat|sexycabaretclub|girlsbar|seikan|fuzoku|deliveryhealth)/[0-9]{3,4}"),
    "live_chat_slots": re.compile(r"/livechat/[0-9]{4}"),
    "night_job_ad_slots": re.compile(r"/(?:snack|nghtwork|chatlady)/[0-9]{3,4}"),
    # Kept for replaying older registries. No current publisher uses this route.
    "archive_attachment_slug": re.compile(r"/archives/[0-9]+/[^/]+"),
    "dated_story_attachment_splices": re.compile(r"/post-[0-9]{3,4}/attachment/[0-9]{3,4}"),
    "coded_merchant_snippet_pages": re.compile(r"/aa10[0-9]{8}/cc10[0-9]{8}\.html"),
    "mixed_review_catalogue": re.compile(r"/aws/rev/[0-9]{5,6}\.php"),
    "five_digit_game_antenna_posts": re.compile(r"/archives/[0-9]{5}"),
    "six_digit_game_antenna_posts": re.compile(r"/archives/[0-9]{6}"),
    "four_digit_localized_article_scrape": re.compile(r"/[0-9]{4}(?:-[a-z0-9]{1,22}){3,18}\.html"),
    "dated_canned_question_diary": re.compile(r"/date/201[78]/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])"),
    "dated_stock_housing_diary": re.compile(r"/entry/201[568]/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/061[34][0-5][0-9]"),
    "nineteen_digit_tweet_scrape": re.compile(r"/t[0-9]{19}"),
    "dated_2020_2021_news_splice": re.compile(r"/202[01]/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/"
                                              r"(?=[^/]*[ぁ-ゖァ-ヺ一-龯])[^/]{8,160}"),
    "eight_digit_headline_feed": re.compile(r"/feed/[0-9]{8}"),
    "nine_digit_headline_feed": re.compile(r"/feed/[0-9]{9}"),
    "six_digit_compiled_faq": re.compile(r"/[0-9]{6}"),
    "scraped_catalogue_fiction": re.compile(r"/(?:c16h10|spewiness)/[0-9]{6}\.html"),
    "desertful_catalogue": re.compile(r"/desertful/[0-9]{6}\.html"),
    "mirrored_image_post": re.compile(r"/pornogratuites/blog-entry-[0-9]{5}\.html"),
    "retail_epoophoron_listing": re.compile(r"/epoophoron/[0-9]{5}\.html"),
    "spun_buyback_html": re.compile(r"/買取[^/]{2,55}\.html"),
    "dated_renovation_montage": re.compile(r"/entry/201[6-8]/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{6}"),
    "dated_affiliate_montage": re.compile(r"/entry/2018/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/[0-9]{6}"),
    "scheduled_2017_collage": re.compile(r"/entry/2017/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/0650[0-5][0-9]"),
    "dated_zzvor_clinic_archive": re.compile(r"/(?:zzvor(?:28asuka|30rie|32ryou)/201[67]|zzvor67ami/201[79])/"
                                             r"(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])"),
    "stock_endorsement_topics": re.compile(r"/(?:水泳|アンチエイジング|うつ病|書道|チック症)/[0-9]{4,5}"),
    "multilingual_keyword_html": re.compile(r"/[a-z0-9]{5,10}/[0-9]{4}\.html"),
    "casino_snippet_date": re.compile(r"/2021/02/26/(?=[^/]*(?:カジノ|スロット|決闘))[^/]{8,65}"),
    "merchant_coupon_slugs": re.compile(r"/promo/(?:[a-z0-9-]+\.)+[a-z]{2,12}"),
}
PATH_LIST_SCOPES = {"date_archive", "numbered_clinic_post"}
QUERY_SCOPES = {"exact_query", "exam_query", "reverse_exam_query"}
PATH_SCOPES = {"path_prefix", "numbered_slug", *QUERY_SCOPES}
CODED_RETAIL_QUERY = re.compile(r"[a-z]{4}(?:-[0-9][a-z]{2,15}[0-9]{3,5}[a-z]{2,9}-[0-9]{5}-[a-z]{2}"
                                r"|/[0-9]{2}[a-z]{4,14}[0-9][a-z][0-9]{15})")
INJECTED_RETAIL_QUERY = re.compile(r"[a-z]{7}[0-9]{5}[a-z][a-z0-9]{2,8}(?:-[a-z0-9-]{2,30}/[0-9]{2,10})?\.htm")
DASHED_RETAIL_QUERY = re.compile(r"[a-z]{7}-[0-9]{5,6}[a-z][a-z0-9]{6,18}(?:/[a-z0-9]{5,12})?\.htm")
EXAM_OFFER_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,68}_(?=[^-]*[ぁ-ゖァ-ヺー一-龯々])"
                             r"[ぁ-ゖァ-ヺー一-龯々A-Za-z0-9]{2,40}-[0-9]{6}")
REVERSE_EXAM_OFFER_SLUG = re.compile(r"(?=[^/]*[ぁ-ゖァ-ヺー一-龯々])"
                                    r"[ぁ-ゖァ-ヺー一-龯々A-Za-z0-9]{2,36}-[0-9]{6}/"
                                    r"[A-Za-z0-9][A-Za-z0-9_.-]{1,60}-exam\.html")
CLINIC_POST = re.compile(r"(/[a-zA-Z0-9_-]+)/20[0-9]{2}/(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/"
                        r"(?=[^/]*(?:整体|矯正|カイロ))[^/]{2,65}-[0-9]{1,3}")


def calendar_archive(query):
    try:
        args = parse_qs(query, keep_blank_values=True, max_num_fields=16)
    except ValueError:
        return False
    months = args.get("m", [])
    pages = args.get("paged", [])
    return (args.keys() <= {"m", "paged"} and len(months) == 1 and bool(ARCHIVE_DATE.fullmatch(months[0]))
            and (not pages or len(pages) == 1 and bool(ARCHIVE_PAGE.fullmatch(pages[0]))))


class PublisherBlocklist:
    def __init__(self, path=DEFAULT_REGISTRY):
        raw = Path(path).read_bytes()
        registry = json.loads(raw)
        self.revision = registry["evidence_revision"]
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.rules = defaultdict(list)
        self.form_rules = defaultdict(list)
        self.form_reasons = {}
        seen = set()
        for item in registry["scopes"]:
            host, kind, name = (item[key] for key in ("host", "scope", "id"))
            prefix = item.get("path")
            paths = item.get("paths")
            digits = item.get("digits")
            query_key = item.get("query_key")
            suffix = item.get("suffix", "")
            if (not name or name in seen or not host or host != host.lower().removeprefix("www.")
                    or any(c in host for c in "/:@?#* ") or host.endswith(".")
                    or kind not in {"municipality", "host_date_archive", "dictionary_retail_query", "coded_retail_query", "injected_retail_query", "dashed_retail_query", *PATH_SCOPES, *PATH_LIST_SCOPES, *ROUTE_SHAPES}
                    or kind not in PATH_SCOPES and prefix is not None
                    or kind in PATH_SCOPES and (
                        not isinstance(prefix, str) or not prefix.startswith("/")
                        or (kind != "numbered_slug" and prefix != (prefix.rstrip("/") or "/"))
                        or (kind == "numbered_slug" and "//" in prefix))
                    or kind in PATH_LIST_SCOPES and (
                        not isinstance(paths, list) or not paths or any(
                            not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_-]+", path)
                            for path in paths))
                    or kind not in PATH_LIST_SCOPES and paths is not None
                    or kind == "numbered_slug" and (
                        type(digits) is not int or not 1 <= digits <= 22
                        or not isinstance(suffix, str) or suffix not in {"", ".html", ".htm"} or prefix == "/" and not suffix)
                    or kind != "numbered_slug" and "suffix" in item
                    or kind != "numbered_slug" and digits is not None
                    or kind in QUERY_SCOPES and (not isinstance(query_key, str)
                                                  or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", query_key))
                    or kind not in QUERY_SCOPES and query_key is not None):
                raise ValueError(f"Invalid publisher blocklist scope {name!r}")
            registered_domain = ".".join(host.split(".")[-2:])
            feed = (kind in {"eight_digit_headline_feed", "nine_digit_headline_feed"}
                    or kind == "numbered_slug" and prefix == "/feed/" and digits in {8, 9} and not suffix)
            if registered_domain in HEADLINE_NETWORKS and feed:
                self.form_reasons[name] = HEADLINE_FORM
            elif (name, host, kind, prefix, digits, suffix) in SOCIAL_ROUNDUPS:
                self.form_reasons[name] = SOCIAL_FORM
            rules = self.form_rules if name in self.form_reasons else self.rules
            rules[host].append((kind, prefix, name, frozenset(paths or ()), digits, query_key, suffix))
            seen.add(name)

    def match(self, url):
        """Return a reviewed spam scope for this URL."""
        return self._match(url, self.rules)

    def headline_feed_scope(self, url):
        """Return a reviewed exact-host feed scope used in sentence selection."""
        form = self.source_form(url)
        return form[1] if form and form[0] == HEADLINE_FORM else None

    def source_form(self, url):
        """Return (extraction reason, reviewed scope ID) for a sentence-only exclusion."""
        if scope := self._match(url, self.form_rules):
            return self.form_reasons[scope], scope
        return None

    @staticmethod
    def _match(url, by_host):
        try:
            address = urlsplit(url)
            host = (address.hostname or "").rstrip(".").removeprefix("www.")
        except ValueError:
            return None
        rules = by_host.get(host)
        if not rules or address.scheme not in {"http", "https"}:
            return None
        path = unquote(address.path).rstrip("/") or "/"
        for kind, prefix, name, paths, digits, query_key, suffix in rules:
            if kind == "path_prefix" and (prefix == "/" or path == prefix or path.startswith(prefix + "/")):
                return name
            if (kind == "host_date_archive" or kind == "date_archive" and path in paths) and calendar_archive(address.query):
                return name
            if kind == "numbered_clinic_post" and not address.query:
                if (post := CLINIC_POST.fullmatch(path)) and post[1] in paths:
                    return name
            if kind == "numbered_slug" and path.startswith(prefix):
                remainder = path[len(prefix):]
                number = remainder.removesuffix(suffix)
                if (remainder.endswith(suffix) and len(number) == digits
                        and number.isascii() and number.isdecimal()):
                    return name
            if kind in ROUTE_SHAPES and not address.query and ROUTE_SHAPES[kind].fullmatch(path):
                return name
            if kind == "dictionary_retail_query" and path == "/index.php" and re.fullmatch(
                    r"[a-z]{7,14}/[a-z]{6,16}[0-9]{7}\.html", address.query):
                return name
            if kind == "coded_retail_query" and path == "/index.php" and CODED_RETAIL_QUERY.fullmatch(address.query):
                return name
            if kind == "injected_retail_query" and path == "/wander.php" and INJECTED_RETAIL_QUERY.fullmatch(address.query):
                return name
            if kind == "dashed_retail_query" and path == "/wander.php" and DASHED_RETAIL_QUERY.fullmatch(address.query):
                return name
            if kind in QUERY_SCOPES and path == prefix:
                try:
                    args = parse_qs(address.query, keep_blank_values=True, max_num_fields=8)
                except ValueError:
                    continue
                if args.keys() == {query_key} and len(args[query_key]) == 1:
                    value = args[query_key][0]
                    if (kind == "exact_query" and value.strip()
                            or kind == "exam_query" and EXAM_OFFER_SLUG.fullmatch(value)
                            or kind == "reverse_exam_query" and REVERSE_EXAM_OFFER_SLUG.fullmatch(value)):
                        return name
            if kind == "municipality":
                location = municipality_route(url)
                if location and path == "/" + "/".join(location):
                    return name
        return None

    def receipt(self):
        files = ("spam_publisher_blocklist.py", "regional_rewrite.py", "template_index.py",
                 "locality_templates.py", "jp_municipalities.txt")
        return {"registry_sha256": self.sha256, "evidence_revision": self.revision,
                "files_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                 for name in files}}
