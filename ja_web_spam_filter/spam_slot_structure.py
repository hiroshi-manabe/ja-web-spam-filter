"""Detect generated slots using relationships among fields in the normalized document."""

from collections import Counter, defaultdict
import re


AGE_BLOCK = re.compile(r"(?:誕生|\d{1,2}(?:歳|才|代))\s*(?:から|[~〜―–-])\s*(?:晩年|\d{1,2}(?:歳|才|代))")
PERSON_VALUE = re.compile(r".{1,15}(?:い|な|の|た|イ)(?:[一-龯々]{1,5}(?:さん|氏)|[A-Z][・.][A-Z]\(イニシャル\))$")
MODIFIED_NOUN = re.compile(r".{1,12}(?:い|な|の|た|ある)[ァ-ヺー一-龯々]{1,15}$")
COLOUR_ITEM = re.compile(r"(?:[^の]{1,6}色の|[赤青黄黒白]い|ピンクの|グリーンの)")
READING_CREDIT = re.compile(r"(?:執筆|監修|鑑定歴|著者紹介|得意な占術)")
NAME_FORTUNE = re.compile(r"姓名判断|姓名の字画|名前[のを].{0,6}(?:字画|姓名)|[天地人総]格\s*\d+画")
FIELD_NAMES = {"人": "person", "人物": "person", "物": "item", "もの": "item",
               "アイテム": "item", "場所": "place", "スポット": "place"}
JOB_OFFER = re.compile(r"求人|採用|募集|バイト|アルバイト|転職|キャッシング|融資|借入")
SEARCH_CHROME = re.compile(r"検索(?:され(?:てい|てお|てる|い?ま)|すれば|して(?:み|見))|"
                           r"(?:よく|多く)検索|(?:関連する|検索の|検索されている)キーワード")
SEARCH_REPORT = re.compile(r"検索され|検索(?:の|する)キーワード|関連キーワード")
LOCAL_TOKEN = re.compile(r"[一-龯々ァ-ヶ]{1,15}[駅市区町村郡](?:周辺|近辺|付近|近く)|"
                         r"[一-龯々]{2,12}[市区町村]の")
JOB_DETAIL = re.compile(r"(?:時給|月給|年収|給与)\s*[:¥]?\s*\d[\d,.]{1,8}\s*(?:万)?円|"
                        r"(?:仕事内容|応募資格|雇用形態|就業時間|勤務時間)\s*[:|]")
SALUTATION = re.compile(r"(?:この|当)(?:サイト|ページ|ホームページ)は[、 ]*(?P<area>[ぁ-ゖァ-ヺ一-龯々]{1,14}?)の"
                        r"(?P<audience>[^\n、。]{5,22})[、,](?P=area)(?P<offer>[^\n。…]{2,38})")


def _random_compatibility(text):
    # The same panel assigns described strangers, objects and places in pairs.
    # Stroke totals alone and ordinary lucky colours or places are common.
    if (not NAME_FORTUNE.search(text) or len(set(AGE_BLOCK.findall(text))) < 3
            or READING_CREDIT.search(text)):
        return False
    for heading in re.finditer(r"(?:吉運|凶運|幸運|不運|運勢)の相性", text):
        fields = {}
        current = None
        for line in text[heading.end():heading.end() + 550].splitlines():
            line = line.strip(" \t-・●■|:【】")
            if line in FIELD_NAMES:
                current = FIELD_NAMES[line]
                fields[current] = []
            elif current and 2 <= len(line) <= 28 and len(fields[current]) < 2:
                fields[current].append(line)
            else:
                current = None
        people = fields.get("person", [])
        objects = fields.get("item", []) + fields.get("place", [])
        if (len(set(people)) == 2 and all(PERSON_VALUE.fullmatch(word) for word in people)
                and not all(COLOUR_ITEM.match(word) for word in fields.get("item", []))
                and len(set(objects)) == 4 and sum(bool(MODIFIED_NOUN.fullmatch(word)) for word in objects) >= 3):
            return True
    return False


def _repeated_local_pitch(text):
    # One local heading reused for several sections and stuffed back into the
    # continuous sales prose, with no wage or application detail of its own.
    if JOB_DETAIL.search(text):
        return False
    headings = defaultdict(set)
    for line in text.splitlines():
        if not 8 <= len(line) <= 70 or not JOB_OFFER.search(line):
            continue
        segments = line.split()
        if len(segments) >= 3 and len(segments[0]) <= 10:
            headings[tuple(segments[:-1])].add(segments[-1])
    prose = "\n".join(line for line in text.splitlines() if len(line) > 70)
    for tokens, suffixes in headings.items():
        if (len(suffixes) >= 4 and len(tokens[0]) >= 2 and len(set(tokens)) >= 2
                and prose.count(tokens[0] + "の") >= len(suffixes)
                and any(prose.count(token) >= 3 for token in tokens[1:])):
            return True
    return False


def _rotating_local_audience(text):
    if "サイトは" not in text and "ページは" not in text and "ホームページは" not in text:
        return False
    localities = defaultdict(set)
    for instance in SALUTATION.finditer(text):
        offer = instance["offer"].replace(instance["area"], "#")
        if JOB_OFFER.search(offer):
            localities[instance["audience"], offer[:9]].add(instance["area"])
    return any(len(areas) >= 4 for areas in localities.values())


def _reader_address_offer(text):
    if not ("郵便番号" in text and "住所" in text and not JOB_DETAIL.search(text)):
        return False
    reader = re.search(r"(?m)^([^。!?\n]{3,28}[市区町村郡][^。!?\n]{0,16})にお住まいの", text[:650])
    return (reader and text[:reader.start()].count(reader[1]) >= 1
            and re.search(r"お住まいの(?:地域|住所|エリア)(?:情報)?[|:]", text)
            and re.search(r"郵便番号[| :〒]*(?:\d{3}-?\d{4})", text)
            and re.search(r"住所[ (]*(?:ひらがな|フリガナ|読み|かな)", text)
            and re.search(r"(?:申[し込]|登録|エントリー)[^。\n]{0,15}(?:こちら|受付|窓口)", text))


STATION_FIELDS = re.compile(r"(?m)^\|駅名[ \t]*\n?\|\|([^|\n]{2,18}駅)")
STATION_QUERY = re.compile(r"([一-龯々ぁ-ゖァ-ヶー]{2,14}駅)(?:周辺|近く|付近)の")
LENDER_PITCH = re.compile(r"融資|キャッシング|お金を借り|審査|借[り入]")


def _station_loan_with_other_locations(text):
    station = STATION_FIELDS.search(text)
    if not station or not re.search(r"駅名.{0,10}(?:ひらがな|フリガナ|読み)", text):
        return False
    head = text[:station.start()]
    alternatives = set(STATION_QUERY.findall(head)) - {station[1]}
    return (len(alternatives) >= 2 and head.count(station[1]) >= 3
            and len(set(LENDER_PITCH.findall(head))) >= 3
            and bool(re.search(r"調べると|情報がたくさん|検索すると", head))
            and bool(re.search(r"(?:来店|来訪)不要|即日(?:融資|キャッシング)", head)))


def slot_structure_findings(text):
    """Yield whole-page findings for NFKC-normalized Japanese text."""
    if "相性" in text and _random_compatibility(text):
        yield "name-fortune-with-generated-person-item-place-pairs"
    if not JOB_OFFER.search(text):
        return
    if _station_loan_with_other_locations(text):
        yield "station-loan-offer-padded-with-other-station-queries"
    for mention in SEARCH_REPORT.finditer(text):
        # Search words, localities and the offer must co-occur. Long archives
        # can contain all three in unrelated articles thousands of lines apart.
        passage = text[max(0, mention.start() - 550):mention.end() + 550]
        locations = Counter(LOCAL_TOKEN.findall(passage))
        if (len(locations) >= 2 and (len(locations) >= 4 or max(locations.values()) >= 3)
                and JOB_OFFER.search(passage) and len(SEARCH_CHROME.findall(passage)) >= 2
                and not JOB_DETAIL.search(passage)):
            yield "local-offer-filled-with-interchangeable-search-queries"
            break
    if ("求人" in text or "募集" in text) and (_repeated_local_pitch(text) or _rotating_local_audience(text)):
        yield "recruitment-doorway-with-rotating-heading-or-audience-slots"
    if ("転職" in text or "求人" in text) and _reader_address_offer(text):
        yield "recruitment-pitch-with-reader-address-in-place-of-a-vacancy"
