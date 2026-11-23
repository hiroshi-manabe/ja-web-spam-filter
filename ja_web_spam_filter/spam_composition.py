"""Full-page evidence of recurrent text assembly, independent of the publisher or URL."""

from collections import Counter
import re


REVIEW_EVIDENCE = re.compile(r"口コミ|クチコミ|評判|評価|レビュー|体験談|効果|感想|ネタバレ")
OFFER = re.compile(r"プログラム|教材|講座|マニュアル|メソッド|手法|ツール|実践者|購入者|開発者|作者")
SKEPTICISM = re.compile(r"嘘|インチキ|怪し|疑[う問]|信じ(?:て|られ)|クレーム|悪評|苦情|本当(?:に|なの|の評価)|大丈夫なの")
HEARSAY = re.compile(r"みたい|らしい|んだって|言って|いわれて|言われて|という声|っていう|という噂")
INTENT = re.compile(r"(?:試し|買っ|やっ|使っ|実践し)てみ(?:たい|よう|てもいい)|"
                    r"(?:買|や)っちゃ(?:おう|う)|信じても(?:いい|大丈夫)|試す価値")
RATING = re.compile(r"確信|納得でき|間違い(?:は)?ない|明言|よくわかります|期待以上|言えます|見ての通り")
RESEARCH = re.compile(r"情報を(?:探|集|調)|調べ(?:る|た|て)|確認し(?:た|て)|集めるのは|とことん|探してみ|検証")
REPUTATION = re.compile(r"人気の(?:理由|秘密)|認められている|認知度|話題|噂の的|話題に上が|何故.*(?:評価|認め)")
VERDICT = re.compile(r"見識|感触|総評|全体を通|結論|評価として|実感として|印象として|理由のひとつ")
REVIEW_TITLE = re.compile(r"における|に関する|の中身|の方法|の効果|について")
FIRSTHAND = re.compile(r"実際に.{0,12}(?:購入しました|届きました|使ってみました)|"
                       r"(?:使い|飲み|通い|始め)続けて|使用(?:開始|前|後)|受講(?:してから|初日)|開封し|私の(?:記録|成績|結果)")


def staged_endorsement(text):
    if not 125 <= len(text) <= 1300 or not REVIEW_EVIDENCE.search(text):
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not 5 <= len(lines) <= 60 or FIRSTHAND.search(text):
        return False
    if OFFER.search(text) and len(set(REVIEW_EVIDENCE.findall(text))) >= 2:
        if (len(set(SKEPTICISM.findall(text))) >= 2 and HEARSAY.search(text)
                and INTENT.search("\n".join(lines[-6:]))
                and sum(len(line) <= 35 for line in lines) >= 5):
            return True
    # A shorter campaign repeats the item in its headline and verdict, with
    # generalized reputation, price and research claims between them.
    if 7 <= len(lines) <= 13 and " " in lines[0]:
        product = lines[0].split(" の", 1)[0].strip()
        if (6 <= len(product) <= 90 and lines[-1].startswith(product)
                and REVIEW_EVIDENCE.search(lines[0])
                and re.search(r"人気が高い秘密|信頼される理由|何故認められて", text)
                and re.search(r"価格以上の価値|シンプルだからこそ高い効果", text)
                and RESEARCH.search("\n".join(lines[-4:-1]))
                and re.search(r"最良|最高|もっとも|最も|ベスト", lines[-1])
                and RATING.search(lines[-1])):
            return True
    # Product name and subject can change while the judgment, research and popularity
    # claims occupy separate slots in the same short, self-referential endorsement.
    return (REVIEW_EVIDENCE.search(lines[0]) is not None
            and len(RATING.findall(text)) >= 2 and RESEARCH.search(text) is not None
            and REPUTATION.search(text) is not None and VERDICT.search(text) is not None
            and (OFFER.search(lines[0]) is not None or REVIEW_TITLE.search(lines[0]) is not None))


CLINICAL = re.compile(r"カイロプラクティック|急性腰痛症|オステオパシー|ぎっくり腰|整体術")
ORPHAN = re.compile(r"(?m)^(?:[a-z]{1,2}\d{1,3}|[A-Z]{2}|(?:[・-]\n){3,}[・-])[ \t]*$")
DUPLICATED = re.compile(r"([一-龯々ぁ-ゖァ-ヶー]{4,22})(?:\([^\n)]{1,20}\))?\1")
DAMAGE = re.compile(r"循環ん|ていどでは|するうこと|ますで|のにアジャスト|治療法がが|症状元|にです[。.]|"
                    r"とな[.。]ります|となり[.]ます|[,、]らが|を[.。]伴|専門的な着手計画")
CLINIC_SOURCES = (
    re.compile(r"パーマー|Chiro(?:practic)?|ギリシャ語", re.I),
    re.compile(r"世界保健機関|WHO"),
    re.compile(r"手技療法|徒手(?:的)?(?:療法|矯正)|民間療法"),
    re.compile(r"サブラ[クキ]セーション|アジャストメント|マニピュレーション"),
)
DEFINITION = re.compile(r"(?m)^[「『]?(カイロプラクティック|整体|急性腰痛症|腰痛)"
                        r"(?:[ \t」』]*(?:[(「][^\n)」]{1,32}[)」]|[A-Za-z]{3,20})){0,3}"
                        r"[ \t]*(?:とは|は[、,]|は[^\n]{2,15}(?:療法|筋肉|骨格)|の(?:定義|名前|名称|命名))")
EXAM_HEAD = re.compile(r"(?m)^(?:No[. ]*|第)(\d{1,3})(?:[)章節項.]|[ \t]*$)", re.I)


def rewritten_clinical_outline(text):
    if len(text) < 230 or not CLINICAL.search(text):
        return False
    debris = bool(ORPHAN.search(text))
    errors = set(DAMAGE.findall(text))
    duplicate = bool(DUPLICATED.search(text))
    heads = Counter(DEFINITION.findall(text))
    if sum(bool(r.search(text)) for r in CLINIC_SOURCES) >= 3:
        if max(heads.values(), default=0) >= 2 and (debris or duplicate or len(errors) >= 2):
            return True
    # This related rewrite walks through the causes in separate sections,
    # leaving placeholder rows and malformed phrases within the explanations.
    if ("急性腰痛症" in text and "後腹膜" in text
            and len(set(ORPHAN.findall(text))) >= 2
            and len(set(re.findall(
                r"(?:病状|疾患)が発病する|腰(?:の|部の)?周辺痛|症状に受診を|"
                r"痛み後が良い|腰部の疼痛の人|視察で異常が見当", text))) >= 3):
        return True
    # Consecutive orphan section numbers and the copied progression through
    # examination, diagnosis and treatment corroborate scattered broken joins.
    if errors and ("神経" in text and "反射" in text and "筋力" in text and "治療" in text):
        nums = [int(n) for n in EXAM_HEAD.findall(text)]
        if sum(b == a + 1 for a, b in zip(nums, nums[1:])) >= 4 and (len(errors) >= 2 or duplicate):
            return True
    return False


PRICE_CODE = re.compile(r"(?:商品(?:番号|コード)|品番)\s*[:|]\s*[\w.-]{3,28}\s*\n"
                        r"[^\n]{0,20}(?:販売)?価格\s*[:|]\s*[¥￥]?[0-9,.]+", re.I)
BROKEN_ENTITY = re.compile(r"&[a-zA-Z]{1,6}[.,。][a-zA-Z]{1,6};")
# These are closed-class Japanese boundaries. A single comma near one of them
# also occurs in dialogue. Require different damaged words in a commerce record.
BROKEN_WORD = re.compile(r"(?:しま[.,。]す|で[.,。]した|ま[.,。]した|なっ[.,。]た|"
                         r"思[.,。]っ|でき[.,。]た|とい[.,。]う|こ[.,。]れは|"
                         r"もち[.,。]ろん|私[た達]?[.,。]ち|[あ-ん][.,。][ぁぃぅぇぉゃゅょっ][ぁ-ん]|"
                         r"[ァ-ヶ][.,。][ァィゥェォャュョッー][ァ-ヶ])")
MIXED_STOP = re.compile(r"[。][,.、]|[、,][。.]")
CODE_IN_TEXT = re.compile(r"(?<=[ぁ-ゖァ-ヶー])([A-Za-z0-9][A-Za-z0-9/_-]{2,32})(?=[ぁ-ゖァ-ヶー])")


BROKEN_INFLECTION = re.compile(
    r"しま[.,。]した|言いま[.,。]した|とし[.,。]て|とし[.,。]たら|い[.,。]る|であ[.,。]る|並[.,。]べ替"
)


INSERTED_STOCK_CODE = re.compile(r"(?<=[ぁ-ゖァ-ヶ一-龯])([A-Z]{1,8}[-_]?[0-9]{2,12})(?=[ぁ-ゖ])")
MID_CLAUSE_STOP = re.compile(r"(?:[のをはが]。(?=[ぁ-ゖ一-龯])|[ぁ-ゖ一-龯][,.][がをはのに](?=[ぁ-ゖ一-龯]))")


def polluted_catalogue(text):
    price = PRICE_CODE.search(text)
    if price is None:
        return False
    # A product card can also interrupt a longer copied narrative.
    if price.start() >= 420:
        before = set(BROKEN_INFLECTION.findall(text[max(0, price.start() - 650):price.start()]))
        after = set(BROKEN_INFLECTION.findall(text[price.end():price.end() + 850]))
        return bool(before and after and len(before | after) >= 4)
    # Repeated price cards can bracket the prose, while a stock code interrupts
    # different words inside it. Require damage in addition to repeated metadata.
    if text.count(price[0]) >= 2 and len(set(MID_CLAUSE_STOP.findall(text))) >= 2:
        repeating_codes = Counter(INSERTED_STOCK_CODE.findall(text))
        if any(count >= 2 for count in repeating_codes.values()):
            return True
    damaged = len(set(BROKEN_WORD.findall(text)))
    if damaged >= 4 or damaged >= 2 and (BROKEN_ENTITY.search(text) or len(MIXED_STOP.findall(text)) >= 3):
        return True
    insertions = Counter(CODE_IN_TEXT.findall(text))
    recurring = [token for token, count in insertions.items() if count >= 2]
    return (len(recurring) >= 2 and sum(insertions[t] for t in recurring) >= 5
            and (damaged >= 1 or BROKEN_ENTITY.search(text) is not None or MIXED_STOP.search(text) is not None))


SUPPLEMENT_TERMS = re.compile(r"サプリ(?:メント)?|ナットウキナーゼ|アスタキサンチン|DHA(?:EPA)?|EPA|乳酸菌|コラーゲン|酵素", re.I)
BROKEN_SALES_JOINS = (
    re.compile(r"(?:学術的|医学的|専門的|技術的)なんです[。.]"),
    re.compile(r"(?:定期|毎月|通販)で(?:美しい|正しい|詳しい)ような"),
    re.compile(r"(?:DHA(?:EPA)?|EPA|乳酸菌|酵素)で突然だった", re.I),
    re.compile(r"(?:サプリ(?:メント)?|酵素|ナットウキナーゼ)(?:もしくは|または)人気の"),
    re.compile(r"(?:納豆|サプリ|酵素|DHA)より飛び出してくれる", re.I),
)


def clipped_spun_supplement(text):
    if not 100 <= len(text) <= 750:
        return False
    body = text.split("\n引用をストックしました", 1)[0].strip()
    return (body.endswith(("...", "…")) and len(set(SUPPLEMENT_TERMS.findall(body))) >= 4
            and sum(bool(pattern.search(body)) for pattern in BROKEN_SALES_JOINS) >= 3)


KEYWORD_COPULA = re.compile(r"^私(?:は|が)[^\n。]{0,12}だったとき[、,]私は")
TRANSLATION_COLLISIONS = (
    re.compile(r"朗読(?:この|その|彼の|私の)"),
    re.compile(r"知られている(?:使用|利用|用途)は"),
    re.compile(r"(?:若い|すべての)公正な(?:セックス|性別)"),
    re.compile(r"(?:女性|男性|子供)のプロジェクトを(?:ドレープ|掛ける)"),
)


def short_keyword_word_salad(text, path):
    if not 75 <= len(text) <= 380 or text.count("\n") not in {1, 2}:
        return False
    topic = path.rstrip("/").rpartition("/")[2]
    if not re.fullmatch(r"[ぁ-ゖァ-ヶー一-龯々]{5,24}", topic):
        return False
    first, tail = text.split("\n", 1)
    return (topic in first and topic in tail and bool(KEYWORD_COPULA.search(first))
            and sum(bool(pattern.search(text)) for pattern in TRANSLATION_COLLISIONS) >= 2)


LOCAL_SERVICE_CARD = re.compile(
    r"(?m)^([一-龯々]{2,9})で([ぁ-ゖァ-ヶー一-龯々]{2,12})するなら[^\n]{8,90}No[.]?[0-9]{7,12}\s*$"
)
LOCAL_SLOT_DAMAGE = re.compile(
    r"ください[。.]。|(?:します|ございます)[。.]のための|(?:に|や)、のための|(?:ます|です)[。.]とは"
)


def garbled_local_service_cards(text):
    if not 350 <= len(text) <= 3700:
        return False
    headings = Counter(LOCAL_SERVICE_CARD.findall(text))
    for (place, service), count in headings.items():
        if (count >= 2 and text.count("のための" + place) >= 3
                and text.count("のための" + service) >= 2
                and len(set(LOCAL_SLOT_DAMAGE.findall(text))) >= 2):
            return True
    return False


GOSSIP_QUERY = re.compile(r"^([ぁ-ゖァ-ヶー一-龯]{1,9}) +([ぁ-ゖァ-ヶー一-龯]{1,9}) +(彼女|彼氏|結婚|破局|理由)$")
GOSSIP_JOIN_DAMAGE = (
    re.compile(r"と(?:交際|結婚)していた[。.]なんと"),
    re.compile(r"(?:この時点で|当時)[^。\n]{2,18}(?:動画|写真)は、[^。\n]{3,30}欲しいと思います"),
    re.compile(r"元気に復活してしまう(?:動画|写真)"),
    re.compile(r"(?:祝福|応援)される前に[^。\n]{5,55}(?:のが|が)(?:一番の)?原因"),
)


def garbled_gossip_query(text, path):
    if not 250 <= len(text) <= 1250 or not re.fullmatch(r"/[0-9]{4,9}/?", path):
        return False
    title, _, body = text.partition("\n")
    topic = GOSSIP_QUERY.fullmatch(title.strip())
    return (bool(topic) and body.count(topic[1] + topic[2]) >= 4
            and sum(bool(pattern.search(body)) for pattern in GOSSIP_JOIN_DAMAGE) >= 3)


INVENTED_LEMMA = re.compile(r"(?m)^「(を[ぁ-ゖ]{1,4}[一-龯々]{1,4}[くぐすつぬぶむるう])」という言葉の意味を解説[!！]")
UNSUPPORTED_ORIGIN = re.compile(r"成り立ちや由来は(?:明確には|はっきりとは)?(?:分かって|わかって)いません")


def fabricated_dictionary_entry(text):
    if not 400 <= len(text) <= 3500:
        return False
    heading = INVENTED_LEMMA.search(text)
    if not heading:
        return False
    lemma = heading[1]
    examples = re.findall(r"「[^」\n]*[一-龯ァ-ヶ]" + re.escape(lemma) + r"[^」]*」", text)
    return (text.count("「" + lemma + "」") >= 8 and len(set(examples)) >= 2
            and "読み方はなんと読む" in text and bool(UNSUPPORTED_ORIGIN.search(text))
            and text.count("古典文学") + text.count("歌舞伎") >= 2)


PLUMBING_KEYWORD = re.compile(r"通水管|通馬桶|疏通(?:管道|下水道)|清理(?:水管|馬桶)|清水溝|抽水肥")
INTERRUPTED_JAPANESE = (
    r"[ぁ-ゖ][かがさたなばまらわ]{}(?:ない|なかった)",
    r"[ぁ-ゖ]ま{}(?:す|した|たか)",
    r"[0-9][0-9,]*{}[ァ-ヶ]{3,}",
    r"[一-龯]工{}大学",
)


def inserted_foreign_service_keywords(text):
    counts = Counter(PLUMBING_KEYWORD.findall(text))
    repeated = {token for token, count in counts.items() if count >= 2}
    if len(repeated) < 2 or sum(counts[token] for token in repeated) < 6:
        return False
    slot = "(?:" + "|".join(map(re.escape, sorted(repeated))) + ")"
    return sum(bool(re.search(pattern.replace("{}", slot), text)) for pattern in INTERRUPTED_JAPANESE) >= 2


FUNERAL_TERMS = re.compile(r"会葬礼[品状]|精進落とし|遷霊祭|戒名|献灯|野辺送り|湯灌|墓地|神職|日供|延命治療|納棺|葬儀社|エンバーミング|後飾り|釘打ち")
CANNED_REACTIONS = re.compile(r"とは難儀|バカみたいですね|胡散臭いに決ま|なるべく黙殺|誰か金ください|の野郎が|咲き乱れる必要|わななくでしょう")
UNRELATED_ABSTRACTIONS = re.compile(r"結合価|理性批判|意識の機能|同一性を保持")


def assembled_funeral_word_salad(text):
    return (200 <= len(text) <= 1800 and len(set(FUNERAL_TERMS.findall(text))) >= 7
            and len(set(CANNED_REACTIONS.findall(text))) >= 3
            and len(set(UNRELATED_ABSTRACTIONS.findall(text))) >= 2)


REPEATED_COUNTED_PHRASE = re.compile(r"([0-9]{2,4}の[ァ-ヶー]{3,14})の\1")
UNRELATED_GAME_FRAGMENTS = re.compile(r"報酬GET|時間を追加し|中間の株スタート|[〈<][0-9]{1,3}対[〉>]|がゲームを見る")
VIDEO_LOCALIZATION_PATH = re.compile(r"/(?:Duga|Mgs|Dti)/[A-Za-z0-9]+/(?:gallery)?[0-9]+/index\.html", re.I)


def localized_video_with_duplicated_game_prose(text, path):
    return (90 <= len(text) <= 625 and bool(VIDEO_LOCALIZATION_PATH.fullmatch(path))
            and bool(REPEATED_COUNTED_PHRASE.search(text))
            and len(set(UNRELATED_GAME_FRAGMENTS.findall(text))) >= 3)


MIXED_MANGA_QUERY = re.compile(r"[一-龯]{4}(?:完整版|免费版)[0-9]{1,5}(?:漫画|章节|话)")
JAPANESE_CLAUSE_ENDING = re.compile(r"(?:だった|していた|でしょう|わけではない|を教えてくれた|のように|てきたのか)")
CHINESE_QUERY_TERMS = re.compile(r"免费|话本|高清|图组|组图|被禁|完整版|来源")


def mixed_script_manga_keyword_assembly(text):
    if not 200 <= len(text) <= 3200 or not text.rstrip().endswith("来源:"):
        return False
    if len(set(CHINESE_QUERY_TERMS.findall(text))) < 4:
        return False
    queries = Counter(MIXED_MANGA_QUERY.findall(text))
    for query, count in queries.items():
        if count >= 3 and sum(query in line and bool(JAPANESE_CLAUSE_ENDING.search(line))
                              for line in text.splitlines()) >= 2:
            return True
    return False


SAME_TARGET_REPLIES = re.compile(r"(?m)^(?:>>|≫)\s*(\d+)\s+([^\n]{1,40})[ \t]*$")
VIDEO_CREDIT = re.compile(r"(?im)^\s*powered by auto youtube summarize\s*$")


def manufactured_video_replies(text):
    if not VIDEO_CREDIT.search(text):
        return False
    preamble, separator, description = text.lower().partition("this is description")
    if not separator or len(preamble.splitlines()) < 4:
        return False
    replies = SAME_TARGET_REPLIES.findall(description[-350:])
    if len(replies) < 3 or len({ref for ref, _ in replies}) != 1:
        return False
    return (len({msg.strip() for _, msg in replies}) >= 3
            and sum(3 <= len(line.strip()) < 60 for line in preamble.splitlines()) >= 3)


def composition_findings(text):
    """Yield whole-page specialist identifiers for NFKC-normalized text."""
    if staged_endorsement(text):
        yield "staged-product-endorsement-without-firsthand-use"
    if rewritten_clinical_outline(text):
        yield "repeated-clinical-definitions-with-template-damage"
    if polluted_catalogue(text):
        yield "catalogue-with-multiple-interrupted-word-boundaries"
    if clipped_spun_supplement(text):
        yield "clipped-supplement-copy-with-multiple-broken-joins"
    if garbled_local_service_cards(text):
        yield "local-service-card-with-broken-place-and-service-slots"
    if fabricated_dictionary_entry(text):
        yield "fabricated-dictionary-entry-from-object-particle"
    if inserted_foreign_service_keywords(text):
        yield "foreign-service-keywords-inserted-within-japanese-words"
    if assembled_funeral_word_salad(text):
        yield "funeral-vocabulary-in-unrelated-canned-clauses"
    if mixed_script_manga_keyword_assembly(text):
        yield "mixed-script-manga-keywords-in-incompatible-prose"
    if manufactured_video_replies(text):
        yield "video-description-enclosed-by-manufactured-same-target-replies"
