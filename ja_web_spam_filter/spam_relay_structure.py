"""Identify detail pages whose entire body is an automatically assembled relay."""

import re
from collections import Counter


FEED_ITEM = re.compile(r"/(?:[^/]+/)*(?:feeds?|rss|site_id)/(?:[0-9]+|(?:item|entry|post)/[^/]+)/?$", re.I)
ARTICLE_ITEM = re.compile(r"/(?:[^/]+/)*(?:archives?|articles?|entries|posts?)/[^/]+/?$|"
                          r"/(?:[^/]+/)*20\d{2}/\d{1,2}/\d{1,2}/[^/]+/?$|/[^/]*\d[^/]*/?$", re.I)
ATTACHMENT = re.compile(r"/(?:attachment/[^/]+|(?:image|img|photo|capture|screenshot|画像|キャプチャ)"
                        r"(?:[-_0-9][^/]*)?|archives?/\d+/[^/]+)/?$", re.I)
LIST_ROUTE = re.compile(r"/(?:archives?/category|category|categories|tags?|category_id|search|ranking|page)(?:/|$)", re.I)
LIST_LABEL = re.compile(r"(?:記事一覧|記事検索|検索結果|ランキング一覧|カテゴリ一覧|過去記事の一覧|"
                        r"最近(?:の|追加した)記事|新着記事一覧|検索条件|日別アーカイブ|"
                        r"よくある(?:ご)?質問|質問一覧|質問と回答|目次|商品一覧|収録曲一覧|セットリスト)")
ARTICLE_LABEL = re.compile(r"^(?:執筆者|筆者|著者|文・写真|インタビュー|記事本文|本文|レビュー本文|"
                           r"投稿者[:：]|公開日[:：]|\d{1,3}\s*[:：]\s*[^\s]|>>\s*\d+)")
HEADLINE_MARK = re.compile(r"[!?←→]|\.{3}|w{2,}|笑{2,}|^【|[「『].{2,36}[」』]|"
                           r"(?:だろ|かよ|教えてくれ|みた結果|した結果|なんだが|な件|なんだよな)[。w]*$")
OUTLET = re.compile(r"速報|アンテナ|ちゃんねる|ニュース|ぶろぐ|まとめ|通信|news|blog", re.I)
OUTGOING = re.compile(r"^(?:このサイトの記事を見る|(?:引用元|配信元|リンク先|元サイト|元記事)で(?:記事|全文)を(?:読む|見る))$")
DATE = re.compile(r"^(?:19|20)\d{2}[-/.年]\d{1,2}[-/.月]\d{1,2}日?(?:\s.*)?$")
ENTRY_TIME = re.compile(r"^\d{1,2}(?:月|/)\d{1,2}日?\s+\d{1,2}:\d{2}$")
CLIPPED_JOIN = re.compile(r"^(.{20,110}?)(?:\.{3,}|…+)([^\s.。…].{5,86})$")
BOILERPLATE = re.compile(r"^(?:copyright\b|\(visited \d|©|all rights reserved)", re.I)
SOCIAL_ITEM = re.compile(r"/(?:t|(?:tweets?|status(?:es)?)/)[0-9]+/?$", re.I)
WORD_RUN = re.compile(r"[ぁ-ゖァ-ヺー一-龯々A-Za-z0-9]{4,}")
SOURCE_STAMP = re.compile(r"(?:twitter|x)\.com/[^\s/]+/status/|(?m:^[—―–-]\s*[^\n]{1,95}\(@[\w_]+\))|"
                          r"(?:19|20)\d{2}(?:[/年-]\d{1,2}){1,2}|"
                          r"(?m:^(?:ニュース一覧|ツイート一覧|投稿一覧|コメント一覧|出典|引用元|参加者一覧)|"
                          r"^(?:ログイン|フォロー|リポスト|返信|いいね|引用ポスト)$)", re.I)


def _keyword_post_collection(lines):
    # A search export drops the tweet IDs and timestamps and alternates short
    # display names and excerpts about the same search string. The first display
    # name sometimes disappears along with the original lead.
    for offset in (0, 1):
        authors = lines[offset:-1:2]
        posts = lines[offset+1::2]
        short_names = sum(len(name) <= 26 and "。" not in name for name in authors)
        if (len(authors) < 5 or short_names * 5 < len(authors) * 4
                or len(set(authors)) * 4 < len(authors) * 3
                or sum(len(post) >= 11 for post in posts) * 3 < len(posts) * 2):
            continue
        repeated = Counter()
        for post in posts:
            repeated.update({word[i:i+4] for word in WORD_RUN.findall(post)
                             for i in range(len(word) - 3)
                             if re.search(r"[一-龯ァ-ヺ]|^[ぁ-ゖ]{4}$", word[i:i+4])})
        # Search terms must recur in independently worded posts. Identical copies
        # or fixed headings alone cannot establish the collection structure.
        for phrase, count in repeated.items():
            if (count >= max(4, (len(posts) + 2) // 3)
                    and not any(phrase in author for author in authors)
                    and (not re.fullmatch(r"[ぁ-ゖ]+", phrase) or count * 5 >= len(posts) * 3)
                    and len({p for p in posts if phrase in p}) >= 4):
                return True
    return False


def relay_pattern(text, path):
    """Return a page-level reason for normalized text and a decoded URL path."""
    if not 80 <= len(text) <= 14000 or LIST_ROUTE.search(path):
        return None
    feed_item = FEED_ITEM.fullmatch(path)
    attachment = ATTACHMENT.search(path)
    # The numeric ID, source hostname and vocabulary of the headlines vary independently.
    social_item = SOCIAL_ITEM.fullmatch(path)
    antenna = "アンテナ" in text[:250] and ARTICLE_ITEM.fullmatch(path)
    if not (feed_item or attachment or social_item or antenna):
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 5 or any(LIST_LABEL.search(line) for line in lines[:3]):
        return None

    if attachment and 5 <= len(lines) <= 20:
        # On a broken attachment archive the title of the *next* article is glued
        # directly onto the truncated extract of the previous one, on consecutive lines.
        content = [line for line in lines if not BOILERPLATE.match(line)]
        joined = [CLIPPED_JOIN.fullmatch(line) for line in content]
        run = 0
        for line, match in zip(content, joined):
            if match:
                run += 1
            elif (run >= 3 and run >= len(content) - 3
                  and re.fullmatch(r".{12,115}(?:\.{3,}|…+)", line)
                  and line == content[-1]):
                return "attachment-body-made-of-clipped-excerpts-glued-to-next-headlines"
            else:
                run = 0

    if any(ARTICLE_LABEL.match(line) for line in lines):
        return None
    if (social_item and 11 <= len(lines) <= 65 and max(map(len, lines)) <= 280
            and not SOURCE_STAMP.search(text) and _keyword_post_collection(lines)):
        return "single-status-route-with-a-keyword-selected-post-collection"
    if antenna and len(lines) <= 19 and any("アンテナ" in line for line in lines[:3]):
        outward = next((i for i, line in enumerate(lines) if OUTGOING.fullmatch(line)), None)
        if outward is not None:
            before, after = lines[:outward], lines[outward + 1:]
            if (3 <= len(before) <= 10 and 1 <= len(after) <= 9
                    and any(DATE.fullmatch(line) for line in before)
                    and all(len(line) <= 120 and line.count("。") < 3 for line in lines)
                    and sum(len(line) >= 18 for line in before) <= 2
                    and sum(bool(HEADLINE_MARK.search(line)) for line in before + after) >= 2):
                return "outbound-article-relay-with-headlines-in-place-of-the-story"
    if feed_item and 9 <= len(lines) <= 110:
        title, credit, *headlines = lines
        credit_in_lead = (2 <= len(credit) <= min(46, len(title) + 8)
                          and ("。" not in credit and (not re.search(r"[!?]", credit) or OUTLET.search(credit))))
        multiple_outlets = sum(bool(OUTLET.search(line)) and len(line) <= 22 for line in set(lines[:10])) >= 2
        if (len(title) >= 11 and (credit_in_lead or multiple_outlets)
                and (len(lines) >= 12 or OUTLET.search(credit))
                and not any(DATE.match(line) or line.startswith(("- ", "http", "|", "●")) for line in headlines)
                and sum(bool(ENTRY_TIME.fullmatch(line)) for line in headlines) < 3
                and max(map(len, headlines)) <= 130
                and sum(len(line) >= 10 for line in headlines) * 3 >= 2 * len(headlines)
                and sum(line.count("。") >= 2 for line in headlines) * 4 <= len(headlines)
                and sum(bool(HEADLINE_MARK.search(line)) for line in headlines) >= max(4, len(headlines) // 4)
                and len(set(headlines)) * 10 >= len(headlines) * 9):
            return "feed-item-made-of-an-outlet-credit-and-disconnected-headlines"
    return None
