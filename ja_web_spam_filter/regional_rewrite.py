"""Find long, ordered paraphrases reused on commercial municipality routes."""

from collections import Counter, defaultdict
from itertools import combinations
import re
from urllib.parse import unquote, urlsplit

from .word_salad_filter import normalize


PROMOTIONAL = re.compile(r"契約|料金|お得|無料|費用|キャンペーン|価格|プラン|コース|申込|評判|比較|相談")
CLAUSE = re.compile(r"[^。！？!?\r\n]{28,280}[。！？!?]")
CONTENT = re.compile(r"[一-龯ァ-ヶ].*[一-龯ァ-ヶ]")
GEO_END = re.compile(r"[都道府県市町村区]")


def municipality_route(url):
    """Return a verified prefecture and municipality pair supplied by the route."""
    try:
        parts = unquote(urlsplit(url).path).strip("/").split("/")
    except ValueError:
        return None
    candidates = [(a, b) for a, b in zip(parts, parts[1:])
                  if GEO_END.search(a[-1:]) and GEO_END.search(b[-1:])]
    if not candidates:
        return None
    from template_index import _place_hierarchy

    labels, _, _ = _place_hierarchy()
    return next((pair for pair in candidates if pair in labels), None)


def _anchors(text):
    grams = (text[i:i + 8] for i in range(len(text) - 7))
    return {gram for gram in grams if CONTENT.search(gram)}


def _clauses(text):
    result = []
    for match in CLAUSE.finditer(text):
        surface = "".join(normalize(match[0]).split())
        anchors = _anchors(surface)
        if anchors:
            result.append((match.span(), surface, anchors))
        if len(result) >= 42:
            break
    return result


def ordered_matches(left, right):
    """Find an increasing alignment of clauses that share substantial wording."""
    paths = {}
    for i, (_, a, words_a) in enumerate(left):
        row = {}
        for j, (_, b, words_b) in enumerate(right):
            count = len(words_a & words_b)
            if count < 5 or count < .12 * min(len(words_a), len(words_b)):
                continue
            previous = max((path for index, path in paths.items() if index < j), key=len, default=())
            row[j] = (*previous, (i, j, a != b))
        for j, path in row.items():
            if len(path) > len(paths.get(j, ())):
                paths[j] = path
    return max(paths.values(), key=len, default=())


def regional_rewrite_pairs(records):
    """Yield plausible paraphrase campaigns and raw offsets for corroborated spans."""
    indexed = {}
    inverted = defaultdict(set)
    for row, record in records.items():
        text = record["text"]
        if not 500 <= len(text) <= 6000:
            continue
        place = municipality_route(record["url"])
        if not place or len(set(PROMOTIONAL.findall(normalize(text)))) < 2:
            continue
        clauses = _clauses(text)
        if len(clauses) < 6:
            continue
        indexed[row] = (place, clauses)
        for anchor in set().union(*(entry[2] for entry in clauses)):
            inverted[anchor].add(row)
    scores = Counter()
    for hits in inverted.values():
        if 2 <= len(hits) <= 16:
            scores.update(combinations(sorted(hits), 2))
    for (a, b), count in sorted(scores.items()):
        if count < 60:
            continue
        loc_a, left = indexed[a]
        loc_b, right = indexed[b]
        if loc_a == loc_b:
            continue
        aligned = ordered_matches(left, right)
        if len(aligned) < 6 or sum(changed for _, _, changed in aligned) < 4:
            continue
        yield a, b, [(left[i][0], right[j][0]) for i, j, _ in aligned]


def regional_copy_overlays(records):
    """Mark corroborated prose, or the whole page with broad independent coverage."""
    from register_audit import name_of_site

    spans = defaultdict(set)
    widely_repeated = defaultdict(set)
    sizes = {}
    for left, right, matches in regional_rewrite_pairs(records):
        for side, row, peer in ((0, left, right), (1, right, left)):
            spans[row].update(match[side] for match in matches)
            if row not in sizes:
                sizes[row] = len(_clauses(records[row]["text"]))
            if len(matches) >= 8 and len(matches) >= .60 * sizes[row]:
                hostname = urlsplit(records[peer]["url"]).hostname
                if hostname:
                    widely_repeated[row].add(name_of_site(hostname))
    for row, hosts in widely_repeated.items():
        if len(hosts) >= 2:
            spans[row] = {(0, len(records[row]["text"]))}
    return spans
