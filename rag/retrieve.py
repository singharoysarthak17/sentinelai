import math
import re
from collections import Counter
from functools import lru_cache

from rag.kb import Chunk, load_chunks

STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "is", "are", "be",
        "by", "with", "from", "that", "this", "it", "as", "at", "any"}


def _stem(t: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if t.endswith(suffix) and len(t) - len(suffix) >= 4:
            t = t[: -len(suffix)]
            break
    return t[:-1] if t.endswith("e") and len(t) > 4 else t


def tokenize(text: str) -> list[str]:
    return [_stem(t) for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOP]

class BM25:
    """Okapi BM25 with Lucene-style IDF (always positive, safe on tiny corpora)."""

    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.tfs = [Counter(d) for d in docs]
        self.lens = [len(d) for d in docs]
        self.avgdl = sum(self.lens) / len(docs)
        df: Counter = Counter()
        for d in docs:
            df.update(set(d))
        n = len(docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def score(self, query: list[str], i: int) -> float:
        tf, dl, s = self.tfs[i], self.lens[i], 0.0
        for t in query:
            f = tf.get(t, 0)
            if f:
                s += self.idf[t] * f * (self.k1 + 1) / (
                    f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s


@lru_cache(maxsize=1)
def _kb() -> tuple[list[Chunk], list[str]]:
    return load_chunks()


def quarantined_docs() -> list[str]:
    return _kb()[1]


@lru_cache(maxsize=None)
def _index_for(role: str):
    # ACL filter BEFORE scoring: restricted chunks never touch this role's index.
    visible = [c for c in _kb()[0] if role in c.acl]
    if not visible:
        return [], None
    return visible, BM25([tokenize(c.title + " " + c.text) for c in visible])


def search(query: str, role: str, k: int = 3) -> list[dict]:
    visible, bm25 = _index_for(role)
    if bm25 is None:
        return []  # unknown role: default deny
    q = tokenize(query)
    scored = sorted(((bm25.score(q, i), c) for i, c in enumerate(visible)),
                    key=lambda x: x[0], reverse=True)
    return [{**c.model_dump(), "score": round(s, 3)} for s, c in scored[:k] if s > 0]