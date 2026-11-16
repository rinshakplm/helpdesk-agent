"""Retrieval: split policy documents into sections and rank them with BM25."""
import re
from pathlib import Path

from rank_bm25 import BM25Okapi

KB_DIR = Path(__file__).resolve().parent.parent / "kb"

STOPWORDS = {
    "a", "an", "the", "is", "are", "am", "was", "were", "be", "to", "of", "and",
    "or", "in", "on", "at", "for", "with", "my", "me", "i", "you", "your", "it",
    "this", "that", "do", "does", "how", "can", "what", "when", "if", "as", "by",
    "from", "not", "no", "so", "we", "our", "will", "should", "would", "could",
    # words that appear in many headings or questions but say nothing about the topic
    "who", "which", "where", "why", "there", "any", "all", "about", "tell", "show",
    "need", "want", "get", "company", "policy", "policies", "nimbus", "tech", "please",
}


def _stem(word):
    """Very light stemming so 'passwords' matches 'password'."""
    if word.endswith("ss"):
        return word
    for suffix in ("ing", "ed", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def tokenize(text):
    words = re.findall(r"[a-z0-9]+", text.lower())
    return [_stem(w) for w in words if w not in STOPWORDS and len(w) > 1]  # drops stray letters such as the s in it's


def load_chunks(kb_dir=None):
    """Read every .md file in kb/ and cut it into one chunk per '##' section."""
    chunks = []
    for path in sorted(Path(kb_dir or KB_DIR).glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title_match = re.search(r"^# (.+)$", text, re.M)
        id_match = re.search(r"^Document ID:\s*(.+)$", text, re.M)
        title = title_match.group(1).strip() if title_match else path.stem
        doc_id = id_match.group(1).strip() if id_match else path.stem
        parts = re.split(r"^## ", text, flags=re.M)
        for part in parts[1:]:
            heading, _, body = part.partition("\n")
            chunks.append(
                {
                    "doc_id": doc_id,
                    "title": title,
                    "section": heading.strip(),
                    "text": body.strip(),
                    "source": path.name,
                }
            )
    return chunks


class KnowledgeBase:
    def __init__(self, kb_dir=None):
        self.chunks = load_chunks(kb_dir)
        corpus = [
            tokenize(f"{c['title']} {c['section']} {c['section']} {c['text']}")
            for c in self.chunks
        ]
        self.bm25 = BM25Okapi(corpus)

    def search(self, query, k=3, min_score=1.0):
        """Return up to k sections that match the query well enough."""
        tokens = tokenize(query)
        if not tokens:
            return []
        scores = self.bm25.get_scores(tokens)
        ranked = sorted(zip(scores, self.chunks), key=lambda x: x[0], reverse=True)
        results = []
        for score, chunk in ranked[:k]:
            if score >= min_score:
                results.append({**chunk, "score": round(float(score), 2)})
        return results
