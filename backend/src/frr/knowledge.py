"""The knowledge base the risk & impact assessor retrieves from: network
standards, the exception register and change/rollback runbooks (FRR-01.4).

Documents are plain text or Markdown, split on headings (then on size) into
chunks of at most ~1,200 characters, and retrieved with Postgres full-text
search ranked by ts_rank_cd. Retrieved chunks are handed to the model as
QUOTED, CITED context -- never as instructions -- and every narrative must cite
the chunk ids it used, which are checked against what was retrieved.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import psycopg

from ..db import audit

MAX_DOC_BYTES = 2 * 1024 * 1024
_CHUNK = 1200
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


def chunk(text: str) -> list[tuple[str | None, str]]:
    """[(heading, body)] in document order."""
    out: list[tuple[str | None, str]] = []
    heading, buf = None, []

    def flush():
        body = "\n".join(buf).strip()
        while body:
            if len(body) <= _CHUNK:
                out.append((heading, body))
                break
            cut = body.rfind("\n", 0, _CHUNK)
            cut = cut if cut > _CHUNK // 3 else body.rfind(" ", 0, _CHUNK)
            cut = cut if cut > 0 else _CHUNK
            out.append((heading, body[:cut].strip()))
            body = body[cut:].strip()

    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            flush()
            heading, buf = m.group(2)[:300], []
        else:
            buf.append(line)
    flush()
    return out


def add(cur: psycopg.Cursor, kind: str, title: str, text: str, uploaded_by: str | None) -> dict:
    data = text.encode()
    if len(data) > MAX_DOC_BYTES:
        raise ValueError(f"document exceeds {MAX_DOC_BYTES} bytes")
    pieces = chunk(text)
    if not pieces:
        raise ValueError("document has no text")
    digest = hashlib.sha256(data).hexdigest()
    cur.execute("""INSERT INTO ztpa.knowledge_docs (kind, title, sha256, uploaded_by)
                   VALUES (%s, %s, %s, %s) ON CONFLICT (sha256) DO NOTHING RETURNING *""",
                [kind, title, digest, uploaded_by])
    doc = cur.fetchone()
    if doc is None:
        cur.execute("SELECT * FROM ztpa.knowledge_docs WHERE sha256 = %s", [digest])
        return {**cur.fetchone(), "duplicate": True}
    for i, (h, body) in enumerate(pieces):
        cur.execute("INSERT INTO ztpa.knowledge_chunks (doc_id, ord, heading, body) VALUES (%s, %s, %s, %s)",
                    [doc["doc_id"], i, h, body])
    audit(cur, "knowledge_doc_added", subject=str(doc["doc_id"]),
          detail={"kind": kind, "title": title, "chunks": len(pieces)})
    return {**doc, "chunks": len(pieces), "duplicate": False}


def search(cur: psycopg.Cursor, query: str, *, k: int = 4) -> list[dict[str, Any]]:
    """Top-k chunks for a free-text query. OR semantics over the query's words,
    so a long query still matches documents that use some of its terms."""
    words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9-]{1,40}", query.lower())][:40]
    if not words:
        return []
    tsq = " | ".join(dict.fromkeys(words))
    cur.execute(
        """SELECT d.doc_id, d.kind, d.title, c.ord, c.heading, c.body,
                  ts_rank_cd(c.tsv, q) AS rank
             FROM ztpa.knowledge_chunks c
             JOIN ztpa.knowledge_docs d USING (doc_id),
                  to_tsquery('english', %s) q
            WHERE c.tsv @@ q
            ORDER BY rank DESC, d.uploaded_at DESC, c.ord
            LIMIT %s""", [tsq, k])
    return [{**r, "cite": f"{str(r['doc_id'])[:8]}#{r['ord']}"} for r in cur.fetchall()]
