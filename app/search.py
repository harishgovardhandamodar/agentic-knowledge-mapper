"""Search providers: RSS feeds, arXiv API, DuckDuckGo HTML web search.

Each returns a list of candidate dicts:
  title, url, description, content, source, author, date_published,
  artifact_type, query
"""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re
import urllib.parse
import xml.etree.ElementTree as ET

import feedparser
import httpx
from bs4 import BeautifulSoup

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) agentic-knowledge-mapper/1.0"}

DEFAULT_RSS = [
    {"url": "https://news.ycombinator.com/rss", "source": "Hacker News", "type": "news"},
    {"url": "https://export.arxiv.org/rss/cs.AI", "source": "arXiv cs.AI", "type": "paper"},
    {"url": "https://www.lesswrong.com/feed.xml", "source": "LessWrong", "type": "essay"},
    {"url": "https://alignmentforum.org/feed.xml", "source": "AI Alignment Forum", "type": "research"},
    {"url": "https://openai.com/news/rss.xml", "source": "OpenAI Blog", "type": "research"},
]


def _clean(text: str | None, limit: int = 1200) -> str:
    if not text:
        return ""
    t = re.sub(r"<[^>]+>", " ", text)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:limit]


def _parse_date(value) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        dt = parsedate_to_datetime(str(value))
        return dt
    except Exception:
        return None


def search_rss(query: str, feeds: list | None = None, per_feed: int = 8) -> list:
    """Keyword-filtered scan of RSS feeds (no key needed)."""
    out = []
    terms = [t.lower() for t in re.split(r"[,\s]+", query) if t]
    for feed in (feeds or DEFAULT_RSS):
        try:
            with httpx.Client(timeout=10, headers=UA, follow_redirects=True) as client:
                r = client.get(feed["url"])
                if r.status_code != 200:
                    continue
                parsed = feedparser.parse(r.content)
        except Exception:
            continue
        for e in parsed.entries[:30]:
            title = _clean(getattr(e, "title", ""), 500)
            desc = _clean(getattr(e, "summary", getattr(e, "description", "")), 1200)
            blob = f"{title} {desc}".lower()
            if terms and not any(t in blob for t in terms):
                continue
            out.append({
                "title": title or "(untitled)",
                "url": getattr(e, "link", ""),
                "description": desc,
                "content": "",
                "source": feed.get("source", "RSS"),
                "author": _clean(getattr(e, "author", ""), 200),
                "date_published": _parse_date(getattr(e, "published", None)),
                "artifact_type": feed.get("type", "news"),
                "query": query,
            })
            if len(out) >= per_feed * len(feeds or DEFAULT_RSS):
                break
    return out


def search_arxiv(query: str, max_results: int = 15) -> list:
    """arXiv API full-text search."""
    out = []
    q = urllib.parse.quote(query)
    url = (f"http://export.arxiv.org/api/query?search_query=all:{q}"
           f"&start=0&max_results={max_results}&sortBy=submittedDate&sortOrder=descending")
    try:
        with httpx.Client(timeout=15, headers=UA) as client:
            r = client.get(url)
            r.raise_for_status()
            root = ET.fromstring(r.content)
    except Exception:
        return out
    ns = {"a": "http://www.w3.org/2005/Atom"}
    for entry in root.findall("a:entry", ns):
        def _t(tag):
            el = entry.find(f"a:{tag}", ns)
            return _clean(el.text) if el is not None and el.text else ""
        link = entry.find("a:id", ns)
        authors = entry.findall("a:author/a:name", ns)
        pub = entry.find("a:published", ns)
        try:
            dt = datetime.fromisoformat(pub.text.replace("Z", "+00:00")) if pub is not None else None
        except Exception:
            dt = None
        summary = _t("summary")
        out.append({
            "title": _t("title") or "(untitled)",
            "url": link.text.strip() if link is not None and link.text else "",
            "description": summary[:600],
            "content": summary,
            "source": "arXiv",
            "author": ", ".join(a.text for a in authors if a.text) or "Unknown",
            "date_published": dt,
            "artifact_type": "paper",
            "query": query,
        })
    return out


def search_web(query: str, max_results: int = 10) -> list:
    """DuckDuckGo HTML endpoint (no key). Best-effort; may rate-limit."""
    out = []
    try:
        with httpx.Client(timeout=12, headers={**UA, "Referer": "https://duckduckgo.com/"}) as client:
            r = client.post("https://html.duckduckgo.com/html/",
                            data={"q": query, "b": "", "kl": ""})
            if r.status_code != 200:
                return out
            soup = BeautifulSoup(r.text, "html.parser")
            for res in soup.select(".result")[:max_results]:
                a = res.select_one(".result__a")
                snip = res.select_one(".result__snippet")
                if not a:
                    continue
                href = a.get("href", "")
                m = re.search(r"uddg=([^&]+)", href)
                url = urllib.parse.unquote(m.group(1)) if m else href
                if url.startswith("//"):
                    url = "https:" + url
                out.append({
                    "title": _clean(a.get_text(), 500) or "(untitled)",
                    "url": url,
                    "description": _clean(snip.get_text() if snip else "", 600),
                    "content": "",
                    "source": urllib.parse.urlparse(url).netloc or "web",
                    "author": "",
                    "date_published": None,
                    "artifact_type": "news",
                    "query": query,
                })
    except Exception:
        pass
    return out
