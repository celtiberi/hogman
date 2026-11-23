#!/usr/bin/env python3
"""Build hogman.network/docs and machine-readable discovery files:
- Wraps each page in site/docs-src/ in the shared layout (header, left sidebar,
  right on-this-page TOC, prev/next pager, footer, canonical & JSON-LD metadata)
  and writes it to site/public/docs/.
- Generates deterministic site/public/sitemap.xml, site/public/llms.txt, and
  site/public/llms-full.txt so search engines and AI assistants stay in sync.

    python3 site/docs-src/build.py

Edit the page fragments here, not the generated files. To add a page, add its
fragment and a line to PAGES."""
import html as html_mod
from html.parser import HTMLParser
import json
import os
import re

SRC = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.normpath(os.path.join(SRC, "..", "public"))
OUT = os.path.join(PUBLIC, "docs")
WORK_OUT = os.path.join(PUBLIC, "work", "docs")
BASE_URL = "https://hogman.network"
WORK_BASE_URL = "https://work.hogman.network"

PAGES = [  # (file, nav title, page title, description, sidebar group)
    ("index", "Quickstart", "Docs — Quickstart", "Create a pen, join with one command, and put an HTTPS server on your private network.", "Guides"),
    ("join", "Joining a pen", "Joining a pen", "Join a pen on Mac or Linux, handle VPNs and browsers, add devices, update, and leave.", "Guides"),
    ("share", "Hosting HTTPS servers", "Hosting HTTPS servers", "Put any web app, local port, or static directory inside your pen over HTTPS (port 443).", "Guides"),
    ("keeper", "Running a pen", "Running a pen", "Roles, invites, the herd, suspend and kick, and what keepers can and can't see.", "Guides"),
    ("security", "Architecture & security", "Architecture and security", "Packet flow, components, client isolation, DNS-01 HTTPS, threat model, host isolation, and known limits.", "Reference"),
    ("faq", "FAQ & troubleshooting", "FAQ and troubleshooting", "Common questions (Tailscale, self-hosting, VPNs, limits) and fixes for common errors.", "Reference"),
]

H2_RE = re.compile(r'<h2\b[^>]*\bid="([^"]+)"[^>]*>(.*?)</h2>', re.DOTALL)
FAQ_PAIR_RE = re.compile(r"<dt\b[^>]*>(.*?)</dt>\s*<dd\b[^>]*>(.*?)</dd>", re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


def page_href(slug: str) -> str:
    return "/docs/" if slug == "index" else f"/docs/{slug}.html"


def work_page_rel(slug: str) -> str:
    return "./" if slug == "index" else f"./{slug}.html"


def adapt_work_body(body: str) -> str:
    """Adapt single-source doc fragments for work.hogman.network/docs/:
    keep all internal doc links inside the Work docs tree and swap consumer
    example names to neutral operational examples."""
    out = body.replace('href="/docs/"', 'href="./"')
    out = re.sub(r'href="/docs/([^"]+)"', r'href="./\1"', out)
    out = out.replace("john-mcafee", "store-north")
    out = out.replace("deadmans-switch", "cooler-1")
    out = out.replace("https://get.hogman.network/", "https://get.hogman.network/#wait")
    return out


def plain_text(fragment: str) -> str:
    text = html_mod.unescape(TAG_RE.sub("", fragment))
    return re.sub(r"\s+", " ", text).strip()


def build_toc(body: str) -> str:
    items = []
    for hid, raw_title in H2_RE.findall(body):
        label = plain_text(raw_title)
        items.append(f'<li><a href="#{hid}">{html_mod.escape(label)}</a></li>')
    if not items:
        return ""
    return (
        '<aside class="docs-toc" aria-label="On this page">\n'
        '  <p class="docs-nav-h">On this page</p>\n'
        '  <ul>\n'
        + "\n".join(f"    {li}" for li in items)
        + "\n  </ul>\n</aside>"
    )


def build_pager(idx: int, href_fn=page_href) -> str:
    prev_html = '<span class="pager-slot"></span>'
    next_html = '<span class="pager-slot"></span>'
    if idx > 0:
        slug, navt, *_ = PAGES[idx - 1]
        prev_html = (
            f'<a class="pager-link prev" href="{href_fn(slug)}">'
            f'<span class="pager-dir">&larr; Previous</span>'
            f'<span class="pager-title">{html_mod.escape(navt)}</span></a>'
        )
    if idx + 1 < len(PAGES):
        slug, navt, *_ = PAGES[idx + 1]
        next_html = (
            f'<a class="pager-link next" href="{href_fn(slug)}">'
            f'<span class="pager-dir">Next &rarr;</span>'
            f'<span class="pager-title">{html_mod.escape(navt)}</span></a>'
        )
    return f'<nav class="docs-pager" aria-label="Adjacent pages">\n  {prev_html}\n  {next_html}\n</nav>'


def build_jsonld(
    slug: str,
    navt: str,
    title: str,
    desc: str,
    body: str,
    base_url: str = BASE_URL,
    site_name: str = "Hogman",
    og_image: str = BASE_URL + "/og-hero-v2.jpg",
) -> str:
    url = base_url + page_href(slug)
    crumbs = [
        {"@type": "ListItem", "position": 1, "name": site_name, "item": base_url + "/"},
        {"@type": "ListItem", "position": 2, "name": "Docs", "item": base_url + "/docs/"},
    ]
    if slug != "index":
        crumbs.append({"@type": "ListItem", "position": 3, "name": navt, "item": url})

    graph = [
        {
            "@type": "TechArticle",
            "headline": f"{title} · {site_name}",
            "description": desc,
            "url": url,
            "image": og_image,
            "isPartOf": {"@type": "WebSite", "name": site_name, "url": base_url + "/"},
        },
        {
            "@type": "BreadcrumbList",
            "itemListElement": crumbs,
        },
    ]

    if slug == "faq":
        entities = []
        for q_html, a_html in FAQ_PAIR_RE.findall(body):
            q = plain_text(q_html)
            a = plain_text(a_html)
            if q and a:
                entities.append({
                    "@type": "Question",
                    "name": q,
                    "acceptedAnswer": {"@type": "Answer", "text": a},
                })
        if entities:
            graph.append({"@type": "FAQPage", "mainEntity": entities})

    payload = json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False, indent=2)
    payload = payload.replace("</", "<\\/")
    return f'<script type="application/ld+json">\n{payload}\n</script>'


class MarkdownConverter(HTMLParser):
    """Minimal deterministic HTML-fragment to clean Markdown converter for llms-full.txt."""

    def __init__(self, base_url: str = BASE_URL):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.out = []
        self.in_pre = False
        self.in_code = False
        self.in_table_row = []
        self.in_table_head = False
        self.table_rows = []
        self.in_cell = False
        self.cell_buf = []
        self.link_href = None
        self.link_buf = []
        self.list_stack = []

    def _emit(self, text: str):
        if self.in_cell:
            self.cell_buf.append(text)
        elif self.link_href is not None:
            self.link_buf.append(text)
        else:
            self.out.append(text)

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "h1":
            self._emit("\n# ")
        elif tag == "h2":
            self._emit("\n\n## ")
        elif tag == "h3":
            self._emit("\n\n### ")
        elif tag == "p":
            self._emit("\n\n")
        elif tag == "br":
            self._emit("\n")
        elif tag == "pre":
            self.in_pre = True
            self._emit("\n\n```text\n")
        elif tag == "code":
            self.in_code = True
            if not self.in_pre:
                self._emit("`")
        elif tag in ("strong", "b"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag == "ul":
            self.list_stack.append(("ul", 0))
            self._emit("\n")
        elif tag == "ol":
            self.list_stack.append(("ol", 0))
            self._emit("\n")
        elif tag == "li":
            if self.list_stack:
                kind, n = self.list_stack[-1]
                n += 1
                self.list_stack[-1] = (kind, n)
                prefix = f"{n}. " if kind == "ol" else "- "
            else:
                prefix = "- "
            self._emit(f"\n{prefix}")
        elif tag == "dt":
            self._emit("\n\n### ")
        elif tag == "dd":
            self._emit("\n\n")
        elif tag == "a":
            href = attr.get("href", "")
            if href.startswith("/"):
                href = self.base_url + href
            elif href == "./":
                href = self.base_url + "/docs/"
            elif href.startswith("./"):
                href = self.base_url + "/docs/" + href[2:]
            self.link_href = href
            self.link_buf = []
        elif tag == "table":
            self.table_rows = []
        elif tag == "thead":
            self.in_table_head = True
        elif tag == "tr":
            self.in_table_row = []
        elif tag in ("th", "td"):
            self.in_cell = True
            self.cell_buf = []

    def handle_endtag(self, tag):
        if tag in ("h1", "h2", "h3"):
            self._emit("\n")
        elif tag == "pre":
            self.in_pre = False
            self._emit("\n```\n")
        elif tag == "code":
            if not self.in_pre:
                self._emit("`")
            self.in_code = False
        elif tag in ("strong", "b"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag in ("ul", "ol"):
            if self.list_stack:
                self.list_stack.pop()
            self._emit("\n")
        elif tag == "a":
            label = "".join(self.link_buf).strip()
            href = self.link_href
            self.link_href = None
            self.link_buf = []
            if href and label and label != href:
                self._emit(f"[{label}]({href})")
            else:
                self._emit(label or href or "")
        elif tag in ("th", "td"):
            cell = re.sub(r"\s+", " ", "".join(self.cell_buf)).strip()
            self.in_table_row.append(cell)
            self.in_cell = False
            self.cell_buf = []
        elif tag == "tr":
            if self.in_table_row:
                self.table_rows.append((self.in_table_head, self.in_table_row))
            self.in_table_row = []
        elif tag == "thead":
            self.in_table_head = False
        elif tag == "table":
            if self.table_rows:
                lines = [""]
                for idx, (is_hdr, row) in enumerate(self.table_rows):
                    lines.append("| " + " | ".join(row) + " |")
                    if idx == 0:
                        lines.append("| " + " | ".join(["---"] * len(row)) + " |")
                lines.append("")
                self._emit("\n".join(lines))
            self.table_rows = []

    def handle_data(self, data):
        if self.in_pre:
            self._emit(data)
        else:
            collapsed = re.sub(r"\s+", " ", data)
            self._emit(collapsed)

    def render(self) -> str:
        raw = "".join(self.out)
        lines = [line.rstrip() if not line.startswith("    ") else line.rstrip() for line in raw.splitlines()]
        cleaned = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
        return cleaned + "\n"


def html_to_markdown(fragment: str, base_url: str = BASE_URL) -> str:
    conv = MarkdownConverter(base_url=base_url)
    conv.feed(fragment)
    conv.close()
    return conv.render()


def write_sitemap(base_url: str = BASE_URL, out_dir: str = PUBLIC, label: str = "sitemap.xml"):
    urls = [(base_url + "/", "1.0")]
    for slug, *_ in PAGES:
        prio = "0.9" if slug == "index" else "0.8"
        urls.append((base_url + page_href(slug), prio))
    entries = "\n".join(
        f"  <url>\n    <loc>{loc}</loc>\n    <priority>{prio}</priority>\n  </url>"
        for loc, prio in urls
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>\n"
    )
    open(os.path.join(out_dir, "sitemap.xml"), "w").write(xml)
    print("wrote", label)


def write_llms_files(bodies: list[tuple[str, str, str, str, str]]):
    doc_links = "\n".join(
        f"- [{navt}]({BASE_URL}{page_href(slug)}): {desc}"
        for slug, navt, _, desc, _ in PAGES
    )
    llms_txt = f"""# Hogman

> Hogman lets you run an invite-only private web ("pen") over WireGuard with real domain names (`*.pens.hogman.network`), standard browser HTTPS certificates, and zero public IP addresses. Open source (AGPL-3.0).

## Key facts

- **What it is:** A private web for groups (families, friends, clubs, teams) where members open private HTTPS (`:443`) sites in ordinary browsers (Chrome, Safari, Firefox) after joining from a single-use invite link.
- **What it deliberately is NOT:** Not a VPN (ordinary internet traffic goes direct untouched), not SSH, not raw TCP/UDP, not an exit node, and personal laptops accept zero inbound connections. Only HTTPS (`:443`) to explicitly shared server nodes (`tag:server`) is permitted.
- **Hosting model:** Control planes are hosted-only on `hogman.network` (no self-hosted pen server support). Users host their own HTTPS web servers or static folders inside their pen via `hogman-join share`.
- **Architecture:** Built on Headscale, Tailscale `tsnet` (userspace WireGuard), Caddy, and CertMagic. Runs cleanly alongside existing Tailscale setups.
- **DNS & HTTPS:** Split-horizon ACME DNS-01 (`ns1.hogman.network` serves only temporary `_acme-challenge.*` TXT, `SOA`, `NS`, `CAA` — zero public `A`/`AAAA` records). Standard public certificates verified by stock OS trust stores (no custom root CA).
- **Platforms & pricing:** Free while testing. macOS and Linux work today; Windows is built but untested; mobile app in progress. Companion Manifest V3 browser extension (`browser-ext/`) supports VPN coexistence on Chrome, Brave, Edge, and Firefox.
- **Security & limits:** Experimental and not yet independently audited. Payloads are end-to-end encrypted (WireGuard + TLS 1.3). Hostnames appear in public Certificate Transparency logs (names only, never site contents). There is zero account recovery (owners should appoint a second owner). Until `pens.hogman.network` is listed on the Public Suffix List, use a separate browser profile for untrusted pens.

## Documentation

{doc_links}

## Full documentation & links

- [Complete documentation in one Markdown file]({BASE_URL}/llms-full.txt)
- [Homepage]({BASE_URL}/)
- [Hogman for Work (small businesses & operations)]({WORK_BASE_URL}/)
- [Create a pen](https://get.hogman.network/)
- [Source code (AGPL-3.0) on GitHub](https://github.com/celtiberi/hogman)
"""
    open(os.path.join(PUBLIC, "llms.txt"), "w").write(llms_txt)
    print("wrote llms.txt")

    sections = [
        "# Hogman — Complete Documentation\n\n"
        f"Source: {BASE_URL}/docs/  \n"
        "Repository: https://github.com/celtiberi/hogman  \n"
        "License: AGPL-3.0\n"
    ]
    for slug, navt, title, desc, body in bodies:
        url = BASE_URL + page_href(slug)
        md = html_to_markdown(body, BASE_URL)
        sections.append(f"---\n\n<!-- Page: {navt} ({url}) -->\n\n{md}")
    open(os.path.join(PUBLIC, "llms-full.txt"), "w").write("\n".join(sections))
    print("wrote llms-full.txt")

    work_dir = os.path.join(PUBLIC, "work")
    work_doc_links = "\n".join(
        f"- [{navt}]({WORK_BASE_URL}{page_href(slug)}): {desc}"
        for slug, navt, _, desc, _ in PAGES
    )
    work_llms_txt = f"""# Hogman for Work

> Private HTTPS networks ("pens") over WireGuard for small businesses and operations teams that don't have a dedicated security department. Take refrigeration controllers, building dashboards, and internal web tools off the open internet — real domain names, standard browser HTTPS, zero public IP addresses, and ~2-second access revocation. Open source (AGPL-3.0).

## Key facts for businesses & operations

- **What it solves:** Removes equipment controllers (refrigeration, HVAC/BMS, cameras, local monitors) and internal web apps from the open internet so automated scanners and attackers have no public IP or login page to reach.
- **How on-site equipment connects:** Devices that cannot run client software stay strictly on the local LAN (no open router ports); a small always-on Linux or Mac computer on site bridges only that device's web UI into the pen via `hogman-join share cooler-1 http://192.168.1.40 --background '<share-link>'`. The local upstream can speak plain HTTP while staff always connect over HTTPS (`:443`).
- **Multi-site blast-radius isolation:** Create separate pens per region or store group so one lost laptop or compromised account cannot reach every location.
- **What it deliberately is NOT:** Not a VPN (ordinary browsing stays direct), no SSH, no raw TCP/UDP ports, no exit nodes, and zero inbound connections to staff laptops. Devices without a web UI are not a fit.
- **Honest security boundaries:** A pen hides vulnerable devices and narrows access to pen members — **it does not patch firmware** (keep vendor security updates enabled). Hostnames appear in public Certificate Transparency logs (names only, never site contents). There is zero account recovery (always appoint two owners per pen). Experimental software, not yet independently audited.
- **Hosting & status:** Control planes are hosted-only on `hogman.network` (invite-only testbed today; commercial plans coming soon). macOS and Linux work today; Windows and mobile apps are in progress.

## Documentation

{work_doc_links}

## Full documentation & links

- [Complete Hogman for Work documentation in one Markdown file]({WORK_BASE_URL}/llms-full.txt)
- [Hogman for Work overview]({WORK_BASE_URL}/)
- [Request early access](https://get.hogman.network/#wait)
- [Source code (AGPL-3.0) on GitHub](https://github.com/celtiberi/hogman)
"""
    open(os.path.join(work_dir, "llms.txt"), "w").write(work_llms_txt)
    print("wrote work/llms.txt")

    work_sections = [
        "# Hogman for Work — Complete Documentation\n\n"
        f"Source: {WORK_BASE_URL}/docs/  \n"
        "Repository: https://github.com/celtiberi/hogman  \n"
        "License: AGPL-3.0\n"
    ]
    for slug, navt, title, desc, body in bodies:
        url = WORK_BASE_URL + page_href(slug)
        md = html_to_markdown(adapt_work_body(body), WORK_BASE_URL)
        work_sections.append(f"---\n\n<!-- Page: {navt} ({url}) -->\n\n{md}")
    open(os.path.join(work_dir, "llms-full.txt"), "w").write("\n".join(work_sections))
    print("wrote work/llms-full.txt")


HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Hogman</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="https://hogman.network{href}">
<link rel="alternate" type="text/plain" href="https://hogman.network/llms.txt" title="Hogman documentation for LLMs">
<meta property="og:title" content="{title} · Hogman">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://hogman.network{href}">
<meta property="og:site_name" content="Hogman">
<meta property="og:image" content="https://hogman.network/og-hero-v2.jpg">
<meta property="og:image:type" content="image/jpeg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Hogman at the fence: clean pigs in sunglasses inside, a filthy horde outside.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title} · Hogman">
<meta name="twitter:description" content="{desc}">
<meta name="twitter:image" content="https://hogman.network/og-hero-v2.jpg">
<meta name="theme-color" content="#0e080c">
<link rel="icon" href="/icons/hogman-32.png" type="image/png" sizes="32x32">
<link rel="icon" href="/icons/hogman-48.png" type="image/png" sizes="48x48">
<link rel="apple-touch-icon" href="/hogman-icon.png">
<link rel="stylesheet" href="/styles.css?v=metal25">
{jsonld}
</head>
<!-- Generated by site/docs-src/build.py from site/docs-src. Edit there. -->
<body class="docs-page">
<header class="top">
  <a class="brand" href="/" aria-label="Hogman home"><img class="brand-icon" src="/hogman-icon.webp" width="28" height="28" alt=""><span>H&Ouml;GMAN</span></a>
  <nav>
    <a href="/#why">Why a pen?</a>
    <a href="/#tech">Under the hood</a>
    <a href="/docs/" aria-current="true">Docs</a>
    <a href="https://github.com/celtiberi/hogman">Source</a>
    <a href="https://get.hogman.network/">Get a pen</a>
  </nav>
</header>
<div class="studs" aria-hidden="true"></div>
<div class="docs">
<aside class="docs-nav" aria-label="Docs pages">
{nav}
</aside>
<main class="docs-main">
"""

FOOT = """
{pager}
<p class="docs-edit fine">Spot something wrong or unclear? Edit the source in
  <a href="https://github.com/celtiberi/hogman/tree/main/site/docs-src">site/docs-src</a> on GitHub.</p>
</main>
{toc}
</div>
<footer>
  <p>Keep a clean pen.</p>
  <p class="foot-links"><a href="/">Home</a> · <a href="/docs/">Docs</a> ·
    <a href="/docs/security.html">Security</a> · <a href="/docs/faq.html">FAQ</a> ·
    <a href="https://get.hogman.network/">Get a pen</a> ·
    <a href="https://github.com/celtiberi/hogman">Source</a></p>
</footer>
<script src="/docs.js?v=1" defer></script>
</body>
</html>
"""

WORK_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Hogman for Work</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="https://work.hogman.network{href}">
<link rel="alternate" type="text/plain" href="https://work.hogman.network/llms.txt" title="Hogman for Work documentation for LLMs">
<meta property="og:title" content="{title} · Hogman for Work">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="website">
<meta property="og:url" content="https://work.hogman.network{href}">
<meta property="og:site_name" content="Hogman for Work">
<meta property="og:image" content="https://work.hogman.network/work/og-work.jpg">
<meta property="og:image:type" content="image/jpeg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Hogman for Work documentation: private HTTPS networks for small businesses.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title} · Hogman for Work">
<meta name="twitter:description" content="{desc}">
<meta name="twitter:image" content="https://work.hogman.network/work/og-work.jpg">
<meta name="theme-color" content="#14181f">
<link rel="icon" href="/work/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/work/work.css?v=2">
{jsonld}
</head>
<!-- Generated by site/docs-src/build.py from site/docs-src. Edit there. -->
<body class="docs-page">
<header class="top">
  <div class="wrap top-inner">
    <a class="brand" href="../" aria-label="Hogman for Work home">
      <img src="/work/favicon.svg" width="28" height="28" alt="">
      <span class="brand-name">Hogman</span>
      <span class="brand-tag">Work</span>
    </a>
    <nav aria-label="Primary navigation">
      <a href="../#why">Why pens</a>
      <a href="../#how">How it works</a>
      <a href="../#uses">Use cases</a>
      <a href="../#honest">Security limits</a>
      <a href="./" aria-current="true">Docs</a>
      <a class="nav-cta" href="https://get.hogman.network/#wait">Request access</a>
    </nav>
  </div>
</header>
<div class="docs">
<aside class="docs-nav" aria-label="Docs pages">
{nav}
</aside>
<main class="docs-main">
"""

WORK_FOOT = """
{pager}
<p class="docs-edit fine">Spot something wrong or unclear? Edit the source in
  <a href="https://github.com/celtiberi/hogman/tree/main/site/docs-src">site/docs-src</a> on GitHub.</p>
</main>
{toc}
</div>
<footer class="foot">
  <div class="wrap foot-inner">
    <p class="foot-brand">
      <strong>Hogman</strong> &middot; Open source (<a href="https://github.com/celtiberi/hogman/blob/main/LICENSE">AGPL-3.0</a>) &middot; Hosted control planes on <code>hogman.network</code>
    </p>
    <p class="foot-links">
      <a href="../">Overview</a> &middot;
      <a href="./">Docs</a> &middot;
      <a href="./security.html">Security</a> &middot;
      <a href="./faq.html">FAQ</a> &middot;
      <a href="https://github.com/celtiberi/hogman">GitHub</a>
    </p>
  </div>
</footer>
<script src="/docs.js?v=1" defer></script>
</body>
</html>
"""


def build_sidebar(current_slug: str, href_fn=page_href) -> str:
    nav, group = [], None
    for g, n, _, _, grp in PAGES:
        if grp != group:
            if group is not None:
                nav.append("</ul>")
            nav.append(f'<p class="docs-nav-h">{grp}</p>\n<ul>')
            group = grp
        current = ' aria-current="page"' if g == current_slug else ""
        nav.append(f'<li><a href="{href_fn(g)}"{current}>{n}</a></li>')
    nav.append("</ul>")
    return "\n".join(nav)


os.makedirs(OUT, exist_ok=True)
os.makedirs(WORK_OUT, exist_ok=True)
built_bodies = []
for idx, (f, navt, title, desc, _) in enumerate(PAGES):
    body = open(os.path.join(SRC, f + ".html")).read().strip()
    built_bodies.append((f, navt, title, desc, body))

    out_html = (
        HEAD.format(
            title=title,
            desc=desc,
            href=page_href(f),
            jsonld=build_jsonld(f, navt, title, desc, body),
            nav=build_sidebar(f, page_href),
        )
        + body
        + "\n"
        + FOOT.format(pager=build_pager(idx, page_href), toc=build_toc(body))
    )
    open(os.path.join(OUT, f + ".html"), "w").write(out_html)
    print("wrote", f)

    work_body = adapt_work_body(body)
    work_html = (
        WORK_HEAD.format(
            title=title,
            desc=desc,
            href=page_href(f),
            jsonld=build_jsonld(
                f,
                navt,
                title,
                desc,
                work_body,
                base_url=WORK_BASE_URL,
                site_name="Hogman for Work",
                og_image=WORK_BASE_URL + "/work/og-work.jpg",
            ),
            nav=build_sidebar(f, work_page_rel),
        )
        + work_body
        + "\n"
        + WORK_FOOT.format(pager=build_pager(idx, work_page_rel), toc=build_toc(work_body))
    )
    open(os.path.join(WORK_OUT, f + ".html"), "w").write(work_html)
    print("wrote work/docs/" + f)

write_sitemap(BASE_URL, PUBLIC, "sitemap.xml")
write_sitemap(WORK_BASE_URL, os.path.join(PUBLIC, "work"), "work/sitemap.xml")
write_llms_files(built_bodies)
