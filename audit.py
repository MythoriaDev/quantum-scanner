"""
Quantum-Readiness Audit: deeper checks for a paid client audit.

  * discover_hosts()  - finds the organisation's public services (VPN, webmail, portals...)
  * check_email()     - email security records (MX provider, SPF, DMARC, MTA-STS, TLS-RPT)
  * run_audit()       - scans everything and combines it with the client questionnaire
  * build_audit_report() - produces the branded HTML audit report with a roadmap
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import escape

import dns.exception
import dns.resolver

from scanner import ScanError, normalize_target, scan

# Common names for internet-facing services. Remote access ones matter most.
SUBDOMAINS = [
    "www", "mail", "webmail", "owa", "autodiscover", "remote", "vpn", "sslvpn", "portal",
    "citrix", "gateway", "rdweb", "rds", "secure", "login", "sso", "adfs", "sts", "extranet",
    "client", "clients", "clientportal", "files", "share", "sftp", "ftp", "api", "app",
    "intranet", "fw", "firewall", "connect", "access", "my", "dms", "docs",
]
REMOTE_ACCESS = {"remote", "vpn", "sslvpn", "citrix", "gateway", "rdweb", "rds", "fw",
                 "firewall", "connect", "access"}

MAIL_PROVIDERS = [
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("mimecast", "Mimecast"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
    ("barracudanetworks.com", "Barracuda"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("sophos.com", "Sophos Email"),
]

ROADMAP_ORDER = {"Now (0-3 months)": 0, "Next (3-12 months)": 1, "Later (1-3 years)": 2}


# --------------------------------------------------------------------------- #
# DNS helpers
# --------------------------------------------------------------------------- #
def _resolver():
    r = dns.resolver.Resolver()
    r.lifetime = 5.0
    r.timeout = 3.0
    return r


def _txt(resolver, name):
    """Return list of TXT strings, [] if none, None if lookup failed."""
    try:
        ans = resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return None


def check_email(domain, resolver=None):
    resolver = resolver or _resolver()
    res = {"domain": domain, "mx": [], "provider": "Unknown", "spf": None, "spf_status": "missing",
           "dmarc": None, "dmarc_policy": "missing", "mta_sts": False, "tls_rpt": False,
           "lookup_failed": False}
    try:
        ans = resolver.resolve(domain, "MX")
        res["mx"] = sorted(
            (str(r.exchange).rstrip(".").lower() for r in sorted(ans, key=lambda r: r.preference))
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except (dns.exception.DNSException, OSError):
        res["lookup_failed"] = True
        return res

    for mx in res["mx"]:
        for needle, name in MAIL_PROVIDERS:
            if needle in mx:
                res["provider"] = name
                break
        if res["provider"] != "Unknown":
            break
    if res["mx"] and res["provider"] == "Unknown":
        res["provider"] = "Other / self-hosted (%s)" % res["mx"][0]

    txt = _txt(resolver, domain) or []
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if spf:
        res["spf"] = spf[0]
        s = spf[0].lower().split()
        if "+all" in s or "all" in s[-1:] and not s[-1].startswith(("-", "~", "?")):
            res["spf_status"] = "too permissive (+all)"
        elif "?all" in s:
            res["spf_status"] = "neutral (?all)"
        elif len(spf) > 1:
            res["spf_status"] = "multiple SPF records (invalid)"
        else:
            res["spf_status"] = "ok"

    dmarc = [t for t in (_txt(resolver, "_dmarc." + domain) or []) if t.lower().startswith("v=dmarc1")]
    if dmarc:
        res["dmarc"] = dmarc[0]
        policy = "none"
        for part in dmarc[0].split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip().lower() == "p":
                policy = v.strip().lower() or "none"
        res["dmarc_policy"] = policy

    res["mta_sts"] = any(t.lower().startswith("v=stsv1") for t in (_txt(resolver, "_mta-sts." + domain) or []))
    res["tls_rpt"] = any(t.lower().startswith("v=tlsrptv1") for t in (_txt(resolver, "_smtp._tls." + domain) or []))
    return res


# --------------------------------------------------------------------------- #
# Host discovery
# --------------------------------------------------------------------------- #
def _resolves(host):
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return True
    except (socket.gaierror, OSError, UnicodeError):
        return False


def discover_hosts(domain, extra_hosts=(), max_workers=16):
    candidates = [domain] + ["%s.%s" % (s, domain) for s in SUBDOMAINS]
    for h in extra_hosts:
        h = h.strip().lower()
        if h and h not in candidates:
            candidates.append(h)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        ok = list(pool.map(_resolves, candidates))
    return [h for h, good in zip(candidates, ok) if good]


def _role(host, domain):
    if host == domain:
        return "Main domain"
    label = host[: -(len(domain) + 1)] if host.endswith("." + domain) else host
    first = label.split(".")[0]
    if first in REMOTE_ACCESS:
        return "Remote access"
    if first in ("mail", "webmail", "owa", "autodiscover"):
        return "Email"
    if first == "www":
        return "Website"
    return "Service"


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def run_audit(domain_input, answers, extra_hosts=(), allow_private=False, cafile=None,
              resolver=None, progress=None):
    """Returns an audit dict. Raises ScanError for an invalid domain."""
    domain, _port = normalize_target(domain_input)
    if domain.startswith("www."):
        domain = domain[4:]

    def tick(msg, frac):
        if progress:
            progress(msg, frac)

    tick("Looking up email security records...", 0.05)
    email = check_email(domain, resolver)

    tick("Discovering public services...", 0.2)
    hosts = discover_hosts(domain, extra_hosts)
    if not hosts:
        raise ScanError("No public services found for %s. Check the domain name." % domain)

    tick("Scanning %d services..." % len(hosts), 0.35)
    with ThreadPoolExecutor(max_workers=8) as pool:
        scans = list(pool.map(lambda h: scan(h, timeout=6.0, allow_private=allow_private, cafile=cafile), hosts))
    services = []
    for h, s in zip(hosts, scans):
        s["role"] = _role(h, domain)
        services.append(s)

    tick("Building findings...", 0.9)
    audit = {
        "domain": domain,
        "answers": dict(answers),
        "email": email,
        "services": services,
        "created": datetime.now(timezone.utc).strftime("%d %B %Y"),
    }
    audit["actions"], audit["rating"], audit["urgency"] = _assess(audit)
    tick("Done", 1.0)
    return audit


def _assess(a):
    actions = []  # (when, priority, title, detail)

    def add(when, prio, title, detail):
        actions.append((when, prio, title, detail))

    ans = a["answers"]
    live = [s for s in a["services"] if not s["error"]]
    no_tls13 = [s for s in live if s["tls_version"] != "TLSv1.3"]
    no_pq = [s for s in live if s["pq_supported"] is not True]
    remote_no_pq = [s for s in no_pq if s["role"] == "Remote access"]
    expiring = [s for s in live if s["cert_days_left"] < 30]
    untrusted = [s for s in live if not s["cert_trusted"]]

    if no_tls13:
        add("Now (0-3 months)", "High", "Upgrade %d service(s) to TLS 1.3" % len(no_tls13),
            "These services cannot use post-quantum encryption until upgraded: "
            + ", ".join(s["host"] for s in no_tls13) + ".")
    if remote_no_pq:
        add("Now (0-3 months)", "High", "Prioritise remote-access systems",
            "Remote-access gateways carry staff logins and confidential documents and lack post-quantum "
            "protection: " + ", ".join(s["host"] for s in remote_no_pq)
            + ". Ask the vendor for its post-quantum (hybrid key exchange) support and upgrade path.")
    other_no_pq = [s for s in no_pq if s not in remote_no_pq and s not in no_tls13]
    if other_no_pq:
        add("Next (3-12 months)", "Medium", "Enable hybrid post-quantum key exchange on %d service(s)" % len(other_no_pq),
            "Turn on X25519MLKEM768 via your CDN, load balancer or a server software upgrade for: "
            + ", ".join(s["host"] for s in other_no_pq) + ".")
    if expiring or untrusted:
        add("Now (0-3 months)", "High", "Fix certificate problems",
            "Untrusted, expired or soon-to-expire certificates on: "
            + ", ".join(sorted({s["host"] for s in expiring + untrusted})) + ".")

    e = a["email"]
    if not e["lookup_failed"]:
        if e["dmarc_policy"] in ("missing", "none"):
            add("Now (0-3 months)", "High", "Enforce DMARC on email",
                "DMARC is %s, so criminals can send email that appears to come from your domain. "
                "Move to p=quarantine, then p=reject." % ("missing" if e["dmarc_policy"] == "missing" else "set to monitor only (p=none)"))
        if e["spf_status"] != "ok":
            add("Now (0-3 months)", "Medium", "Fix the SPF record", "SPF status: %s." % e["spf_status"])
        if not e["mta_sts"]:
            add("Next (3-12 months)", "Medium", "Require encrypted email delivery (MTA-STS)",
                "Without MTA-STS, email sent to you can be downgraded to unencrypted delivery. Add MTA-STS and TLS-RPT.")

    if ans.get("inventory") != "Yes, complete":
        add("Now (0-3 months)", "High", "Build a cryptographic inventory",
            "List every system that uses encryption (email, VPN, document management, backups, cloud apps, "
            "suppliers) with its owner and vendor. The NCSC expects this discovery work to be done by 2028.")
    if ans.get("leadership") == "No":
        add("Now (0-3 months)", "Medium", "Brief partners / leadership",
            "Explain the 'harvest now, decrypt later' risk and the NCSC timeline (plan by 2028, priority "
            "upgrades by 2031, full migration by 2035), and assign an owner.")
    if ans.get("suppliers") != "Yes":
        add("Next (3-12 months)", "Medium", "Ask key suppliers for their post-quantum roadmap",
            "Send your IT provider, practice/document management and cloud vendors a short questionnaire on "
            "when they will support post-quantum cryptography.")
    if ans.get("key_mgmt") != "Yes":
        add("Next (3-12 months)", "Medium", "Set up certificate and key management",
            "Keep a register of certificates and keys with owners and renewal dates, so algorithms can be "
            "swapped quickly (crypto-agility).")
    if ans.get("mfa") in ("No", "Not sure") and ans.get("vpn", "None") != "None":
        add("Now (0-3 months)", "High", "Turn on multi-factor authentication for remote access",
            "Remote access without MFA is one of the most common ways attackers get in today, regardless of quantum risk.")
    vpn = ans.get("vpn", "None")
    if vpn not in ("None", "Not sure"):
        add("Next (3-12 months)", "Medium", "Check %s VPN post-quantum support" % vpn,
            "Confirm the firmware version and whether post-quantum key exchange is available or planned.")
    elif vpn == "Not sure":
        add("Now (0-3 months)", "Medium", "Identify your remote-access technology",
            "Find out which VPN or remote-access product staff use; it is a priority for post-quantum upgrades.")
    if ans.get("backups") == "No / not sure":
        add("Next (3-12 months)", "Medium", "Confirm backups are encrypted",
            "Check backups are encrypted with strong (256-bit) symmetric encryption and record where keys are held.")
    add("Later (1-3 years)", "Low", "Adopt post-quantum certificates and signatures",
        "When public certificate authorities and your vendors support them, move to post-quantum signatures. "
        "Plan to complete full migration by 2035 in line with NCSC guidance.")

    actions.sort(key=lambda x: (ROADMAP_ORDER[x[0]], {"High": 0, "Medium": 1, "Low": 2}[x[1]]))

    # Overall rating
    total = len(live) or 1
    pq_share = sum(1 for s in live if s["pq_supported"] is True) / total
    highs = sum(1 for x in actions if x[1] == "High")
    if pq_share >= 0.8 and highs <= 1:
        rating = "Good"
    elif pq_share >= 0.4 and highs <= 3:
        rating = "Partial"
    else:
        rating = "At risk"

    lifetime = ans.get("data_lifetime", "")
    if lifetime in ("10+ years", "5-10 years"):
        urgency = "High"
    elif lifetime == "2-5 years":
        urgency = "Medium"
    else:
        urgency = "Lower"
    return actions, rating, urgency


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
RATING_COLOURS = {"Good": "#1a7f37", "Partial": "#b7791f", "At risk": "#c92a2a"}


def build_audit_report(a, brand_name="", contact=""):
    ans = a["answers"]
    brand = escape(brand_name.strip()) if brand_name and brand_name.strip() else "Quantum-Readiness Audit"
    org = escape(ans.get("org") or a["domain"])
    live = [s for s in a["services"] if not s["error"]]
    pq_yes = sum(1 for s in live if s["pq_supported"] is True)

    svc_rows = ""
    for s in a["services"]:
        if s["error"]:
            svc_rows += "<tr><td>%s</td><td>%s</td><td colspan='4' class='muted'>%s</td></tr>" % (
                escape(s.get("host", s["target"])), escape(s["role"]), escape(s["error"]))
            continue
        pq = "<span class='ok'>Yes</span>" if s["pq_supported"] is True else (
            "<span class='bad'>No</span>" if s["pq_supported"] is False else "Unknown")
        svc_rows += "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            escape(s["host"]), escape(s["role"]), pq, escape(s["tls_version"]), escape(s["grade"]),
            escape(s["cert_expires"]))

    e = a["email"]
    if e["lookup_failed"]:
        email_html = "<p class='muted'>Email records could not be looked up at the time of the audit.</p>"
    else:
        def yn(v):
            return "<span class='ok'>Yes</span>" if v else "<span class='bad'>No</span>"
        dm = e["dmarc_policy"]
        dm_html = ("<span class='ok'>%s</span>" if dm in ("reject", "quarantine") else "<span class='bad'>%s</span>") % escape(dm)
        sp_html = ("<span class='ok'>%s</span>" if e["spf_status"] == "ok" else "<span class='bad'>%s</span>") % escape(e["spf_status"])
        email_html = ("<table><tr><th>Email provider</th><td>%s</td></tr><tr><th>SPF</th><td>%s</td></tr>"
                      "<tr><th>DMARC policy</th><td>%s</td></tr><tr><th>MTA-STS (enforced encryption)</th><td>%s</td></tr>"
                      "<tr><th>TLS reporting</th><td>%s</td></tr></table>") % (
            escape(e["provider"]) if e["mx"] else "No mail servers found", sp_html, dm_html, yn(e["mta_sts"]), yn(e["tls_rpt"]))

    road = ""
    for phase in ROADMAP_ORDER:
        items = [x for x in a["actions"] if x[0] == phase]
        if not items:
            continue
        road += "<h3>%s</h3>" % escape(phase)
        for _w, prio, title, detail in items:
            road += ("<div class='act'><span class='p p%s'>%s</span><div><b>%s</b><div class='muted'>%s</div></div></div>"
                     % (prio, prio, escape(title), escape(detail)))

    q_labels = [
        ("Sector", "sector"), ("Staff", "staff"), ("IT managed by", "it_managed"),
        ("Email platform (stated)", "email_platform"), ("Remote access / VPN", "vpn"),
        ("MFA on remote access", "mfa"), ("Key systems", "systems"),
        ("How long client data must stay confidential", "data_lifetime"),
        ("Cryptographic inventory", "inventory"), ("Suppliers asked about PQC", "suppliers"),
        ("Certificate/key register", "key_mgmt"), ("Backups encrypted", "backups"),
        ("Leadership briefed on PQC", "leadership"), ("Notes", "notes"),
    ]
    q_rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (escape(lbl), escape(str(ans.get(k) or "-")))
                     for lbl, k in q_labels)

    contact_html = ""
    if contact and contact.strip():
        contact_html = "<div class='cta'>Prepared by <b>%s</b> &middot; %s</div>" % (brand, escape(contact.strip()))

    return """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Quantum-Readiness Audit: %(org)s</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2328;max-width:860px;margin:32px auto;padding:0 20px;line-height:1.5}
h1{font-size:28px;margin:0}h2{font-size:19px;margin-top:36px;border-bottom:1px solid #ddd;padding-bottom:6px}h3{font-size:16px;margin:20px 0 6px}
.brand{color:#57606a;font-size:14px}.muted{color:#57606a;font-size:14px}
.kpis{display:flex;gap:14px;flex-wrap:wrap;margin:22px 0}.kpi{flex:1;min-width:150px;border:1px solid #ddd;border-radius:12px;padding:14px}
.kpi .v{font-size:24px;font-weight:700}.kpi .l{color:#57606a;font-size:13px}
table{border-collapse:collapse;width:100%%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}th{color:#57606a;font-weight:500}
.ok{color:#1a7f37;font-weight:600}.bad{color:#c92a2a;font-weight:600}
.act{display:flex;gap:12px;margin:10px 0}.p{font-size:11px;font-weight:700;border-radius:6px;padding:2px 8px;height:fit-content;color:#fff;flex-shrink:0;width:52px;text-align:center}
.pHigh{background:#c92a2a}.pMedium{background:#b7791f}.pLow{background:#57606a}
.cta{margin-top:28px;padding:16px;background:#f0f6ff;border-radius:10px}.note{color:#6e7781;font-size:12px;margin-top:32px}
@media print{body{margin:0}h2{break-after:avoid}.act,tr{break-inside:avoid}}
</style></head><body>
<div class="brand">%(brand)s</div>
<h1>Quantum-Readiness Audit</h1>
<div class="muted">%(org)s &middot; %(domain)s &middot; %(created)s</div>
<div class="kpis">
<div class="kpi"><div class="v" style="color:%(rcol)s">%(rating)s</div><div class="l">Overall readiness</div></div>
<div class="kpi"><div class="v">%(urgency)s</div><div class="l">Urgency (based on how long data must stay confidential)</div></div>
<div class="kpi"><div class="v">%(pq_yes)d / %(live)d</div><div class="l">Public services with post-quantum protection</div></div>
<div class="kpi"><div class="v">%(highs)d</div><div class="l">High-priority actions</div></div>
</div>
<h2>Summary</h2>
<p>Quantum computers are expected to break the public-key encryption that protects most systems today. Data
intercepted now can be stored and decrypted later ("harvest now, decrypt later"), so information that must stay
confidential for years is already at risk. The UK's National Cyber Security Centre (NCSC) asks organisations to
identify their cryptography and plan migration <b>by 2028</b>, complete high-priority upgrades <b>by 2031</b>, and
finish migrating <b>by 2035</b>.</p>
<p>This audit combines an external scan of %(org)s's internet-facing services with information provided by the
organisation, and sets out a prioritised roadmap.</p>
<h2>Prioritised roadmap</h2>%(road)s
<h2>Internet-facing services</h2>
<table><tr><th>Service</th><th>Type</th><th>Post-quantum</th><th>TLS</th><th>Grade</th><th>Cert expires</th></tr>%(svc)s</table>
<h2>Email security</h2>%(email)s
<h2>Information provided by the organisation</h2><table>%(q)s</table>
%(contact)s
<div class="note">The external scan used only standard public connections, the same as a web browser or email
server would make, to services that resolve publicly under %(domain)s. Services not exposed to the internet, and
the accuracy of information provided by the organisation, are outside the scope of the automated checks.</div>
</body></html>""" % {
        "org": org, "brand": brand, "domain": escape(a["domain"]), "created": escape(a["created"]),
        "rcol": RATING_COLOURS[a["rating"]], "rating": a["rating"], "urgency": escape(a["urgency"]),
        "pq_yes": pq_yes, "live": len(live), "highs": sum(1 for x in a["actions"] if x[1] == "High"),
        "road": road, "svc": svc_rows, "email": email_html, "q": q_rows, "contact": contact_html,
    }
