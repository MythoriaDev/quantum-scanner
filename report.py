"""Builds a client-friendly, self-contained HTML report from a scan result."""

from html import escape

GRADE_COLOURS = {"A": "#1a7f37", "B": "#4c9a2a", "C": "#b7791f", "D": "#d9480f", "F": "#c92a2a"}
STATUS_ICONS = {"good": ("&#10004;", "#1a7f37"), "warn": ("!", "#b7791f"),
                "bad": ("&#10008;", "#c92a2a"), "info": ("i", "#1c6dd0")}

GRADE_SUMMARY = {
    "A": "Excellent. This website already uses post-quantum protection for its traffic.",
    "B": "Good, but there are gaps to close before it is fully quantum-ready.",
    "C": "Partially prepared. Important quantum-readiness measures are missing.",
    "D": "At risk. Traffic to this website can be recorded today and decrypted by future quantum computers.",
    "F": "High risk. The website's encryption setup needs urgent attention.",
}


def build_html_report(r, brand_name="", contact=""):
    if r.get("error"):
        raise ValueError("Cannot build a report for a failed scan.")
    host = escape(r["host"] + ("" if r["port"] == 443 else ":%d" % r["port"]))
    grade = r["grade"]
    colour = GRADE_COLOURS[grade]
    brand = escape(brand_name.strip()) if brand_name and brand_name.strip() else "Quantum-Readiness Scanner"

    rows = ""
    for status, title, text in r["findings"]:
        icon, c = STATUS_ICONS[status]
        rows += (
            '<div class="f"><div class="i" style="background:%s">%s</div>'
            '<div><div class="t">%s</div><div class="d">%s</div></div></div>'
            % (c, icon, escape(title), escape(text))
        )

    tech = [
        ("Website", host),
        ("IP address", escape(str(r.get("ip", "")))),
        ("TLS version", escape(r["tls_version"])),
        ("Cipher", escape("%s (%d-bit)" % (r["cipher"], r["cipher_bits"] or 0))),
        ("Post-quantum key exchange", "Yes (X25519MLKEM768)" if r["pq_supported"] is True
         else "No" if r["pq_supported"] is False else "Unknown"),
        ("Certificate key", escape("%s %d-bit" % (r["cert_key_type"], r["cert_key_bits"]))),
        ("Certificate issuer", escape(r["cert_issuer"])),
        ("Certificate expires", escape(r["cert_expires"])),
        ("Scanned", escape(r["scanned_at"])),
    ]
    tech_rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, v) for k, v in tech)

    next_steps = []
    if r["pq_supported"] is not True:
        next_steps.append("Enable hybrid post-quantum key exchange (X25519MLKEM768) on your web server, "
                          "load balancer or CDN. Many providers support it with a configuration change or upgrade.")
    if r["tls_version"] != "TLSv1.3":
        next_steps.append("Upgrade your server to support TLS 1.3.")
    if not r["cert_trusted"] or r["cert_days_left"] < 30:
        next_steps.append("Fix your HTTPS certificate (it is untrusted, expired or expiring soon).")
    next_steps.append("Build an inventory of everywhere else your organisation uses encryption (email, VPNs, "
                      "databases, internal systems, suppliers). This scan only covers your public website.")
    next_steps.append("Create a migration roadmap aligned with government post-quantum guidance.")
    steps_html = "".join("<li>%s</li>" % escape(s) for s in next_steps)

    contact_html = ""
    if contact and contact.strip():
        contact_html = ('<div class="cta">Want help becoming quantum-ready? Contact <b>%s</b> at <b>%s</b>.</div>'
                        % (brand, escape(contact.strip())))

    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Quantum-Readiness Report: %(host)s</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2328;max-width:820px;margin:32px auto;padding:0 20px;line-height:1.5}
h1{font-size:26px;margin:0}h2{font-size:18px;margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:6px}
.brand{color:#57606a;font-size:14px;margin-bottom:4px}
.hero{display:flex;gap:24px;align-items:center;margin:24px 0;padding:20px;border:1px solid #ddd;border-radius:12px}
.g{font-size:56px;font-weight:700;color:#fff;background:%(colour)s;width:96px;height:96px;border-radius:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.s{font-size:15px}.score{font-size:22px;font-weight:600}
.f{display:flex;gap:12px;margin:12px 0}.i{color:#fff;width:24px;height:24px;border-radius:50%%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0;margin-top:2px}
.t{font-weight:600}.d{color:#57606a;font-size:14px}
table{border-collapse:collapse;width:100%%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}th{width:38%%;color:#57606a;font-weight:500}
.cta{margin-top:28px;padding:16px;background:#f0f6ff;border-radius:10px}
.note{color:#6e7781;font-size:12px;margin-top:32px}
@media print{body{margin:0}}
</style></head><body>
<div class="brand">%(brand)s</div>
<h1>Quantum-Readiness Report</h1>
<div style="color:#57606a">%(host)s</div>
<div class="hero"><div class="g">%(grade)s</div><div><div class="score">Score: %(score)d / 100</div><div class="s">%(summary)s</div></div></div>
<h2>Why this matters</h2>
<p>Future quantum computers will be able to break the encryption most organisations use today. Attackers are already
recording encrypted traffic to decrypt later ("harvest now, decrypt later"), and governments have set deadlines for
organisations to move to post-quantum cryptography.</p>
<h2>Findings</h2>%(rows)s
<h2>Recommended next steps</h2><ol>%(steps)s</ol>
<h2>Technical details</h2><table>%(tech)s</table>
%(contact)s
<div class="note">This automated check examines only the public HTTPS configuration of the website above, the same
information any web browser sees when it connects. It is not a full security audit and does not cover internal systems.</div>
</body></html>""" % {
        "host": host, "colour": colour, "brand": brand, "grade": grade, "score": r["score"],
        "summary": escape(GRADE_SUMMARY[grade]), "rows": rows, "steps": steps_html,
        "tech": tech_rows, "contact": contact_html,
    }
