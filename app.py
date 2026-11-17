"""Quantum-Readiness Scanner - web app. Run with:  streamlit run app.py"""

import csv
import io
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor

import streamlit as st

from audit import build_audit_report, run_audit
from report import build_html_report
from scanner import ScanError, scan

# Testing-only switches (leave unset in production)
ALLOW_PRIVATE = os.environ.get("QSCAN_ALLOW_PRIVATE") == "1"
CAFILE = os.environ.get("QSCAN_CAFILE") or None
MAX_BULK = 25

st.set_page_config(page_title="Quantum-Readiness Scanner", page_icon="🛡️", layout="centered")

ICONS = {"good": "✅", "warn": "⚠️", "bad": "❌", "info": "ℹ️"}
GRADE_TEXT = {
    "A": "Excellent: post-quantum protection is in place.",
    "B": "Good, with some gaps to close.",
    "C": "Partially prepared.",
    "D": "At risk from 'harvest now, decrypt later' attacks.",
    "F": "High risk: needs urgent attention.",
}


def run_scan(target):
    return scan(target, allow_private=ALLOW_PRIVATE, cafile=CAFILE)


def safe_filename(host):
    return re.sub(r"[^A-Za-z0-9.-]", "_", host)


def display_name(r):
    if r.get("error"):
        return r["target"]
    return r["host"] if r["port"] == 443 else "%s:%d" % (r["host"], r["port"])


def pq_label(v):
    return "Yes" if v is True else "No" if v is False else "Unknown"


# ---------------- Sidebar: branding for reports ---------------- #
with st.sidebar:
    st.header("Report branding")
    st.caption("Shown on downloadable reports you send to prospects.")
    brand = st.text_input("Your business name", key="brand", placeholder="e.g. QuantumSafe Advisory")
    contact = st.text_input("Contact email / phone", key="contact", placeholder="e.g. hello@yourbusiness.com")

st.title("🛡️ Quantum-Readiness Scanner")
st.write(
    "Check whether a website's encryption is ready for the quantum era: in particular, whether it uses "
    "**post-quantum key exchange** that protects against *harvest now, decrypt later* attacks."
)

tab1, tab2, tab3 = st.tabs(["Scan a website", "Bulk scan", "Client audit (paid)"])

# ---------------- Single scan ---------------- #
with tab1:
    with st.form("single"):
        target = st.text_input("Website address", placeholder="e.g. example.com")
        submitted = st.form_submit_button("Scan", type="primary")
    if submitted:
        with st.spinner("Scanning %s ..." % (target or "")):
            st.session_state["single_result"] = run_scan(target)

    r = st.session_state.get("single_result")
    if r:
        if r["error"]:
            st.error(r["error"])
        else:
            c1, c2 = st.columns([1, 3])
            c1.metric("Grade", r["grade"])
            c2.metric("Quantum-readiness score", "%d / 100" % r["score"])
            st.markdown("**%s**: %s" % (display_name(r), GRADE_TEXT[r["grade"]]))

            st.subheader("Findings")
            for status, title, text in r["findings"]:
                st.markdown("%s **%s**  \n%s" % (ICONS[status], title, text))

            with st.expander("Technical details"):
                st.table({
                    "Item": ["IP address", "TLS version", "Cipher", "Post-quantum key exchange",
                             "PQ check detail", "Certificate key", "Certificate issuer", "Certificate expires"],
                    "Value": [str(r["ip"]), r["tls_version"], "%s (%d-bit)" % (r["cipher"], r["cipher_bits"] or 0),
                              pq_label(r["pq_supported"]), r["pq_detail"],
                              "%s %d-bit" % (r["cert_key_type"], r["cert_key_bits"]),
                              r["cert_issuer"], r["cert_expires"]],
                })

            st.download_button(
                "⬇️ Download client report (HTML)",
                data=build_html_report(r, brand, contact),
                file_name="quantum-readiness-%s.html" % safe_filename(display_name(r)),
                mime="text/html",
            )
            st.caption("Open the report in a browser and use Print → Save as PDF to send it as a PDF.")

# ---------------- Bulk scan ---------------- #
with tab2:
    st.write("Scan up to %d websites at once, one per line, then download the results and reports." % MAX_BULK)
    with st.form("bulk"):
        raw = st.text_area("Websites", height=180, placeholder="example.com\nexample.org\nexample.net")
        bulk_submitted = st.form_submit_button("Scan all", type="primary")
    if bulk_submitted:
        targets = []
        for line in raw.replace(",", "\n").splitlines():
            t = line.strip()
            if t and t not in targets:
                targets.append(t)
        if not targets:
            st.warning("Please enter at least one website.")
        else:
            if len(targets) > MAX_BULK:
                st.warning("Only the first %d websites will be scanned." % MAX_BULK)
                targets = targets[:MAX_BULK]
            progress = st.progress(0.0, text="Scanning...")
            results = [None] * len(targets)
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(run_scan, t): i for i, t in enumerate(targets)}
                done = 0
                for fut in futures:
                    results[futures[fut]] = fut.result()
                    done += 1
                    progress.progress(done / len(targets), text="Scanned %d of %d" % (done, len(targets)))
            progress.empty()
            unique, seen = [], set()
            for r in results:  # drop duplicates such as example.com + https://example.com
                key = display_name(r)
                if key not in seen:
                    seen.add(key)
                    unique.append(r)
            st.session_state["bulk_result"] = unique

    results = st.session_state.get("bulk_result")
    if results:
        rows = []
        for r in results:
            if r["error"]:
                rows.append({"Website": r["target"], "Grade": "-", "Score": None, "Post-quantum": "-",
                             "TLS": "-", "Cert expires": "-", "Note": r["error"]})
            else:
                rows.append({"Website": display_name(r), "Grade": r["grade"], "Score": r["score"],
                             "Post-quantum": pq_label(r["pq_supported"]), "TLS": r["tls_version"],
                             "Cert expires": r["cert_expires"], "Note": ""})
        st.dataframe(rows, hide_index=True)

        ok = [r for r in results if not r["error"]]
        at_risk = [r for r in ok if r["pq_supported"] is not True]
        st.info("%d of %d websites scanned successfully. %d lack post-quantum protection: these are your best prospects."
                % (len(ok), len(results), len(at_risk)))

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        st.download_button("⬇️ Download results (CSV)", data=buf.getvalue(),
                           file_name="quantum-readiness-results.csv", mime="text/csv")

        if ok:
            zbuf = io.BytesIO()
            with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
                for r in ok:
                    z.writestr("quantum-readiness-%s.html" % safe_filename(display_name(r)),
                               build_html_report(r, brand, contact))
            st.download_button("⬇️ Download all client reports (ZIP)", data=zbuf.getvalue(),
                               file_name="quantum-readiness-reports.zip", mime="application/zip")

# ---------------- Client audit ---------------- #
with tab3:
    st.write(
        "Run a full quantum-readiness audit for a paying client. Fill in the questionnaire with the client "
        "(on a call works well), then run the audit. It scans their email security and public services "
        "(VPN, webmail, portals...) and produces a full report with a prioritised roadmap."
    )
    st.warning("Only audit an organisation that has asked you to, and keep their written go-ahead (an email is fine).")
    with st.form("audit"):
        c1, c2 = st.columns(2)
        org = c1.text_input("Client organisation name")
        domain = c2.text_input("Client's main domain", placeholder="e.g. clientfirm.co.uk")
        c1, c2, c3 = st.columns(3)
        sector = c1.selectbox("Sector", ["Legal", "Accountancy", "Financial services", "Healthcare", "Other"])
        staff = c2.selectbox("Staff", ["1-10", "11-50", "51-250", "250+"])
        it_managed = c3.selectbox("IT managed by", ["External IT provider (MSP)", "In-house", "Mix", "Not sure"])
        c1, c2, c3 = st.columns(3)
        email_platform = c1.selectbox("Email platform", ["Microsoft 365", "Google Workspace", "Own server", "Other", "Not sure"])
        vpn = c2.selectbox("Remote access / VPN", ["None", "Not sure", "Fortinet", "Cisco", "Palo Alto", "SonicWall",
                                                   "WatchGuard", "Citrix", "Microsoft (RDP/Always On)", "Other"])
        mfa = c3.selectbox("MFA on remote access", ["Yes", "No", "Not sure"])
        systems = st.text_input("Key systems (practice/document management, accounting, cloud apps)",
                                placeholder="e.g. iManage, Xero, SharePoint")
        data_lifetime = st.selectbox("How long must client data stay confidential?",
                                     ["10+ years", "5-10 years", "2-5 years", "Under 2 years"])
        c1, c2 = st.columns(2)
        inventory = c1.selectbox("Do they have a list of systems that use encryption?",
                                 ["No", "Partial", "Yes, complete"])
        suppliers = c2.selectbox("Have key suppliers been asked about post-quantum plans?", ["No", "Yes"])
        c1, c2, c3 = st.columns(3)
        key_mgmt = c1.selectbox("Register of certificates & keys?", ["No", "Yes"])
        backups = c2.selectbox("Backups encrypted?", ["Yes", "No / not sure"])
        leadership = c3.selectbox("Partners/leadership briefed on PQC?", ["No", "Yes"])
        extra = st.text_input("Other public hostnames to include (optional, comma-separated)",
                              placeholder="e.g. portal.clientfirm.com")
        notes = st.text_area("Notes", height=80)
        audit_submitted = st.form_submit_button("Run audit", type="primary")

    if audit_submitted:
        answers = {"org": org.strip(), "sector": sector, "staff": staff, "it_managed": it_managed,
                   "email_platform": email_platform, "vpn": vpn, "mfa": mfa, "systems": systems.strip(),
                   "data_lifetime": data_lifetime, "inventory": inventory, "suppliers": suppliers,
                   "key_mgmt": key_mgmt, "backups": backups, "leadership": leadership, "notes": notes.strip()}
        bar = st.progress(0.0, text="Starting audit...")
        try:
            st.session_state["audit_result"] = run_audit(
                domain, answers, extra_hosts=[h for h in extra.replace(" ", "").split(",") if h],
                allow_private=ALLOW_PRIVATE, cafile=CAFILE,
                progress=lambda msg, frac: bar.progress(frac, text=msg))
            st.session_state.pop("audit_error", None)
        except ScanError as e:
            st.session_state["audit_error"] = str(e)
            st.session_state.pop("audit_result", None)
        except Exception as e:  # never crash the app
            st.session_state["audit_error"] = "Unexpected error: %s" % e
            st.session_state.pop("audit_result", None)
        bar.empty()

    if st.session_state.get("audit_error"):
        st.error(st.session_state["audit_error"])
    a = st.session_state.get("audit_result")
    if a:
        live = [s for s in a["services"] if not s["error"]]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Overall readiness", a["rating"])
        c2.metric("Urgency", a["urgency"])
        c3.metric("Post-quantum services", "%d / %d" % (sum(1 for s in live if s["pq_supported"] is True), len(live)))
        c4.metric("High-priority actions", sum(1 for x in a["actions"] if x[1] == "High"))
        st.subheader("Roadmap")
        for when, prio, title, detail in a["actions"]:
            st.markdown("**[%s] %s**: %s  \n%s" % (prio, when, title, detail))
        st.subheader("Services found")
        st.dataframe([{"Service": s.get("host", s["target"]), "Type": s["role"],
                       "Post-quantum": pq_label(s.get("pq_supported")) if not s["error"] else "-",
                       "TLS": s.get("tls_version", "-") if not s["error"] else "-",
                       "Grade": s.get("grade", "-") if not s["error"] else "-",
                       "Note": s["error"] or ""} for s in a["services"]], hide_index=True)
        st.download_button(
            "⬇️ Download audit report (HTML)",
            data=build_audit_report(a, brand, contact),
            file_name="quantum-readiness-audit-%s.html" % safe_filename(a["domain"]),
            mime="text/html",
        )
        st.caption("Open the report in a browser and use Print → Save as PDF to deliver it.")

st.divider()
st.caption(
    "This tool only performs a standard HTTPS connection, the same as a web browser visiting the site. "
    "It checks the public website only and is not a full security audit."
)
