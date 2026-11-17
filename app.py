"""Quantum-Readiness Scanner - web app. Run with:  streamlit run app.py"""

import csv
import io
import os
import re
import zipfile
from concurrent.futures import ThreadPoolExecutor

import streamlit as st

from report import build_html_report
from scanner import scan

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

tab1, tab2 = st.tabs(["Scan a website", "Bulk scan"])

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

st.divider()
st.caption(
    "This tool only performs a standard HTTPS connection, the same as a web browser visiting the site. "
    "It checks the public website only and is not a full security audit."
)
