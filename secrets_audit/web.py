"""Streamlit web UI for secrets-audit.

This module serves two purposes:

1. The ``launch()`` function is the entry point for the ``secrets-audit-web``
   console script.  It checks that Streamlit is installed, then spawns
   ``streamlit run`` pointing at this file.

2. When executed by ``streamlit run``, the module-level code (guarded by
   the ``if`` block at the bottom) renders the interactive audit UI.

**Security invariant**: this module never calls ``GetSecretValue``.  It reuses
the same pipeline that the CLI uses, which only reads metadata and policies.
"""

from __future__ import annotations

import sys


# ---------------------------------------------------------------------------
# Part 1 — Launcher (entry point for ``secrets-audit-web``)
# ---------------------------------------------------------------------------


def launch() -> None:
    """Entry point for secrets-audit-web console script."""
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print(
            "Error: Streamlit is not installed.\n"
            "Install the web UI dependencies with:\n\n"
            "    pip install secrets-audit[web]\n",
            file=sys.stderr,
        )
        sys.exit(1)

    import subprocess
    from pathlib import Path

    web_module = str(Path(__file__).resolve())
    subprocess.run(  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            web_module,
            "--server.address",
            "127.0.0.1",
            "--server.headless",
            "true",
            "--browser.gatherUsageStats",
            "false",
        ]
    )


# ---------------------------------------------------------------------------
# Part 2 — Streamlit app (runs when executed by ``streamlit run``)
# ---------------------------------------------------------------------------

if __name__ == "__main__" or "streamlit" in sys.modules:
    import streamlit as st

    from secrets_audit.pipeline import (
        AuditParams,
        ValidationError,
        run_audit,
        validate_params,
    )
    from secrets_audit.renderer import _ic_column_table, render

    # -- Page config ---------------------------------------------------------

    st.set_page_config(page_title="secrets-audit", layout="wide")
    st.title("secrets-audit")
    st.caption("Resolve and report who can access an AWS Secrets Manager secret")

    # -- Sidebar (Input Form) ------------------------------------------------

    with st.sidebar:
        st.header("Audit Parameters")

        secret = st.text_input("Secret name or ARN", key="secret")
        region = st.text_input("AWS Region", key="region")
        output_format = st.selectbox(
            "Output Format", ["table", "json"], key="output_format"
        )

        st.divider()
        st.subheader("Identity Center Resolution")

        master_profile = st.text_input("Master Profile", key="master_profile")
        master_account_id = st.text_input(
            "Master Account ID",
            key="master_account_id",
            disabled=bool(master_profile),
        )
        cross_account_role_arn = st.text_input(
            "Cross-Account Role ARN",
            key="cross_account_role_arn",
            disabled=bool(master_profile),
        )
        ic_region = st.text_input("IC Region", key="ic_region")

        st.divider()
        st.subheader("Options")

        last_accessed = st.checkbox("Last Accessed", key="last_accessed")
        versions = st.checkbox("Include Versions", key="versions")
        expand_groups = st.checkbox("Expand Groups", key="expand_groups")
        allow_partial = st.checkbox("Allow Partial", key="allow_partial")

        run_clicked = st.button("Run Audit", type="primary")

    # -- Main Area (Results) -------------------------------------------------

    if run_clicked:
        if not secret:
            st.error("Secret name or ARN is required.")
        else:
            # Build AuditParams from form values
            params = AuditParams(
                secret=secret,
                output_format=output_format,
                region=region or None,
                master_account_id=master_account_id or None,
                cross_account_role_arn=cross_account_role_arn or None,
                master_profile=master_profile or None,
                expand_groups=expand_groups,
                last_accessed=last_accessed,
                versions=versions,
                allow_partial=allow_partial,
                ic_region=ic_region or None,
            )

            # Validate inputs before any AWS calls
            try:
                validate_params(params)
            except ValidationError as exc:
                st.error(str(exc))
                st.stop()

            # Run the audit with progress feedback
            try:
                with st.status("Running audit...", expanded=True) as status:
                    report = run_audit(
                        params,
                        progress=lambda msg: status.update(label=msg),
                    )
                    status.update(label="Audit complete!", state="complete")
            except Exception as exc:
                st.error(f"Audit failed: {exc}")
                st.stop()

            # -- Display metadata header --
            m = report.metadata
            st.markdown(
                f"**Secret:** {m.secret_name}  \n"
                f"**ARN:** {m.secret_arn}  \n"
                f"**Region:** {m.region or '(default)'}  \n"
                f"**Report generated:** {m.generated_at}  \n"
                f"**Generated by:** {m.generated_by}  \n"
                f"**Tool:** {m.tool_version}"
            )

            # -- Display warnings --
            for warning in report.warnings:
                st.warning(warning)

            # -- Display principals --
            if not report.principals:
                st.info("No IAM principals have access to this secret")
            else:
                rows = []
                for p in report.principals:
                    ic_col = _ic_column_table(p)
                    la = p.last_accessed
                    if la is None:
                        la_str = "N/A"
                    elif hasattr(la, "strftime"):
                        la_str = la.strftime("%Y-%m-%d %H:%M UTC")
                    else:
                        la_str = str(la)

                    rows.append(
                        {
                            "Principal Type": p.principal_type.value,
                            "Principal Name": p.principal_name,
                            "IC User / Group": ic_col,
                            "Access Level": p.access_level.value,
                            "Last Accessed": la_str,
                        }
                    )

                st.dataframe(rows, use_container_width=True)

            # -- Display versions table --
            if versions and report.versions:
                st.subheader("Secret Versions")
                v_rows = []
                for v in report.versions:
                    created = "N/A"
                    if v.created_date is not None:
                        if hasattr(v.created_date, "strftime"):
                            created = v.created_date.strftime(
                                "%Y-%m-%d %H:%M UTC"
                            )
                        else:
                            created = str(v.created_date)
                    v_rows.append(
                        {
                            "Version ID": v.version_id,
                            "Staging Labels": ", ".join(v.staging_labels),
                            "Created Date": created,
                        }
                    )
                st.dataframe(v_rows, use_container_width=True)

            # -- Download buttons --
            st.divider()
            col1, col2 = st.columns(2)
            with col1:
                pdf_bytes = render(report, "pdf")
                st.download_button(
                    "Download PDF",
                    data=pdf_bytes,
                    file_name="secrets-audit-report.pdf",
                    mime="application/pdf",
                )
            with col2:
                st.download_button(
                    "Download CSV",
                    data=render(report, "csv"),
                    file_name="secrets-audit-report.csv",
                    mime="text/csv",
                )
