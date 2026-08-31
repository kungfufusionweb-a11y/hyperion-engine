"""Hyperion Security Engine — minimal Streamlit UI shell.

This is a plumbing checkpoint that wires together the backend modules
(scanner.py, dependency_check.py, repo_scanner.py, ai_llm.py) with zero
visual polish. Confirms the full pipeline runs end-to-end.
"""

import os
import tempfile
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# Load API configuration from .env
load_dotenv()

from scanner import scan_source
from dependency_check import check_dependencies
from repo_scanner import scan_repository
from ai_llm import get_analysis


def main():
    st.set_page_config(page_title="Hyperion Security Engine", layout="wide")
    st.title("Hyperion Security Engine")
    st.caption("Minimal UI shell — pipeline plumbing checkpoint")

    # Sidebar: input mode selection
    st.sidebar.header("Input Mode")
    mode = st.sidebar.radio(
        "Select scan mode:",
        ["Paste code snippet", "Upload file", "GitHub repo URL"],
        index=0,
    )

    # Optional requirements.txt uploader (for snippet/upload modes)
    if mode in ["Paste code snippet", "Upload file"]:
        st.sidebar.markdown("---")
        st.sidebar.subheader("Dependencies (optional)")
        req_file = st.sidebar.file_uploader(
            "Upload requirements.txt:",
            type=["txt"],
            accept_multiple_files=False,
            help="Optional: analyze dependencies for known vulnerabilities",
        )
    else:
        req_file = None

    # Main content area: input based on mode
    st.header("Input")
    code = None
    filename = "input.py"
    repo_url = None

    if mode == "Paste code snippet":
        code = st.text_area(
            "Paste Python code to scan:",
            height=300,
            placeholder="# Paste your Python code here\nimport os\nos.system('ls')",
        )

    elif mode == "Upload file":
        uploaded_file = st.file_uploader(
            "Upload a Python file:",
            type=["py"],
            accept_multiple_files=False,
        )
        if uploaded_file is not None:
            try:
                code = uploaded_file.read().decode("utf-8-sig")
                filename = uploaded_file.name
            except UnicodeDecodeError as e:
                st.error(f"Could not decode uploaded file: {e}")
                return

    elif mode == "GitHub repo URL":
        repo_url = st.text_input(
            "GitHub repository URL:",
            placeholder="https://github.com/user/repo",
        )

    # Scan button
    st.markdown("---")
    scan_clicked = st.button("Scan", type="primary", use_container_width=True)

    if scan_clicked:
        # Validate input and show warnings for empty inputs
        if mode == "Paste code snippet" and not code:
            st.warning("Please paste some code to scan.")
            return
        elif mode == "Upload file" and code is None:
            st.warning("Please upload a Python file.")
            return
        elif mode == "GitHub repo URL" and not repo_url:
            st.warning("Please enter a GitHub repository URL.")
            return

        # Run the scan
        try:
            with st.spinner("Analyzing..."):
                scan_findings = []
                dep_findings = []
                source_code = ""

                if mode in ["Paste code snippet", "Upload file"]:
                    # AST-based source code scan
                    scan_findings = scan_source(code or "", filename=filename)

                    # Dependency scan (if requirements.txt uploaded)
                    if req_file is not None:
                        temp_file = None
                        temp_path = ""
                        try:
                            # Write uploaded requirements.txt to temp file with utf-8-sig encoding
                            temp_fd, temp_path = tempfile.mkstemp(suffix=".txt")
                            temp_file = os.fdopen(temp_fd, "w", encoding="utf-8-sig")
                            temp_file.write(req_file.read().decode("utf-8-sig"))
                            temp_file.close()  # Important: close before passing to check_dependencies()
                            
                            # Now pass the path to check_dependencies
                            dep_findings = check_dependencies(temp_path)
                        finally:
                            if temp_file and not temp_file.closed:
                                temp_file.close()
                            if temp_path:
                                try:
                                    os.remove(temp_path)
                                except OSError:
                                    pass  # Ignore removal errors (file may not exist)

                    # Get AI analysis (or fallback) for single-file scans only
                    source_code = code or ""
                    analysis = get_analysis(
                        scan_findings=scan_findings,
                        dep_findings=dep_findings,
                        source_code=source_code,
                    )

                    # Build final result
                    output = {
                        "scan_findings": scan_findings,
                        "dep_findings": dep_findings,
                        "analysis": analysis,
                    }

                elif mode == "GitHub repo URL":
                    # Full repository scan - no AI analysis for whole repos yet
                    result = scan_repository(repo_url)
                    scan_findings = result["scan_findings"]
                    dep_findings = result["dep_findings"]
                    
                    # Build result without AI analysis
                    output = {
                        "scan_findings": scan_findings,
                        "dep_findings": dep_findings,
                    }
                    
                    if result["error"]:
                        st.warning(f"Repository scan error: {result['error']}")

                # Display result
                st.header("Results")
                st.json(output)

        except Exception as e:
            st.error(f"Unexpected error during scan: {e}")
            st.exception(e)


if __name__ == "__main__":
    main()