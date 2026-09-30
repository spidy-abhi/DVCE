import os
import re
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

from athena_client import prompt_athena
from call_graph import build_package_call_graph, is_call_graph_request
from dependency_audit import scan_python_dependencies
from local_repository import build_repository_context


load_dotenv()

st.set_page_config(page_title="Repository Chat", layout="wide")
st.title("Local Repository Chat")
st.caption("Ask questions about a repository on this machine.")

if "active_repository" not in st.session_state:
    st.session_state.active_repository = ""
if "messages" not in st.session_state:
    st.session_state.messages = []

with st.sidebar:
    st.subheader("Repository")
    repository_input = st.text_input(
        "Local folder path",
        value=str(Path.cwd()),
        key="repository_path",
    )
    if st.button("Open repository", type="primary"):
        normalized_path = repository_input.strip().strip("\"").strip("'")
        candidate = Path(normalized_path).expanduser()
        if candidate.is_dir():
            resolved_path = str(candidate.resolve())
            if resolved_path != st.session_state.active_repository:
                st.session_state.messages = []
                st.session_state.pop("dependency_scan", None)
                st.session_state.pop("dependency_scan_error", None)
            st.session_state.active_repository = resolved_path
            st.success("Repository opened.")
        else:
            st.error(f"Folder not found: {normalized_path or '(empty path)'}")

    if st.session_state.active_repository:
        st.caption(st.session_state.active_repository)
    if not os.getenv("ATHENA_AUTH_TOKEN"):
        st.warning("Set ATHENA_AUTH_TOKEN in .env to enable chat.")

st.caption("Relevant local source files are sent to the configured Athena service with each question.")

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        for graph in message.get("graphs", []):
            with st.expander(
                f"{graph['package']} call graph · {graph['affected_count']} affected functions",
                expanded=False,
            ):
                st.caption(graph["caption"])
                st.graphviz_chart(graph["dot"], use_container_width=True)

if st.session_state.active_repository:
    if st.button("Scan Python dependencies for CVEs"):
        st.session_state.pop("dependency_scan", None)
        st.session_state.pop("dependency_scan_error", None)
        try:
            with st.spinner("Resolving Python dependencies and checking OSV advisories..."):
                st.session_state.dependency_scan = scan_python_dependencies(
                    Path(st.session_state.active_repository)
                )
        except Exception as error:
            st.session_state.dependency_scan_error = str(error)
        else:
            st.session_state.pop("dependency_scan_error", None)

    if st.session_state.get("dependency_scan_error"):
        st.error(st.session_state.dependency_scan_error)

    dependency_scan = st.session_state.get("dependency_scan")
    if dependency_scan:
        st.subheader("Dependency CVE scan")
        st.caption(
            f"Audited {dependency_scan['dependency_count']} resolved package versions from "
            f"{len(dependency_scan['manifests'])} requirements file(s) against OSV."
        )
        if dependency_scan["message"]:
            st.info(dependency_scan["message"])
        elif dependency_scan["findings"]:
            critical_count = sum(
                finding["severity"] == "CRITICAL"
                for finding in dependency_scan["findings"]
            )
            st.metric("Critical findings", critical_count)
            st.dataframe(
                [
                    {
                        "Severity": finding["severity"],
                        "Package": finding["package"],
                        "Installed": finding["version"],
                        "CVE": finding["cve_ids"],
                        "Advisory": finding["advisory_id"],
                        "CVSS": finding["cvss_score"],
                        "Fixed in": finding["fixed_versions"],
                        "Summary": finding["summary"],
                        "Manifest": finding["manifest"],
                    }
                    for finding in dependency_scan["findings"]
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("No known vulnerabilities were reported for the resolved dependencies.")

    question = st.chat_input("Ask about this repository")
    if question:
        st.session_state.messages.append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)

        with st.chat_message("assistant"):
            try:
                graphs = []
                if is_call_graph_request(question):
                    repository = Path(st.session_state.active_repository)
                    dependency_scan = st.session_state.get("dependency_scan")
                    if dependency_scan is None:
                        with st.spinner("Checking dependencies for the requested CVE..."):
                            dependency_scan = scan_python_dependencies(repository)
                        st.session_state.dependency_scan = dependency_scan

                    requested_cves = {
                        cve.upper()
                        for cve in re.findall(r"CVE-\d{4}-\d{4,}", question, re.IGNORECASE)
                    }
                    findings = dependency_scan["findings"]
                    if requested_cves:
                        selected_findings = [
                            finding
                            for finding in findings
                            if requested_cves.intersection(
                                re.findall(
                                    r"CVE-\d{4}-\d{4,}",
                                    f"{finding['cve_ids']} {finding['advisory_id']}",
                                    re.IGNORECASE,
                                )
                            )
                        ]
                    else:
                        selected_findings = [
                            finding
                            for finding in findings
                            if finding["severity"] in {"CRITICAL", "HIGH"}
                        ]

                    if not selected_findings:
                        answer = (
                            f"No matching dependency finding was found for "
                            f"{', '.join(sorted(requested_cves)) if requested_cves else 'Critical/High findings'}. "
                            "Run the dependency CVE scan and check that the requested CVE affects a dependency in this repository."
                        )
                    else:
                        seen_packages = set()
                        for finding in selected_findings:
                            package = finding["package"]
                            if package in seen_packages:
                                continue
                            seen_packages.add(package)
                            result = build_package_call_graph(repository, package)
                            if result["dot"]:
                                graphs.append(
                                    {
                                        "package": package,
                                        "caption": (
                                            f"Showing {result['node_count']} nearby nodes" 
                                            + (" from a larger set." if result["truncated"] else ".")
                                            + " Direct package users are red; neighbors are blue."
                                        ),
                                        "affected_count": result["affected_count"],
                                        "dot": result["dot"],
                                    }
                                )
                        if graphs:
                            answer = (
                                "Generated a static call graph for the package(s) associated with "
                                f"{', '.join(sorted(seen_packages))}. Red nodes directly use the affected "
                                "package; blue nodes are connected project callers or callees. This shows "
                                "static call relationships, not proof of runtime reachability or exploitability."
                            )
                        else:
                            answer = (
                                "The dependency finding is present, but no repository functions directly "
                                "import or reference the affected package, so there is no affected call path to draw."
                            )
                else:
                    if not os.getenv("ATHENA_AUTH_TOKEN"):
                        raise RuntimeError("ATHENA_AUTH_TOKEN is not configured.")

                    with st.spinner("Reading relevant repository files..."):
                        context, file_count = build_repository_context(
                            Path(st.session_state.active_repository), question
                        )
                    if not context:
                        raise ValueError("No supported source or documentation files were found.")

                    recent_messages = st.session_state.messages[-12:]
                    conversation = "\n\n".join(
                        f"{message['role'].capitalize()}: {message['content']}"
                        for message in recent_messages
                    )
                    prompt = f"""You are a conversational coding and security assistant.
Answer the user's questions using the local repository excerpts and conversation below.
Be specific, cite file paths when useful, and say when the excerpts do not provide enough evidence.
Do not claim to have inspected files that are not included in the excerpts.

Relevant local repository excerpts:
{context}

Conversation:
{conversation}

Assistant:"""
                    with st.spinner("Asking Athena..."):
                        answer = prompt_athena(prompt)
                st.markdown(answer)
                if graphs:
                    for graph in graphs:
                        with st.expander(
                            f"{graph['package']} call graph · {graph['affected_count']} affected functions",
                            expanded=False,
                        ):
                            st.caption(graph["caption"])
                            st.graphviz_chart(graph["dot"], use_container_width=True)
                elif not is_call_graph_request(question):
                    st.caption(f"Context included {file_count} local file(s).")
                st.session_state.messages.append(
                    {"role": "assistant", "content": answer, "graphs": graphs}
                )
            except Exception as error:
                st.error(str(error))
else:
    st.info("Enter a local repository folder in the sidebar to start a conversation.")