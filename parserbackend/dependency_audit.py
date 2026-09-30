import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import requests
from cvss import CVSS2, CVSS3, CVSS4


SKIPPED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "venv",
}
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns/{}"


def find_requirement_files(repository: Path) -> list[Path]:
    requirement_files = []
    repository = repository.resolve()

    for root, directories, filenames in os.walk(repository, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.lower() not in SKIPPED_DIRECTORIES
        )
        for filename in filenames:
            lowered_name = filename.lower()
            if not (
                lowered_name == "requirements.txt"
                or lowered_name.startswith("requirements-") and lowered_name.endswith(".txt")
            ):
                continue
            path = Path(root) / filename
            if path.is_symlink():
                continue
            requirement_files.append(path)

    return sorted(requirement_files, key=lambda path: path.as_posix().lower())


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _severity_details(advisory: dict) -> tuple[str, float | None]:
    database_severity = advisory.get("database_specific", {}).get("severity")
    if isinstance(database_severity, str):
        normalized = database_severity.upper()
        if normalized in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
            if normalized == "MODERATE":
                normalized = "MEDIUM"
            return normalized, None

    scores = []
    vector_types = {
        "CVSS_V2": CVSS2,
        "CVSS_V3": CVSS3,
        "CVSS_V4": CVSS4,
    }
    for severity in advisory.get("severity", []):
        vector = severity.get("score", "")
        vector_type = severity.get("type", "")
        vector_parser = vector_types.get(vector_type)
        if vector_parser is None:
            if vector.startswith("CVSS:4"):
                vector_parser = CVSS4
            elif vector.startswith("CVSS:3"):
                vector_parser = CVSS3
            elif vector.startswith("CVSS:2"):
                vector_parser = CVSS2
        if vector_parser is None:
            continue
        try:
            scores.append(float(vector_parser(vector).scores()[0]))
        except (TypeError, ValueError):
            continue

    if scores:
        highest_score = max(scores)
        return _severity_from_score(highest_score), highest_score
    return "UNKNOWN", None


def _fetch_osv_advisory(vulnerability_id: str) -> dict:
    response = requests.get(
        OSV_VULNERABILITY_URL.format(quote(vulnerability_id, safe="")),
        timeout=15,
    )
    if response.status_code == 404:
        return {}
    response.raise_for_status()
    advisory = response.json()
    return advisory if isinstance(advisory, dict) else {}


def _audit_error_detail(stderr: str) -> str:
    lines = [
        line.strip()
        for line in stderr.splitlines()
        if line.strip()
        and not line.lstrip().startswith(("Traceback", "File \"", "During handling of"))
        and not line.lstrip().startswith(("^", "~"))
    ]
    if not lines:
        return ""

    relevant = next(
        (
            line
            for line in reversed(lines)
            if any(
                marker in line.lower()
                for marker in (
                    "error:",
                    "no matching distribution",
                    "could not find a version",
                    "invalid requirement",
                    "resolutionimpossible",
                    "certificate verify failed",
                    "certificate_verify_failed",
                    "timed out",
                    "401 client error",
                    "403 client error",
                )
            )
        ),
        lines[-1],
    )
    relevant = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1<redacted>@", relevant)
    relevant = re.sub(
        r"(?i)\b(token|password|secret)(\s*[=:]\s*)\S+",
        r"\1\2<redacted>",
        relevant,
    )
    relevant = re.sub(r"(?i)([?&](?:token|password|secret)=)[^&\s]+", r"\1<redacted>", relevant)
    return relevant[:300]


def _scan_requirements_file(requirement_file: Path, repository: Path) -> dict:
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--requirement",
        str(requirement_file),
        "--format",
        "json",
        "--vulnerability-service",
        "osv",
        "--strict",
        "--progress-spinner",
        "off",
        "--timeout",
        "30",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"Audit timed out for {requirement_file.relative_to(repository)}.") from error

    if result.returncode not in (0, 1) or not result.stdout.strip():
        if "CERTIFICATE_VERIFY_FAILED" in result.stderr or "certificate verify failed" in result.stderr.lower():
            reason = (
                "TLS certificate verification failed while contacting OSV or the package index. "
                "Configure this Python environment to trust your organization's CA certificate, then retry."
            )
        else:
            reason = "pip-audit failed before producing a report. Check the manifest, dependency resolution, and service access."
        detail = _audit_error_detail(result.stderr)
        if detail:
            reason = f"{reason} pip-audit: {detail}"
        raise RuntimeError(
            f"pip-audit could not scan {requirement_file.relative_to(repository)} "
            f"(exit code {result.returncode}). {reason}"
        )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"pip-audit returned invalid JSON for {requirement_file.relative_to(repository)}."
        ) from error
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise RuntimeError(
            f"pip-audit returned an unexpected report for {requirement_file.relative_to(repository)}."
        )
    return report


def scan_python_dependencies(repository: Path) -> dict:
    repository = repository.resolve()
    requirement_files = find_requirement_files(repository)
    if not requirement_files:
        return {
            "manifests": [],
            "dependency_count": 0,
            "findings": [],
            "message": "No requirements*.txt files were found.",
        }

    dependencies_by_identity = {}
    for requirement_file in requirement_files:
        report = _scan_requirements_file(requirement_file, repository)
        relative_manifest = requirement_file.relative_to(repository).as_posix()
        for dependency in report["dependencies"]:
            identity = (dependency.get("name", ""), dependency.get("version", ""))
            if identity not in dependencies_by_identity:
                dependencies_by_identity[identity] = {
                    "name": identity[0],
                    "version": identity[1],
                    "manifests": [],
                    "vulns": {},
                }
            entry = dependencies_by_identity[identity]
            if relative_manifest not in entry["manifests"]:
                entry["manifests"].append(relative_manifest)
            for vulnerability in dependency.get("vulns", []):
                entry["vulns"][vulnerability.get("id", "UNKNOWN")] = vulnerability

    details_by_id = {}
    findings = []
    for dependency in dependencies_by_identity.values():
        for vulnerability_id, vulnerability in dependency["vulns"].items():
            if vulnerability_id not in details_by_id:
                try:
                    details_by_id[vulnerability_id] = _fetch_osv_advisory(vulnerability_id)
                except requests.RequestException:
                    details_by_id[vulnerability_id] = {}
            advisory = details_by_id[vulnerability_id]
            severity, cvss_score = _severity_details(advisory)
            aliases = vulnerability.get("aliases", [])
            cve_ids = sorted(
                {
                    alias
                    for alias in aliases
                    if isinstance(alias, str) and alias.startswith("CVE-")
                }
            )
            if vulnerability_id.startswith("CVE-"):
                cve_ids.append(vulnerability_id)
            findings.append(
                {
                    "package": dependency["name"],
                    "version": dependency["version"],
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "advisory_id": vulnerability_id,
                    "cve_ids": ", ".join(sorted(set(cve_ids))) or "Not assigned",
                    "fixed_versions": ", ".join(vulnerability.get("fix_versions", [])) or "No fix listed",
                    "summary": vulnerability.get("description") or advisory.get("summary", ""),
                    "manifest": ", ".join(dependency["manifests"]),
                }
            )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(
        key=lambda finding: (
            severity_order.get(finding["severity"], 5),
            finding["package"].lower(),
            finding["advisory_id"],
        )
    )
    return {
        "manifests": [path.relative_to(repository).as_posix() for path in requirement_files],
        "dependency_count": len(dependencies_by_identity),
        "findings": findings,
        "message": "",
    }