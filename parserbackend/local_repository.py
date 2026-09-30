import os
import re
from pathlib import Path


SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
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
SKIPPED_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "id_rsa",
    "secrets.json",
}
MAX_CANDIDATE_FILES = 300
MAX_SELECTED_FILES = 20
MAX_FILE_CHARS = 5000
MAX_CONTEXT_CHARS = 36000
MAX_FILE_BYTES = 128_000


def build_repository_context(repository: Path, question: str) -> tuple[str, int]:
    query_terms = {
        term.lower()
        for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", question)
        if term.lower() not in {"and", "are", "can", "for", "how", "the", "this", "what", "with"}
    }
    candidates = []

    for root, directories, filenames in os.walk(repository, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.lower() not in SKIPPED_DIRECTORIES
        )
        for filename in sorted(filenames):
            path = Path(root) / filename
            lowered_name = filename.lower()
            if (
                path.suffix.lower() not in SOURCE_SUFFIXES
                or lowered_name in SKIPPED_FILES
                or lowered_name.startswith(".env.")
            ):
                continue
            if lowered_name.endswith((".pem", ".p12", ".pfx", ".key")):
                continue

            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if "\0" in content:
                continue

            relative_path = path.relative_to(repository).as_posix()
            searchable_content = content.lower()
            searchable_path = relative_path.lower()
            score = sum(min(searchable_content.count(term), 8) for term in query_terms)
            score += sum(3 for term in query_terms if term in searchable_path)
            candidates.append((score, relative_path, content))
            if len(candidates) >= MAX_CANDIDATE_FILES:
                break
        if len(candidates) >= MAX_CANDIDATE_FILES:
            break

    candidates.sort(key=lambda candidate: (-candidate[0], candidate[1].lower()))
    excerpts = []
    used_chars = 0
    for _, relative_path, content in candidates[:MAX_SELECTED_FILES]:
        excerpt = content.strip()[:MAX_FILE_CHARS]
        block = f"FILE: {relative_path}\n{excerpt}"
        remaining = MAX_CONTEXT_CHARS - used_chars
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining]
        excerpts.append(block)
        used_chars += len(block)

    return "\n\n".join(excerpts), len(excerpts)