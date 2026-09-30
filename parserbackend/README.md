# Local Repository Chat

Ask conversational questions about a local codebase using the Unisys Athena API.

## How It Works
1. Select a local repository folder in the Streamlit sidebar.
2. Select **Scan Python dependencies for CVEs** to audit `requirements*.txt` files and resolved transitive dependencies against OSV.
3. Ask a question about the repository.
4. Relevant supported source and documentation files are selected locally and sent to Athena with recent conversation history.
5. Ask for a call graph, for example: `Generate a call graph for CVE-2026-12345`.

The context selector skips `.env` files, common credential files, generated output, and dependency directories. Review your organization's data-handling requirements before sending repository content to Athena.
The dependency scan contacts OSV and the package index to resolve dependencies. It reports CVSS-based severity when the advisory provides a supported CVSS vector; otherwise, severity is shown as unknown.
Call graphs are generated locally from Python ASTs for packages matched to the CVE findings. Highlighted package-using functions and nearby call edges indicate static relationships, not runtime reachability or exploitability.

### Deterministic Python Reachability Analyzer

Run the standalone AST analyzer by naming the vulnerable function explicitly:

```bash
python static_analyzer.py path/to/project --vulnerable-function ExampleLibrary.parse_request
```

Run its controlled upload-path demo tests with:

```bash
python -m unittest discover -s tests -v
```

The first version recognizes Flask/FastAPI-style HTTP route decorators, extracts Python functions and calls, resolves same-project functions and common imported aliases, and uses breadth-first search from each route handler to find the shortest reachable path. It does not import or execute project code and does not use an LLM to determine calls or reachability.

The proposed JSON contract is:

```json
{
   "project": "DemoApplication",
   "functions": [{"id": "controller.UploadController.handle_upload", "name": "handle_upload", "file": "controller.py", "line": 4}],
   "calls": [{"caller": "controller.UploadController.handle_upload", "callee": "service.FileService.process", "file": "controller.py", "line": 5, "resolved": true, "vulnerable_target": false}],
   "entry_points": [{"function": "app.upload", "trigger": "POST /api/upload", "file": "app.py", "line": 6}],
   "vulnerable_function": {"query": "ExampleLibrary.parse_request", "matches": []},
   "reachability": {"reachable": true, "entry_point": "POST /api/upload", "call_path": ["app.upload", "controller.UploadController.handle_upload"]},
   "parse_errors": []
}
```

This schema is a proposed MVP contract and should be confirmed with the team lead before being frozen. Reachability is based on resolved static call edges and returns the shortest path found. Dynamic dispatch, reflection, callbacks, framework-generated routes, conditional runtime behavior, and complex aliasing are not modeled; unresolved external calls are retained but cannot establish reachability unless they match the requested vulnerable function.

### 🏗️ Architecture

<kbd>![Alt text](images/arch_diagram.png?raw=true "architecture_diagram")</kbd>

### Prerequisites
- Python 3.11 or newer
- Athena API access and a bearer token

### 🛠️ Installation & Setup
1. Clone the repository
2. Create a `.env` file in the project root:

   ```
   ATHENA_AUTH_TOKEN=your_athena_bearer_token
   ```
3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```  

### 🚀 Usage

Start the web interface:
   ```bash
   streamlit run app.py
   ```

The legacy CLI still requires `GITHUB_TOKEN` in `.env` and accepts a GitHub Advisory ID plus a codebase path:
   ```bash
   python3 cve_analyzer.py <GHSA ID> <path_to_codebase>
   ``` 
### 🎥 Demo

The demo showcases vulnerabilities (GHSA ID) from SBOM / Github Dependabot alerts are analyzed by the tool and the impact is studied. The code repo used in the demo for analysis and SBOM generation is [Dolos AI CTF Challenge](https://github.com/alexdevassy/Machine_Learning_CTF_Challenges/tree/master/Dolos_ML_CTF_Challenge).

<kbd>![Alt text](images/cve_analyzer.gif?raw=true "demo")</kbd>

### Limitations
- Repository context is limited to supported source and documentation extensions and a bounded number of files.
- Files not selected as relevant may not be available to the assistant.
- Dependency scanning currently supports `requirements*.txt` manifests.
- Call graph generation currently analyzes Python functions and statically resolvable calls.
- The standalone reachability analyzer is Python-only and currently identifies HTTP route decorators as entry points.

### 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
