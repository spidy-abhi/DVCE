import json
import tempfile
import unittest
from pathlib import Path

from static_analyzer import analyze_project


DEMO_FILES = {
    "app.py": '''from flask import Flask
from controller import UploadController

app = Flask(__name__)

@app.post("/api/upload")
def upload():
    return UploadController().handle_upload()
''',
    "controller.py": '''from service import FileService

class UploadController:
    def handle_upload(self):
        return FileService().process()
''',
    "service.py": '''from parser_service import ParserService

class FileService:
    def process(self):
        return ParserService().parse()
''',
    "parser_service.py": '''from example_library import ExampleLibrary

class ParserService:
    def parse(self):
        return ExampleLibrary.parse_request()

def unused_vulnerable_function():
    return ExampleLibrary.parse_request()
''',
}


class StaticAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.project = Path(self.temporary_directory.name) / "DemoApplication"
        self.project.mkdir()
        for relative_path, content in DEMO_FILES.items():
            (self.project / relative_path).write_text(content, encoding="utf-8")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_finds_exact_reachable_upload_path(self):
        result = analyze_project(self.project, "ExampleLibrary.parse_request")

        self.assertEqual(result["project"], "DemoApplication")
        self.assertEqual(result["entry_points"][0]["trigger"], "POST /api/upload")
        self.assertTrue(result["reachability"]["reachable"])
        self.assertEqual(
            result["reachability"]["call_path"],
            [
                "app.upload",
                "controller.UploadController.handle_upload",
                "service.FileService.process",
                "parser_service.ParserService.parse",
                "example_library.ExampleLibrary.parse_request",
            ],
        )
        self.assertTrue(
            any(call["vulnerable_target"] for call in result["calls"])
        )

    def test_reports_unreachable_vulnerable_definition(self):
        result = analyze_project(self.project, "unused_vulnerable_function")

        self.assertTrue(result["vulnerable_function"]["matches"])
        self.assertFalse(result["reachability"]["reachable"])
        self.assertEqual(result["reachability"]["call_path"], [])

    def test_result_is_json_serializable(self):
        result = analyze_project(self.project, "ExampleLibrary.parse_request")

        serialized = json.dumps(result)
        self.assertIsInstance(json.loads(serialized), dict)
        self.assertIn("calls", result)
        self.assertIn("entry_points", result)
        self.assertIn("vulnerable_function", result)
        self.assertIn("reachability", result)

    def test_qualified_external_call_is_not_bound_to_same_named_local_function(self):
        parser_file = self.project / "parser_service.py"
        parser_file.write_text(
            parser_file.read_text(encoding="utf-8")
            + "\ndef parse_request():\n    return False\n",
            encoding="utf-8",
        )

        result = analyze_project(self.project, "ExampleLibrary.parse_request")
        call = next(
            call
            for call in result["calls"]
            if call["caller"] == "parser_service.ParserService.parse"
        )

        self.assertEqual(call["callee"], "example_library.ExampleLibrary.parse_request")
        self.assertFalse(call["resolved"])
        self.assertTrue(call["vulnerable_target"])


if __name__ == "__main__":
    unittest.main()