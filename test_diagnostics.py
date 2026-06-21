import unittest
import json
from lxml import etree
import xmlschema

from diagnostics import (
    parse_and_format_json,
    parse_and_format_xml,
    generate_json_schema,
    scan_security_issues,
    diff_payloads,
    PayloadAnalyzer
)

class TestPayloadDiagnostics(unittest.TestCase):

    def test_json_parsing_success(self):
        raw_json = '{"name": "test", "active": true, "items": [1, 2, 3]}'
        res = parse_and_format_json(raw_json)
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["name"], "test")
        self.assertIn('"active": true', res["formatted"])

    def test_json_parsing_failure(self):
        raw_json = '{"name": "test", "active": true, }' # Trailing comma
        res = parse_and_format_json(raw_json)
        self.assertFalse(res["success"])
        self.assertIn("error", res)
        self.assertGreater(res["error"]["line"], 0)

    def test_xml_parsing_success(self):
        raw_xml = '<root><element id="1">Text Content</element></root>'
        res = parse_and_format_xml(raw_xml)
        self.assertTrue(res["success"])
        self.assertEqual(res["data"].tag, "root")
        self.assertIn('<element id="1">', res["formatted"])

    def test_xml_parsing_failure(self):
        raw_xml = '<root><element id="1">Text Content</root>' # Unclosed element
        res = parse_and_format_xml(raw_xml)
        self.assertFalse(res["success"])
        self.assertIn("error", res)

    def test_schema_generation_json(self):
        data = {
            "title": "Book",
            "pages": 240,
            "available": True,
            "tags": ["fiction", "scifi"],
            "author": {
                "name": "Jane Doe",
                "email": "jane@example.com"
            }
        }
        schema = generate_json_schema(data)
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["properties"]["pages"]["type"], "integer")
        self.assertEqual(schema["properties"]["available"]["type"], "boolean")
        self.assertEqual(schema["properties"]["tags"]["type"], "array")
        self.assertEqual(schema["properties"]["author"]["properties"]["email"]["format"], "email")

    def test_security_scan_pii_and_secrets(self):
        # Email, AWS key, SSN
        raw_payload = """
        {
          "email": "user@domain.com",
          "ssn": "123-45-6789",
          "token": "AKIA9876543210ABCDEF",
          "query": "SELECT * FROM data"
        }
        """
        res = scan_security_issues(raw_payload, is_xml=False)
        self.assertTrue(res["vulnerable"])
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("PII Exposure (Email Addresses)", rules)
        self.assertIn("PII Exposure (Social Security Numbers)", rules)
        self.assertIn("Secret Leak (AWS API Key)", rules)

    def test_security_scan_xml_xxe(self):
        raw_xml = """<?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE test [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>
        """
        res = scan_security_issues(raw_xml, is_xml=True)
        self.assertTrue(res["vulnerable"])
        rules = [f["rule"] for f in res["findings"]]
        self.assertIn("XML External Entity (XXE) Vulnerability", rules)

    def test_payload_difference_json(self):
        payload_a = '{"id": 1, "name": "A", "roles": ["user"]}'
        payload_b = '{"id": 1, "name": "B", "roles": ["user", "admin"], "status": "active"}'
        res = diff_payloads(payload_a, payload_b, is_xml=False)
        self.assertTrue(res["success"])
        self.assertEqual(res["summary"]["added_count"], 2) # status, roles[1]
        self.assertEqual(res["summary"]["modified_count"], 1) # name
        self.assertIn("status", res["diffs"]["added"])
        self.assertIn("name", res["diffs"]["modified"])

    def test_analyzer_conventions_and_depth(self):
        # Deeply nested object and mixed key styles
        raw_json = {
            "first_name": "Test",   # snake_case
            "lastName": "User",     # camelCase
            "Level2": {             # PascalCase
                "level3": {
                    "level4": {
                        "level5": {
                            "level6": {
                                "too_deep": True
                            }
                        }
                    }
                }
            }
        }
        analyzer = PayloadAnalyzer(json.dumps(raw_json), is_xml=False)
        report = analyzer.get_diagnostics_report()
        self.assertTrue(report["success"])
        self.assertEqual(report["metrics"]["max_depth"], 7)
        self.assertEqual(report["metrics"]["dominant_naming_style"], "mixed")
        
        # Check that warnings triggered
        warnings = [w["category"] for w in report["warnings"]]
        self.assertIn("Structure", warnings)
        self.assertIn("Convention", warnings)

if __name__ == "__main__":
    unittest.main()
