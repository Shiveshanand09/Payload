import json
import re
from typing import Any, Dict, List, Tuple, Union
from lxml import etree
import xmlschema

# Regex Patterns for Sensitive Data & Injections
RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
RE_CREDIT_CARD = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
RE_SSN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
RE_AWS_KEY = re.compile(r'\b(AKIA|ASCA|ACCA|ASIA)[A-Z0-9]{16}\b')
RE_JWT = re.compile(r'\beyJhbGciOi[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b')
RE_IP = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
RE_PRIVATE_KEY = re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----')

# Common security threats
RE_SQL_INJECTION = re.compile(
    r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b.*?\b(FROM|INTO|TABLE|WHERE|JOIN)?\b|"
    r"'\s*OR\s*'\d+'\s*=\s*'\d+'|\bOR\s+\d+\s*=\s*\d+\b"
)
RE_XSS = re.compile(r"(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|onerror\s*=\s*['\"].*?['\"]|javascript\s*:\s*alert")

# Sensitive keys patterns
SENSITIVE_KEY_KEYWORDS = ["password", "secret", "passwd", "apikey", "credential", "auth", "token", "privatekey", "client_secret"]

# Naming style checks
RE_CAMEL = re.compile(r'^[a-z]+[a-zA-Z0-9]*$')
RE_SNAKE = re.compile(r'^[a-z0-9]+(_[a-z0-9]+)*$')
RE_PASCAL = re.compile(r'^[A-Z][a-zA-Z0-9]*$')
RE_KEBAB = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')

# Javascript float safety limit
JS_MAX_SAFE_INTEGER = 9007199254740991


def check_luhn(card_number: str) -> bool:
    """Validate card number using Luhn algorithm."""
    digits = [int(d) for d in re.sub(r'\D', '', card_number)]
    if not digits or len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            double = digit * 2
            checksum += double if double < 10 else double - 9
        else:
            checksum += digit
    return checksum % 10 == 0


# ==========================================
# Parsing & Formatting
# ==========================================

def parse_and_format_json(raw_str: str) -> Dict[str, Any]:
    """Parse JSON and return formatted string and raw dict or raise exception with metadata."""
    try:
        parsed = json.loads(raw_str)
        formatted = json.dumps(parsed, indent=2)
        return {"success": True, "data": parsed, "formatted": formatted}
    except json.JSONDecodeError as ex:
        # Extract location details
        line = ex.lineno
        col = ex.colno
        msg = ex.msg
        lines = raw_str.splitlines()
        context = ""
        if 0 <= line - 1 < len(lines):
            context = lines[line - 1]
        return {
            "success": False,
            "error": {
                "message": msg,
                "line": line,
                "column": col,
                "context": context
            }
        }


def parse_and_format_xml(raw_str: str) -> Dict[str, Any]:
    """Parse XML and return formatted string and raw lxml Element or raise exception with metadata."""
    try:
        parser = etree.XMLParser(resolve_entities=False, remove_blank_text=True)
        root = etree.fromstring(raw_str.encode('utf-8'), parser=parser)
        formatted = etree.tostring(root, pretty_print=True, encoding='utf-8').decode('utf-8')
        return {"success": True, "data": root, "formatted": formatted}
    except etree.XMLSyntaxError as ex:
        lines = raw_str.splitlines()
        line = ex.position[0]
        col = ex.position[1]
        context = ""
        if 0 <= line - 1 < len(lines):
            context = lines[line - 1]
        return {
            "success": False,
            "error": {
                "message": ex.msg,
                "line": line,
                "column": col,
                "context": context
            }
        }
    except Exception as ex:
        return {
            "success": False,
            "error": {
                "message": str(ex),
                "line": 1,
                "column": 1,
                "context": ""
            }
        }


# ==========================================
# Schema Generation
# ==========================================

def generate_json_schema(data: Any) -> Dict[str, Any]:
    """Recursively infer draft-07 JSON Schema from Python objects."""
    if data is None:
        return {"type": "null"}
    elif isinstance(data, bool):
        return {"type": "boolean"}
    elif isinstance(data, int):
        return {"type": "integer"}
    elif isinstance(data, float):
        return {"type": "number"}
    elif isinstance(data, str):
        # Infer formats if possible
        schema = {"type": "string"}
        if RE_EMAIL.match(data):
            schema["format"] = "email"
        elif RE_IP.match(data):
            schema["format"] = "ipv4"
        elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$', data):
            schema["format"] = "date-time"
        elif re.match(r'^\d{4}-\d{2}-\d{2}$', data):
            schema["format"] = "date"
        return schema
    elif isinstance(data, list):
        if not data:
            return {"type": "array", "items": {}}
        # Merge schemas of all items to construct a single broad items representation
        item_schemas = [generate_json_schema(item) for item in data]
        # De-duplicate schemas
        unique_schemas = []
        for s in item_schemas:
            if s not in unique_schemas:
                unique_schemas.append(s)
        
        if len(unique_schemas) == 1:
            items_schema = unique_schemas[0]
        else:
            items_schema = {"anyOf": unique_schemas}
        return {"type": "array", "items": items_schema}
    elif isinstance(data, dict):
        properties = {}
        required = []
        for k, v in data.items():
            properties[k] = generate_json_schema(v)
            required.append(k)
        schema = {
            "type": "object",
            "properties": properties
        }
        if required:
            schema["required"] = required
        return schema
    return {}


def xml_to_dict_tree(element: etree._Element) -> Dict[str, Any]:
    """Helper to convert xml elements recursively into a structured JSON-like tree for analysis."""
    node = {
        "tag": element.tag,
        "attributes": dict(element.attrib),
        "children": []
    }
    
    # Handle text content
    text = element.text.strip() if element.text else ""
    if text:
        node["text"] = text
        # Try to infer type of text
        if text.lower() == 'true':
            node["inferred_type"] = "boolean"
        elif text.lower() == 'false':
            node["inferred_type"] = "boolean"
        else:
            try:
                int(text)
                node["inferred_type"] = "integer"
            except ValueError:
                try:
                    float(text)
                    node["inferred_type"] = "number"
                except ValueError:
                    node["inferred_type"] = "string"
    else:
        node["inferred_type"] = "object" if len(element) > 0 else "empty"

    for child in element:
        node["children"].append(xml_to_dict_tree(child))
        
    return node


# ==========================================
# Diagnostics & Hygiene Engine
# ==========================================

class PayloadAnalyzer:
    def __init__(self, raw_str: str, is_xml: bool = False):
        self.raw_str = raw_str
        self.is_xml = is_xml
        self.parsed_data = None
        self.success = False
        self.parse_error = None
        
        # Diagnostics metrics
        self.naming_styles = {"camel": 0, "snake": 0, "pascal": 0, "kebab": 0, "other": 0}
        self.max_depth = 0
        self.total_keys = 0
        self.empty_structures = 0
        self.null_values = 0
        self.unsafe_floats = []
        self.date_formats = {"iso8601": 0, "other_date": 0}
        
        # Run parsing
        if is_xml:
            res = parse_and_format_xml(raw_str)
        else:
            res = parse_and_format_json(raw_str)
            
        if res["success"]:
            self.success = True
            self.parsed_data = res["data"]
            self.formatted_str = res["formatted"]
            self._analyze()
        else:
            self.parse_error = res["error"]

    def _analyze(self):
        """Kick off recursive tree audits based on document type."""
        if self.is_xml:
            # Convert XML to a structure we can traverse
            tree = xml_to_dict_tree(self.parsed_data)
            self._traverse_xml_dict(tree, 1)
        else:
            self._traverse_json(self.parsed_data, 1)

    def _classify_name(self, name: str):
        """Classify key/tag names into naming convention buckets."""
        if not name:
            return
        self.total_keys += 1
        if RE_CAMEL.match(name):
            self.naming_styles["camel"] += 1
        elif RE_SNAKE.match(name):
            self.naming_styles["snake"] += 1
        elif RE_PASCAL.match(name):
            self.naming_styles["pascal"] += 1
        elif RE_KEBAB.match(name):
            self.naming_styles["kebab"] += 1
        else:
            self.naming_styles["other"] += 1

    def _traverse_json(self, node: Any, current_depth: int):
        self.max_depth = max(self.max_depth, current_depth)
        
        if node is None:
            self.null_values += 1
            return
            
        if isinstance(node, dict):
            if not node:
                self.empty_structures += 1
                return
            for k, v in node.items():
                self._classify_name(k)
                self._traverse_json(v, current_depth + 1)
                
        elif isinstance(node, list):
            if not node:
                self.empty_structures += 1
                return
            for item in node:
                self._traverse_json(item, current_depth + 1)
                
        elif isinstance(node, (int, float)):
            if isinstance(node, int) and abs(node) > JS_MAX_SAFE_INTEGER:
                self.unsafe_floats.append(node)
                
        elif isinstance(node, str):
            if node == "":
                self.empty_structures += 1
            elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$', node):
                self.date_formats["iso8601"] += 1
            elif re.match(r'^\d{4}-\d{2}-\d{2}$', node):
                self.date_formats["other_date"] += 1

    def _traverse_xml_dict(self, node: Dict[str, Any], current_depth: int):
        self.max_depth = max(self.max_depth, current_depth)
        
        # Tag name styling check
        self._classify_name(node["tag"])
        
        # Attributes styling check
        for attr in node["attributes"].keys():
            self._classify_name(attr)
            
        # Analyze inferred text type
        text = node.get("text", "")
        inf_type = node.get("inferred_type")
        
        if inf_type == "empty":
            self.empty_structures += 1
        elif inf_type == "integer":
            val = int(text)
            if abs(val) > JS_MAX_SAFE_INTEGER:
                self.unsafe_floats.append(val)
        elif inf_type == "number":
            pass
        elif inf_type == "string":
            if text == "":
                self.empty_structures += 1
            elif re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$', text):
                self.date_formats["iso8601"] += 1
            elif re.match(r'^\d{4}-\d{2}-\d{2}$', text):
                self.date_formats["other_date"] += 1
                
        for child in node["children"]:
            self._traverse_xml_dict(child, current_depth + 1)

    def get_diagnostics_report(self) -> Dict[str, Any]:
        """Compile general dashboard metrics, warnings, and formatting recommendations."""
        if not self.success:
            return {"success": False, "error": self.parse_error}
            
        # Determine naming style consistency
        predominant_style = "mixed"
        style_pct = 0.0
        if self.total_keys > 0:
            for style, count in self.naming_styles.items():
                pct = (count / self.total_keys) * 100
                if pct > 70:
                    predominant_style = style
                    style_pct = pct
                    break
                    
        # Construct recommendations
        warnings = []
        if self.max_depth > 5:
            warnings.append({
                "category": "Structure",
                "severity": "medium",
                "message": f"Deeply nested structure (depth: {self.max_depth}). High nesting makes parsing more CPU-intensive and APIs harder to consume. Consider flattening."
            })
            
        if self.total_keys > 0 and predominant_style == "mixed":
            warnings.append({
                "category": "Convention",
                "severity": "low",
                "message": "Inconsistent naming styles detected. Keys mix camelCase, snake_case, or PascalCase. Adopt a uniform convention."
            })
            
        if self.unsafe_floats:
            warnings.append({
                "category": "Data Type",
                "severity": "medium",
                "message": f"Detected numbers exceeding Javascript safe integer limits (9,007,199,254,740,991). Loss of precision may occur in standard JS frontends: {self.unsafe_floats[:3]}..."
            })
            
        if self.null_values > (self.total_keys * 0.3) and self.total_keys > 5:
            warnings.append({
                "category": "Performance",
                "severity": "low",
                "message": f"High density of null values ({self.null_values} out of {self.total_keys} fields). Consider omitting keys with null values to save payload bandwidth."
            })

        return {
            "success": True,
            "metrics": {
                "max_depth": self.max_depth,
                "total_keys": self.total_keys,
                "empty_structures": self.empty_structures,
                "null_values": self.null_values,
                "unsafe_floats_count": len(self.unsafe_floats),
                "dates": self.date_formats,
                "naming_distribution": self.naming_styles,
                "dominant_naming_style": predominant_style,
                "naming_consistency_percent": round(style_pct, 1)
            },
            "warnings": warnings,
            "formatted": self.formatted_str
        }


# ==========================================
# Security Audit Scanner
# ==========================================

def scan_security_issues(raw_str: str, is_xml: bool = False) -> Dict[str, Any]:
    """Scan raw payload string for security flaws (PII leaks, SQLi/XSS inputs, XXE threats)."""
    findings = []
    
    # 1. XML Specific Audits (XXE & Entity DoS checks)
    if is_xml:
        # Check for DOCTYPE
        if "<!DOCTYPE" in raw_str.upper():
            findings.append({
                "rule": "XML External Entity (XXE) Vulnerability",
                "severity": "high",
                "evidence": "<!DOCTYPE ...>",
                "description": "The XML payload includes a DOCTYPE definition. If the XML parser has external entities enabled, this makes the server vulnerable to file exposure, SSRF, and local port scanning."
            })
        if "<!ENTITY" in raw_str.upper():
            findings.append({
                "rule": "XML Entity Expansion / Denial of Service",
                "severity": "high",
                "evidence": "<!ENTITY ...>",
                "description": "Entity definition detected. Resolving nested entities can lead to recursive expansion (Billion Laughs attack), causing host memory exhaustion and server freeze."
            })

    # 2. PII & Secret Scans
    # Email addresses
    emails = RE_EMAIL.findall(raw_str)
    if emails:
        findings.append({
            "rule": "PII Exposure (Email Addresses)",
            "severity": "low",
            "evidence": f"Found {len(emails)} email(s) (e.g. {emails[0]})",
            "description": "Sensitive user emails found in the payload. Ensure these are encrypted in transit and necessary for API processing."
        })
        
    # Credit Card scan with Luhn check
    cc_matches = RE_CREDIT_CARD.findall(raw_str)
    valid_ccs = [cc for cc in cc_matches if check_luhn(cc)]
    if valid_ccs:
        findings.append({
            "rule": "PCI-DSS Risk (Credit Cards)",
            "severity": "high",
            "evidence": f"Found {len(valid_ccs)} Luhn-valid card number(s) (e.g. {valid_ccs[0][:4]}xxxx-xxxx)",
            "description": "Raw, unmasked credit card numbers detected. Storing or handling unmasked credit card data violates PCI-DSS standards. Tokenize credit card data."
        })
        
    # SSN Checks
    ssns = RE_SSN.findall(raw_str)
    if ssns:
        findings.append({
            "rule": "PII Exposure (Social Security Numbers)",
            "severity": "critical",
            "evidence": f"Found {len(ssns)} SSN(s)",
            "description": "Explicit US Social Security Numbers detected. Leaking SSNs raises high compliance/regulatory issues."
        })

    # AWS Keys
    aws_keys = RE_AWS_KEY.findall(raw_str)
    if aws_keys:
        findings.append({
            "rule": "Secret Leak (AWS API Key)",
            "severity": "critical",
            "evidence": f"Found key {aws_keys[0][1]}...",
            "description": "AWS Credentials detected in payload. Exposed AWS access keys can result in total cloud infrastructure hijack."
        })
        
    # Private Key
    priv_keys = RE_PRIVATE_KEY.findall(raw_str)
    if priv_keys:
        findings.append({
            "rule": "Secret Leak (Private Key)",
            "severity": "critical",
            "evidence": "-----BEGIN RSA PRIVATE KEY-----",
            "description": "Asymmetric private cryptographic keys detected. Private keys must never be transmitted over standard user-facing REST APIs."
        })
        
    # JWT Tokens
    jwts = RE_JWT.findall(raw_str)
    if jwts:
        findings.append({
            "rule": "Sensitive Token (JWT)",
            "severity": "medium",
            "evidence": f"Found token starting with {jwts[0][:15]}...",
            "description": "Bearer JWT token found in the payload body. Auth tokens belong in Authorization headers rather than the data payload."
        })
        
    # IP Addresses
    ips = RE_IP.findall(raw_str)
    # Filter localhost / private addresses from raising high warnings
    external_ips = [ip for ip in ips if not (ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."))]
    if external_ips:
        findings.append({
            "rule": "Infrastructure Leak (External IP)",
            "severity": "low",
            "evidence": f"Found {len(external_ips)} IP(s) (e.g. {external_ips[0]})",
            "description": "External host IP addresses detected. Exposing backend architecture IPs simplifies target scanning for attackers."
        })

    # 3. Payload Web Attack Injections (SQL Injection & XSS)
    sql_hits = RE_SQL_INJECTION.findall(raw_str)
    if sql_hits:
        findings.append({
            "rule": "Injection Vulnerability (SQL Injection Signatures)",
            "severity": "medium",
            "evidence": str(sql_hits[0]),
            "description": "String parameters contain phrases typical of SQL commands (e.g. SELECT, UNION, OR 1=1). If the backend executes raw queries directly with these parameters, it is vulnerable to SQL injection."
        })
        
    xss_hits = RE_XSS.findall(raw_str)
    if xss_hits:
        findings.append({
            "rule": "Injection Vulnerability (XSS Script Tags)",
            "severity": "medium",
            "evidence": str(xss_hits[0]),
            "description": "HTML script tags or script event triggers (like onerror) detected. Reflecting these strings directly in web views can lead to Cross-Site Scripting."
        })

    # 4. Sensitive keys check in structured JSON
    if not is_xml:
        try:
            parsed = json.loads(raw_str)
            sensitive_keys_found = []
            
            def check_keys(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(kw in k.lower() for kw in SENSITIVE_KEY_KEYWORDS) and v:
                            sensitive_keys_found.append((k, str(v)[:6] + "..."))
                        check_keys(v)
                elif isinstance(obj, list):
                    for item in obj:
                        check_keys(item)
                        
            check_keys(parsed)
            if sensitive_keys_found:
                findings.append({
                    "rule": "Sensitive Field Key Exposure",
                    "severity": "medium",
                    "evidence": f"Keys: {', '.join([item[0] for item in sensitive_keys_found])}",
                    "description": "Fields matching sensitive naming keywords (like 'password', 'apikey', 'secret') were found with active values. Ensure credentials are not sent in raw text."
                })
        except:
            pass
            
    return {
        "success": True,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "critical_count": len([f for f in findings if f["severity"] in ["high", "critical"]])
    }


# ==========================================
# Payload Difference Engine
# ==========================================

def get_keys_recursive(data: Any, path: str = "") -> Dict[str, Any]:
    """Flatten key pathways and capture data types."""
    flat_map = {}
    if isinstance(data, dict):
        for k, v in data.items():
            current_path = f"{path}.{k}" if path else k
            flat_map[current_path] = {"type": type(v).__name__, "value": v}
            flat_map.update(get_keys_recursive(v, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            current_path = f"{path}[{i}]"
            flat_map[current_path] = {"type": type(item).__name__, "value": item}
            flat_map.update(get_keys_recursive(item, current_path))
    return flat_map


def diff_payloads(payload_a: str, payload_b: str, is_xml: bool = False) -> Dict[str, Any]:
    """Perform structural analysis and comparison of two payloads."""
    # 1. Parse both payloads
    if is_xml:
        parse_a = parse_and_format_xml(payload_a)
        parse_b = parse_and_format_xml(payload_b)
        if not parse_a["success"] or not parse_b["success"]:
            return {
                "success": False,
                "error": "Failed to parse XML. Make sure both payloads are well-formed XML structures."
            }
        # Convert XML to dictionary representation for structural comparison
        dict_a = xml_to_dict_tree(parse_a["data"])
        dict_b = xml_to_dict_tree(parse_b["data"])
    else:
        parse_a = parse_and_format_json(payload_a)
        parse_b = parse_and_format_json(payload_b)
        if not parse_a["success"] or not parse_b["success"]:
            return {
                "success": False,
                "error": "Failed to parse JSON. Make sure both payloads are well-formed JSON structures."
            }
        dict_a = parse_a["data"]
        dict_b = parse_b["data"]

    # 2. Get flat maps of paths
    flat_a = get_keys_recursive(dict_a)
    flat_b = get_keys_recursive(dict_b)

    additions = {}
    deletions = {}
    modifications = {}
    type_drifts = {}

    # Find deletions and changes
    for path, meta_a in flat_a.items():
        if path not in flat_b:
            deletions[path] = {"type": meta_a["type"], "value": meta_a["value"]}
        else:
            meta_b = flat_b[path]
            # Check type drift
            if meta_a["type"] != meta_b["type"]:
                type_drifts[path] = {
                    "old_type": meta_a["type"],
                    "new_type": meta_b["type"],
                    "old_value": meta_a["value"],
                    "new_value": meta_b["value"]
                }
            # Check value modified (only check for leaf-level primitives, ignore nested dicts/lists to avoid duplicate diff reports)
            elif meta_a["type"] not in ["dict", "list", "Element", "XMLTree"]:
                if meta_a["value"] != meta_b["value"]:
                    modifications[path] = {
                        "type": meta_a["type"],
                        "old_value": meta_a["value"],
                        "new_value": meta_b["value"]
                    }

    # Find additions
    for path, meta_b in flat_b.items():
        if path not in flat_a:
            additions[path] = {"type": meta_b["type"], "value": meta_b["value"]}

    # Clean duplicates: if a parent dict/list is marked as added/deleted, we don't need all its children also shown.
    # We filter paths that start with an already reported parent path.
    def filter_nested(paths_dict):
        sorted_keys = sorted(paths_dict.keys(), key=len)
        filtered = {}
        for k in sorted_keys:
            # Check if any prefix of key k is in filtered keys
            parts = re.split(r'\.|\[', k)
            is_child = False
            for i in range(1, len(parts)):
                prefix_candidate = "".join([f"[{p}" if p.endswith(']') else f".{p}" for p in parts[:i]]).strip('.')
                # adjust index brackets
                prefix_candidate = re.sub(r'^\.', '', prefix_candidate)
                # Quick scan of existing keys
                if any(k.startswith(f + '.') or k.startswith(f + '[') for f in filtered.keys()):
                    is_child = True
                    break
            if not is_child:
                filtered[k] = paths_dict[k]
        return filtered

    return {
        "success": True,
        "summary": {
            "added_count": len(additions),
            "deleted_count": len(deletions),
            "modified_count": len(modifications),
            "drifted_count": len(type_drifts)
        },
        "diffs": {
            "added": filter_nested(additions),
            "deleted": filter_nested(deletions),
            "modified": modifications,
            "drifted": type_drifts
        }
    }
