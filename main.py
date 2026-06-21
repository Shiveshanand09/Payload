import time
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
import httpx
import jsonschema
from lxml import etree

from diagnostics import (
    PayloadAnalyzer,
    scan_security_issues,
    generate_json_schema,
    xml_to_dict_tree,
    parse_and_format_json,
    parse_and_format_xml,
    diff_payloads
)

app = FastAPI(
    title="API Payload Diagnostics Service",
    description="Backend microservice for analyzing, linting, securing, and validating JSON/XML REST payloads.",
    version="1.0.0"
)

# CORS middleware for testing from other environments/ports
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# API Models
# ==========================================

class PayloadRequest(BaseModel):
    payload: str = Field(..., description="The raw JSON or XML string payload")
    format_type: str = Field("json", description="Either 'json' or 'xml'")


class SchemaValidationRequest(BaseModel):
    payload: str = Field(..., description="The raw JSON or XML string payload to validate")
    schema_definition: str = Field(..., description="The JSON Schema string or XML Schema string to validate against")
    format_type: str = Field("json", description="Either 'json' or 'xml'")


class ClientRequestModel(BaseModel):
    method: str = Field("GET", description="HTTP Method: GET, POST, PUT, DELETE, PATCH")
    url: str = Field(..., description="Target REST URL")
    headers: Optional[Dict[str, str]] = Field(None, description="Optional request headers")
    body: Optional[str] = Field(None, description="Optional request body")


class DiffRequest(BaseModel):
    payload_a: str = Field(..., description="Baseline JSON/XML payload")
    payload_b: str = Field(..., description="Comparison JSON/XML payload")
    format_type: str = Field("json", description="Either 'json' or 'xml'")


# ==========================================
# REST API Endpoints
# ==========================================

@app.post("/api/validate")
def api_validate(req: PayloadRequest):
    """Validate, format, and lint payload."""
    if req.format_type.lower() == "xml":
        res = parse_and_format_xml(req.payload)
        if res["success"]:
            return {"success": True, "formatted": res["formatted"], "data": xml_to_dict_tree(res["data"])}
        else:
            return {"success": False, "error": res["error"]}
    else:
        res = parse_and_format_json(req.payload)
        if res["success"]:
            return {"success": True, "formatted": res["formatted"], "data": res["data"]}
        else:
            return {"success": False, "error": res["error"]}


@app.post("/api/analyze")
def api_analyze(req: PayloadRequest):
    """Deep structural analysis, statistics, style checks, and naming compliance."""
    is_xml = req.format_type.lower() == "xml"
    analyzer = PayloadAnalyzer(req.payload, is_xml=is_xml)
    return analyzer.get_diagnostics_report()


@app.post("/api/scan")
def api_scan(req: PayloadRequest):
    """Scan payload for sensitive credentials, PII exposure, and injection hazards."""
    is_xml = req.format_type.lower() == "xml"
    return scan_security_issues(req.payload, is_xml=is_xml)


@app.post("/api/schema/generate")
def api_schema_generate(req: PayloadRequest):
    """Infer schemas from provided payloads."""
    is_xml = req.format_type.lower() == "xml"
    if is_xml:
        res = parse_and_format_xml(req.payload)
        if not res["success"]:
            return {"success": False, "error": res["error"]}
        tree_dict = xml_to_dict_tree(res["data"])
        return {"success": True, "schema": tree_dict, "type": "xml-tree"}
    else:
        res = parse_and_format_json(req.payload)
        if not res["success"]:
            return {"success": False, "error": res["error"]}
        inferred_schema = generate_json_schema(res["data"])
        return {"success": True, "schema": inferred_schema, "type": "json-schema"}


@app.post("/api/schema/validate")
def api_schema_validate(req: SchemaValidationRequest):
    """Validate payload structure against user-specified Schema."""
    is_xml = req.format_type.lower() == "xml"
    
    if is_xml:
        # Validate XML against XSD
        try:
            xml_res = parse_and_format_xml(req.payload)
            if not xml_res["success"]:
                return {"success": False, "errors": [xml_res["error"]]}
                
            xsd_schema = xmlschema.XMLSchema(req.schema_definition)
            xsd_schema.validate(xml_res["formatted"])
            return {"success": True, "message": "XML Payload successfully validated against XSD."}
        except xmlschema.XMLSchemaValidationError as ex:
            return {
                "success": False,
                "errors": [{
                    "message": ex.message,
                    "line": getattr(ex, 'sourceline', 1),
                    "column": 1,
                    "context": str(ex.reason) if hasattr(ex, 'reason') else ""
                }]
            }
        except Exception as ex:
            return {"success": False, "errors": [{"message": f"Schema parsing/validation error: {str(ex)}", "line": 1, "column": 1}]}
    else:
        # Validate JSON against JSON Schema
        try:
            json_res = parse_and_format_json(req.payload)
            if not json_res["success"]:
                return {"success": False, "errors": [json_res["error"]]}
                
            schema_res = parse_and_format_json(req.schema_definition)
            if not schema_res["success"]:
                return {"success": False, "errors": [{"message": f"Invalid JSON Schema syntax: {schema_res['error']['message']}", "line": schema_res['error']['line'], "column": schema_res['error']['column']}]}
                
            jsonschema.validate(instance=json_res["data"], schema=schema_res["data"])
            return {"success": True, "message": "JSON Payload successfully validated against Schema."}
        except jsonschema.exceptions.ValidationError as ex:
            # Construct a details model
            path = " -> ".join([str(p) for p in ex.path]) if ex.path else "root"
            return {
                "success": False,
                "errors": [{
                    "message": f"Validation failed at '{path}': {ex.message}",
                    "line": 1,
                    "column": 1,
                    "context": f"Expected type: {ex.validator_value}, found: {type(ex.instance).__name__}"
                }]
            }
        except Exception as ex:
            return {"success": False, "errors": [{"message": f"Validation runtime error: {str(ex)}", "line": 1, "column": 1}]}


@app.post("/api/client/request")
async def api_client_request(req: ClientRequestModel):
    """Proxy requests to bypass browser CORS policies and analyze payloads in one trip."""
    start_time = time.perf_counter()
    headers_dict = req.headers or {}
    
    # Ensure User-Agent is present
    if "User-Agent" not in {k.lower(): v for k, v in headers_dict.items()}:
        headers_dict["User-Agent"] = "APIPayloadDiagnosticsTool/2026"
        
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            request_kwargs = {
                "method": req.method.upper(),
                "url": req.url,
                "headers": headers_dict
            }
            if req.body and req.method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
                request_kwargs["content"] = req.body.encode('utf-8')
                
            response = await client.request(**request_kwargs)
            
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
        
        # Build info
        resp_body = response.text
        size_bytes = len(response.content)
        content_type = response.headers.get("content-type", "application/octet-stream")
        
        return {
            "success": True,
            "status_code": response.status_code,
            "latency_ms": elapsed_ms,
            "size_bytes": size_bytes,
            "content_type": content_type,
            "headers": dict(response.headers),
            "body": resp_body
        }
    except httpx.RequestError as ex:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
        return {
            "success": False,
            "error": f"HTTP Request failed: {str(ex)}",
            "latency_ms": elapsed_ms
        }


@app.post("/api/diff")
def api_diff(req: DiffRequest):
    """Compute exact structures difference report."""
    is_xml = req.format_type.lower() == "xml"
    return diff_payloads(req.payload_a, req.payload_b, is_xml=is_xml)


# ==========================================
# Static Files & Frontend Routing
# ==========================================

# Mount static folder (which we'll create next)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    """Serve the single-page application dashboard dashboard."""
    return FileResponse("static/index.html")

# Run via command line if needed
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
