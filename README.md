# API Payload Diagnostics & Security Tool

A premium, interactive web-based dashboard and API proxy server designed to validate, format, secure, and compare REST API payloads (JSON & XML). It leverages a robust **Python (FastAPI)** backend and a gorgeous, glassmorphic **Vanilla CSS & JS** single-page frontend.

---

## 🚀 Key Features

* **Diagnostics Suite**: Deep structural analysis of API payloads, calculating statistics such as maximum nesting depth, field count, conventions, naming casing distribution (camelCase, snake_case, PascalCase, kebab-case), null distribution, and JS floating-point limits safety warnings.
* **Security Auditor**: Automatically scans payloads for security threats and exposures:
  * **PII Leaks**: Identifies SSNs, credit cards (Luhn validated), and email addresses.
  * **Secrets**: Detects AWS keys, JWT tokens, private cryptographic keys, and database credentials.
  * **Injections**: Detects SQL injection phrases and XSS script signatures.
  * **XML Specifics**: Checks for XML External Entity (XXE) DOCTYPE and Entity Expansion recursion threats.
* **REST Request Client**: Enables proxying HTTP requests (GET, POST, PUT, DELETE, PATCH) directly through the backend server, bypassing CORS limitations, measuring response latency in milliseconds, and exporting response data straight into the diagnostics engine.
* **Payload Comparator**: Compares baseline and comparison payloads side-by-side to highlight added keys, deleted paths, changed values, and schema type drift.
* **Schema Validation Hub**: Infers JSON Schema Draft-07 representations or XML tag structures, and validates loaded payloads against custom-defined schema configurations.
* **Formatter & Minifier**: Instant syntax beautification or structural minification for both XML and JSON formats.

---

## 🛠️ Technology Stack

* **Backend**: Python 3.12+, FastAPI, Uvicorn, Pydantic v2, `jsonschema`, `xmlschema`, `lxml`, `httpx`
* **Frontend**: HTML5, Vanilla CSS3 (Custom design system, glassmorphic cards, transition animations), Vanilla ES6 Javascript

---

## ⚙️ Quick Start Setup

### Prerequisites
Make sure you have **Python 3.12+** installed on your system.

### 1. Set Up Virtual Environment & Dependencies
Clone the repository and initialize the Python virtual environment:
```bash
# Navigate to project directory
cd api-payload-diagnostics

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install packages
pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Run the Server
Launch the FastAPI development server:
```bash
uvicorn main:app --reload
```
The server will bind and start running on: **`http://127.0.0.1:8000`**

### 3. Open the UI
Open your web browser and navigate to `http://127.0.0.1:8000` to access the interactive developer workspace.

---

## 🧪 Running Automated Tests
The suite contains unit tests covering parser validations, security scanners, schema inferences, and tree comparisons. To execute the tests, run:
```bash
venv/bin/python -m unittest test_diagnostics.py
```

---

## 📂 Project Structure
```text
api-payload-diagnostics/
├── main.py               # FastAPI server endpoints & routers
├── diagnostics.py        # Core processing logic (Scanners, diff, schemas)
├── test_diagnostics.py   # Unit test suite
├── requirements.txt      # Python dependencies list
├── .gitignore            # Git exclusion definitions
└── static/
    ├── index.html        # Main dashboard markup template
    ├── style.css         # Custom premium stylesheet
    └── app.js            # Frontend state controller & client fetch dispatches
```