import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scanner import scan_source


def test_hardcoded_secret_assignment():
    code = 'import os\nAPI_KEY = "sk-live-1234567890"\nprint(os.getenv("API_KEY"))\n'
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "hardcoded_secret"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_hardcoded_secret_function_default():
    code = 'def connect(password="hunter2"):\n    pass\n'
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "hardcoded_secret"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 1


def test_sql_injection_fstring_in_execute():
    code = (
        "def get_user(conn, user_id):\n"
        "    cursor = conn.cursor()\n"
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "sql_injection"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 3


def test_sql_injection_string_concat_in_execute():
    code = (
        "def get_user(conn, user_id):\n"
        "    cursor = conn.cursor()\n"
        '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)\n'
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "sql_injection"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 3


def test_sql_injection_percent_format_in_raw():
    code = (
        "def get_user(conn, user_id):\n"
        "    cursor = conn.cursor()\n"
        '    cursor.raw("SELECT * FROM users WHERE id = %s" % user_id)\n'
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "sql_injection"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 3


def test_sql_injection_str_format_in_execute():
    code = (
        "def get_user(conn, user_id):\n"
        "    cursor = conn.cursor()\n"
        '    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n'
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "sql_injection"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 3


def test_sql_injection_tainted_variable():
    code = (
        "def get_user(conn, user_id):\n"
        "    cursor = conn.cursor()\n"
        '    query = "SELECT * FROM users WHERE id = " + user_id\n'
        "    cursor.execute(query)\n"
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "sql_injection"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 4


def test_dangerous_call_eval():
    code = 'eval("__import__(\\"os\\").system(\\"ls\\")")\n'
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "dangerous_call"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 1


def test_dangerous_call_os_system():
    code = 'import os\nos.system("rm -rf /")\n'
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "dangerous_call"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_dangerous_call_subprocess_shell_true():
    code = (
        "import subprocess\n"
        'subprocess.run("ls", shell=True)\n'
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "dangerous_call"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_dangerous_call_pickle_loads():
    code = (
        "import pickle\n"
        "pickle.loads(b'cos\\nsystem\\n(S\\'ls\\'\\ntR.')\n"
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "dangerous_call"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_insecure_deserialization_yaml_load_no_loader():
    code = (
        "import yaml\n"
        "yaml.load(data)\n"
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "insecure_deserialization"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_insecure_deserialization_yaml_load_unsafe_loader():
    code = (
        "import yaml\n"
        "yaml.load(data, Loader=yaml.Loader)\n"
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "insecure_deserialization"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2


def test_insecure_deserialization_yaml_load_safe_loader_skipped():
    code = (
        "import yaml\n"
        "yaml.load(data, Loader=yaml.SafeLoader)\n"
    )
    findings = scan_source(code)
    matches = [f for f in findings if f["pattern_type"] == "insecure_deserialization"]
    assert len(matches) == 0


def test_parse_error_returns_finding():
    code = "def foo(\n    pass\n"
    findings = scan_source(code)
    assert len(findings) == 1
    assert findings[0]["pattern_type"] == "parse_error"
    assert findings[0]["line_number"] == 1


def test_clean_code_returns_empty():
    code = (
        "def add(a, b):\n"
        "    return a + b\n"
        "\n"
        "result = add(1, 2)\n"
        "print(result)\n"
    )
    findings = scan_source(code)
    assert findings == []