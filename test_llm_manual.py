from scanner import scan_source
from dependency_check import check_dependencies
from ai_llm import get_analysis
import json
import os

os.environ["HYPERION_LLM_API_KEY"] = "sk-nry-BDEA57eMfVcVvG3WMyuEe0uh4eproDKpiYD9_pB3sRU"
os.environ["HYPERION_LLM_API_URL"] = "https://router.bynara.id/v1/chat/completions"
os.environ["HYPERION_LLM_MODEL"] = "deepseek-v4-flash"

source = open("some_real_file.py").read()
scan_findings = scan_source(source, "some_real_file.py")
dep_findings = check_dependencies("test_requirements.txt")

result = get_analysis(scan_findings, dep_findings, source)
print(json.dumps(result, indent=2))
