import logging
from pathlib import Path
from enum import Enum
from src.core.loop import loop
from src.core.validate import run_static_analysis_for_valiate
from ..utils.constant import (
    get_LLM_log_base_path,
    get_repair_code_base_path,
    final_repaired_result_path,
    repair_driver_log_path,
    simplifed_prompt,
    llm_model,
)


class CheckStatus(Enum):
    NOT_CHECKED = 0
    NOT_PASSED = 1
    PASSED = 2


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(repair_driver_log_path), logging.StreamHandler()],
)

BASE_PATH = Path(__file__).resolve().parents[2]
logger = logging.getLogger("repair_driver")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(repair_driver_log_path), logging.StreamHandler()],
)
logger = logging.getLogger("repair_driver")


cve_id = "CVE-2024-0435"
app_path = BASE_PATH / "repos/CVE-2024-0435/anything-llm/frontend"
diff_list = [
    {
        "old_path": "src/components/WorkspaceChat/ChatContainer/ChatHistory/HistoricalMessage/index.jsx",
        "new_path": "src/components/WorkspaceChat/ChatContainer/ChatHistory/HistoricalMessage/index.jsx",
        "diff_parsed": {
            "added": [
                [9, 'import createDOMPurify from "dompurify";'],
                [10, "const DOMPurify = createDOMPurify(window);"],
                [50, "                dangerouslySetInnerHTML={{"],
                [51, "                  __html: DOMPurify.sanitize(renderMarkdown(message)),"],
                [52, "                }}"],
            ],
            "deleted": [[48, "                dangerouslySetInnerHTML={{ __html: renderMarkdown(message) }}"]],
        },
        "file_change_id": "74132946302626",
        "method_change": [],
    }
]
temp_dir_path_for_code_slice_generation = BASE_PATH / "repair_logs/CVE-2024-0435/temp_code_slice_generation"
abalation_slice = False
all_vul_funcs = []
vul_type = "Cross-site Scripting (XSS)"
llm_log_base_path = BASE_PATH / "repair_logs/CVE-2024-0435/llm_log"
final_repaired_result_path = BASE_PATH / "repaired_result.json"
CALL_LLM = True
MAX_ROUNDS = 5

loop(
    cve_id=cve_id,
    app_path=app_path,
    diff_list=diff_list,
    temp_dir_path_for_code_slice_generation=temp_dir_path_for_code_slice_generation,
    abalation_slice=abalation_slice,
    all_vul_funcs=all_vul_funcs,
    logger=logger,
    vul_type=vul_type,
    llm_model=llm_model,
    llm_log_base_path=llm_log_base_path,
    simplifed_prompt=simplifed_prompt,
    final_repaired_result_path=final_repaired_result_path,
    flags=["--slice-imports"],
    get_LLM_log_base_path=get_LLM_log_base_path,
    get_repair_code_base_path=get_repair_code_base_path,
    run_static_analysis_for_valiate=run_static_analysis_for_valiate,
    CheckStatus=CheckStatus,
    MAX_ROUNDS=MAX_ROUNDS,
    CALL_LLM=CALL_LLM,
)
