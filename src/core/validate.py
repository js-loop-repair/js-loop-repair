import re
import subprocess
import os
from pathlib import Path
from .constant import static_analysis_path


def run_static_analysis_for_valiate(app_path: str, vul_graph_info_path, validation_output_path, slice_cmd, diff_list_path, repair_diff_path, cve_id, flags):
    cmd = [
        "python3",
        str(static_analysis_path),
        app_path,
        "-t",
        "xss",
        "--timeout",
        "60",
        "--run-env",
        "./tmp_env_for_validate",
        "--log-base-location",
        "./tmp_log_for_validate",
        "--export",
        "all",
        "--nodejs",
        "--avr-app-path",
        app_path,
        "--vul-graph-info-file-path",
        str(vul_graph_info_path),
        "--validation-output-path",
        str(validation_output_path),
        "-s",
        "--max-rep",
        "2",
        "--validate",
        "--repair-diff-path",
        str(repair_diff_path),
        "--cve-id",
        cve_id,
        "--diff-list",
        str(diff_list_path),
    ]

    if flags:
        cmd.extend(flags)
    if "--use-diff-files-as-entrance" in slice_cmd:
        cmd.append("--use-diff-files-as-entrance")
    if "--skip-require" in slice_cmd:
        cmd.append("--skip-require")

    print("Running Validation Analysis...\n")

    env = os.environ.copy()
    env["PYTHONPATH"] = "src"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, check=True, timeout=60)
        print("Validation Analysis Finished")
        if result.stderr:
            print("stderr:\n", result.stderr)
        return True, None

    except subprocess.TimeoutExpired:
        print("Validation Analysis timed out after 60 seconds")
        return False, {"timeout": True}

    except subprocess.CalledProcessError as e:
        print("Static analysis failed for Validation.")
        print("Command:", cmd)
        print("stdout:\n", e.stdout)
        if e.stderr:
            print("stderr:\n", e.stderr)

        log_file = Path("./tmp_log_for_validate/run_log.log")
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            log_content = "".join(lines)
            syntax_match = re.search(r"(SyntaxError:[^\n]+)", log_content)
            line_info_match = re.search(r"lineNumber:\s*(\d+),\s*column:\s*(\d+)", log_content)

            file_path = None
            if syntax_match:
                err_index = log_content.find(syntax_match.group(1))
                before_error = log_content[:err_index]
                file_matches = re.findall(r"Analyzing ([^\n]+)", before_error)
                if file_matches:
                    file_path = file_matches[-1]

            if syntax_match:
                error_info = {
                    "message": syntax_match.group(1).strip(),
                    "file": file_path,
                    "line": line_info_match.group(1) if line_info_match else None,
                    "column": line_info_match.group(2) if line_info_match else None,
                }
                print(
                    f"Detected Syntax Error: {error_info['message']} "
                    f"in file {error_info['file']} "
                    f"(line {error_info['line']}, column {error_info['column']})"
                )
                return False, error_info

        raise

    except Exception as e:
        print("Unexpected error occurred:", e)
        raise
