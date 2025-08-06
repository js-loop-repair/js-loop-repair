import tempfile
import json
import subprocess
import os
import shutil
from pathlib import Path
from .constant import static_analysis_path
import re


class ProgramSlicer:
    def __init__(self, cve_id, log_base="./tmp_log", run_env="./tmp_env", slice_timeout="120", flags=[]):
        self.cve_id = cve_id
        self.log_base = log_base
        self.run_env = run_env
        self.slice_timeout = slice_timeout
        self.cmd_cache_path = Path(f"./cmd_cache/{self.cve_id}.json")
        self.cmd_cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.flags = flags

    def load_cached_cmd(self):
        if self.cmd_cache_path.exists():
            with open(self.cmd_cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    def save_cmd_to_cache(self, cmd_list):
        with open(self.cmd_cache_path, "w", encoding="utf-8") as f:
            json.dump(cmd_list, f)

    def get_app_module_type(self, app_path: Path, diff_list: list, CVE_ID=None) -> str:
        module_types = set()
        seen_paths = set()

        for entry in diff_list:
            for key in ("old_path", "new_path"):
                rel_path = entry.get(key)
                if not rel_path or rel_path in seen_paths:
                    continue
                seen_paths.add(rel_path)

                file_path = app_path / rel_path
                if not file_path.exists():
                    continue

                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                if re.search(r"\b(import\s.+\sfrom\s.+|export\s)", content):
                    module_types.add("es6")
                elif re.search(r"\b(require\s*\(|module\.exports|exports\.)", content):
                    module_types.add("commonjs")
                else:
                    module_types.add("unknown")

        module_types.discard("unknown")

        if len(module_types) > 1:
            return "commonjs"
        elif not module_types:
            return "es6"

        return module_types.pop()

    def run_static_analysis(self, input_path: str, app_path: str, diff_list_path: str, nodejs=True):
        print(f"\n[INFO] Input path for analysis: {input_path}")

        cmd_flag_cache_path = Path(f"./cmd_cache/{self.cve_id}_flags.json")
        cmd_flag_cache_path.parent.mkdir(parents=True, exist_ok=True)

        def build_base_cmd():
            cmd = [
                "python3",
                str(static_analysis_path),
                input_path,
                "-t",
                "xss",
                "--timeout",
                self.slice_timeout,
                "--run-env",
                self.run_env,
                "--log-base-location",
                self.log_base,
                "--export",
                "all",
                "--diff-list",
                diff_list_path,
                "--avr-app-path",
                app_path,
                "--max-rep",
                "2",
                "--call-limit",
                "1",
                "--cve-id",
                self.cve_id,
                "--slice",
                "--single-branch",
                "-s",
            ]
            if nodejs:
                cmd.append("--nodejs")
            if self.flags:
                cmd.extend(self.flags)

            return cmd

        def run_cmd(cmd, attempt_label):
            print(f"\n[RUNNING] Code slicing ({attempt_label}):")
            print(" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            print(f"\n[STDOUT - {attempt_label}]\n{result.stdout.strip()}")
            if result.stderr.strip():
                print(f"\n[STDERR - {attempt_label}]\n{result.stderr.strip()}")
            return result

        env = os.environ.copy()
        env["PYTHONPATH"] = "src"

        if cmd_flag_cache_path.exists():
            with open(cmd_flag_cache_path, "r", encoding="utf-8") as f:
                extra_flags = json.load(f)
            print(f"[INFO] Using cached extra flags: {extra_flags}")
            cmd = build_base_cmd() + extra_flags
            result = run_cmd(cmd, "cached strategy")
            if result.returncode == 0:
                print("[SUCCESS] Cached slicing command worked.\n")
                return cmd
            else:
                print("[WARNING] Cached slicing command failed, falling back to attempts.\n")
        else:
            strategy_attempts = [
                ([], "1st attempt"),
                (["--use-diff-files-as-entrance", "--skip-require"], "2nd attempt (with --skip-require)"),
                (["--use-diff-files-as-entrance", "--require-diff-file"], "3rd attempt (with --require-diff-file)"),
            ]

            for extra_flags, label in strategy_attempts:
                cmd = build_base_cmd() + extra_flags
                result = run_cmd(cmd, label)
                if result.returncode == 0:
                    print(f"[SUCCESS] Code slicing succeeded using {label}.")
                    with open(cmd_flag_cache_path, "w", encoding="utf-8") as f:
                        json.dump(extra_flags, f)
                    return cmd

                if label == "2nd attempt" and "timeout" not in result.stderr.lower():
                    print("[INFO] Skipping 3rd attempt since error was not a timeout.")
                    break

            raise RuntimeError("Static analysis failed in all slicing attempts.")

    def run_abalation(self, app_dir, diff_list, tmp_dir_path, input_path=None, all_vul_funcs=[]):
        printed_code_slice_file, structured_code_slice_file, vul_graph_info_file, cmd, diff_list_path, app_copy_path = self.run(
            app_dir, diff_list, tmp_dir_path, input_path=input_path
        )

        print(f"app_dir: {app_dir}")

        structured_code_slice = {}
        code_slices = []

        funcs_by_file = {}
        for f in all_vul_funcs:
            rel_path = f["path"]
            start, end = f["start_line"], f["end_line"]
            funcs_by_file.setdefault(rel_path, []).append([start, end])

        for rel_path, ranges in funcs_by_file.items():
            file_path = str(app_copy_path / rel_path)
            if not os.path.exists(file_path):
                raise ValueError("")

            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            ranges.sort()
            merged = []
            for start, end in ranges:
                if not merged or start > merged[-1][1] + 1:
                    merged.append([start, end])
                else:
                    merged[-1][1] = max(merged[-1][1], end)

            display_path = rel_path
            structured_code_slice[display_path] = []

            file_slice = [f"// <FILE>: {display_path}\n"]
            for start, end in merged:
                code_lines = lines[start - 1 : end]
                if not code_lines:
                    continue
                file_slice.append("// <SLICE_START>\n")
                file_slice.extend(code_lines)
                if not code_lines[-1].endswith("\n"):
                    file_slice.append("\n// <SLICE_END>\n")
                else:
                    file_slice.append("// <SLICE_END>\n")
                structured_code_slice[display_path].append({"start_line": start, "end_line": end, "code": "".join(code_lines)})

            code_slices.append("".join(file_slice))

        structured_code_slice_file = structured_code_slice_file.resolve()
        printed_code_slice_file = printed_code_slice_file.resolve()

        with open(structured_code_slice_file, "w", encoding="utf-8") as f:
            json.dump(structured_code_slice, f, indent=2)
        with open(printed_code_slice_file, "w", encoding="utf-8") as f:
            f.write("\n".join(code_slices))
        print(f"[INFO] Rewritten structured slices -> {structured_code_slice_file}")
        print(f"[INFO] Rewritten printed slices -> {printed_code_slice_file}")

        return printed_code_slice_file, structured_code_slice_file, vul_graph_info_file, cmd, diff_list_path, app_copy_path

    def run(self, app_dir, diff_list, tmp_dir_path, input_path=None):
        if not diff_list:
            raise ValueError("diff list is not provided")

        cve_dir = Path(tmp_dir_path)
        cve_dir.mkdir(parents=True, exist_ok=True)

        app_copy_path = cve_dir / "app_dir"
        if not app_copy_path.exists():
            if os.path.isdir(app_dir):
                if app_copy_path.exists():
                    shutil.rmtree(app_copy_path)
                shutil.copytree(app_dir, app_copy_path, symlinks=True)
            else:
                raise FileNotFoundError(f"Provided app_dir does not exist: {app_dir}")

            print(f"Saved app_dir copy to: {app_copy_path}")

        diff_list_path = cve_dir / "diff_list.json"
        with open(diff_list_path, "w", encoding="utf-8") as f:
            json.dump(diff_list, f, indent=2)
        print(f"Saved diff_list to: {diff_list_path}")

        if input_path:
            analysis_input_path = app_copy_path / input_path
        else:
            analysis_input_path = app_copy_path

        module_type = self.get_app_module_type(app_copy_path, diff_list)
        use_nodejs_flag = module_type == "commonjs"

        print(f"Module Type:  {module_type}")

        cmd = self.run_static_analysis(str(analysis_input_path), str(app_copy_path), str(diff_list_path), nodejs=use_nodejs_flag)

        printed_code_slice_file = app_copy_path / "../.." / "printed_code_slice.txt"
        structured_code_slice_file = app_copy_path / "../.." / "structured_code_slice.json"
        vul_graph_info_file = app_copy_path / "../.." / "vul_graph_info.json"
        return printed_code_slice_file, structured_code_slice_file, vul_graph_info_file, cmd, diff_list_path, app_copy_path

    def reconstruct_code_slice_program(self, structured_slice_path, output_base_path, clean_before_write=True):
        output_path = Path(output_base_path)
        if clean_before_write and output_path.exists():
            shutil.rmtree(output_path)

        output_path.mkdir(parents=True, exist_ok=True)

        with open(structured_slice_path, "r", encoding="utf-8") as f:
            code_slice_data = json.load(f)

        for relative_path, snippets in code_slice_data.items():
            sorted_snippets = sorted(snippets, key=lambda x: x["start_line"])
            full_code = "".join(snippet["code"] for snippet in sorted_snippets)
            full_file_path = output_path / relative_path
            full_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_file_path, "w", encoding="utf-8") as f:
                f.write(full_code)

        package_json_path = output_path / "package.json"
        with open(package_json_path, "w", encoding="utf-8") as f:
            f.write("{}")

        print(f"Reconstructed files written to: {output_path}")
        return output_path
