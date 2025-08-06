from pathlib import Path
import difflib
import shutil
import json
import os
from typing import Tuple, Dict


def normalize_lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").splitlines(keepends=True)


class RepairMerger:
    def __init__(
        self,
        original_program_path,
        text_code_slice_path,
        original_code_slice_json_path,
        repair_code,
        llm_repair_assistant,
        cve_id,
        output_dir: Path,
        max_folders=5,
    ):
        self.original_program_path = Path(original_program_path)
        self.text_code_slice_path = Path(text_code_slice_path)
        self.original_code_slice_json_path = Path(original_code_slice_json_path)
        self.repair_code = repair_code
        self.output_dir = Path(output_dir)
        self.max_folders = max_folders
        self.cve_id = cve_id

        self.conv_id = llm_repair_assistant.conversation_id
        self.response_id = llm_repair_assistant.last_llm_response_id

        if not self.repair_code:
            raise ValueError("repair_code is not defined")
        if not self.conv_id or not self.response_id:
            raise ValueError("Missing conversation_id or response_id from LLMRepairAssistant")

        self.repair_base_path = self.output_dir / self.conv_id / self.response_id
        self.repair_code_file = self.repair_base_path / "repaired_code.txt"

        self.copied_original_program_path = self.repair_base_path / "original_program"
        self.repaired_program_path = self.repair_base_path / "repaired_program"

        self.repair_base_path.mkdir(parents=True, exist_ok=True)

    def cleanup_old_folders(self):
        base = self.output_dir
        if not base.exists():
            return
        all_dirs = [p for p in base.iterdir() if p.is_dir() and p.name.startswith("test-conv")]
        if len(all_dirs) <= self.max_folders:
            return
        sorted_dirs = sorted(all_dirs, key=lambda p: p.stat().st_mtime)
        dirs_to_remove = sorted_dirs[: -self.max_folders]
        for old_dir in dirs_to_remove:
            try:
                shutil.rmtree(old_dir)
                print(f"Removed old repair directory: {old_dir}")
            except Exception as e:
                print(f"Failed to remove {old_dir}: {e}")

    def setup_directories(self):
        self.cleanup_old_folders()
        if self.copied_original_program_path.exists():
            shutil.rmtree(self.copied_original_program_path)
        if self.repaired_program_path.exists():
            shutil.rmtree(self.repaired_program_path)
        shutil.copytree(self.original_program_path, self.copied_original_program_path)
        shutil.copytree(self.original_program_path, self.repaired_program_path)

    def export_merged_program_if_debug(self, slice_replacement_map: dict):
        if not hasattr(self, "cve_id"):
            print("No cve_id attribute found, skipping debug export.")
            return
        target_root = None
        if not target_root:
            print(f"No debug export path configured for CVE ID: {self.cve_id}")
            return
        target_root = Path(target_root)
        if not target_root.exists():
            print(f"Target debug path does not exist: {target_root}")
            return
        for filename in slice_replacement_map.keys():
            repaired_file = self.repaired_program_path / filename
            target_file = target_root / filename
            if not repaired_file.exists():
                print(f"Patched file missing, skipping: {repaired_file}")
                continue
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repaired_file, target_file)
            print(f"Patched file copied to: {target_file}")
        print(f"Only patched files were merged into: {target_root}")

    def save_repair_code(self):
        self.repair_code_file.write_text(self.repair_code, encoding="utf-8")
        print(f"Repaired code written to: {self.repair_code_file.resolve()}")

    def build_after_to_before_line_map(self, code_before, code_after):
        before_lines = code_before.splitlines()
        after_lines = code_after.splitlines()
        sm = difflib.SequenceMatcher(None, before_lines, after_lines)
        after_to_before_line_map = {}
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                for offset in range(j2 - j1):
                    after_line = j1 + offset + 1
                    before_line = i1 + offset + 1
                    after_to_before_line_map[after_line] = before_line
            else:
                continue
        return after_to_before_line_map

    def extract_repaired_slices(self) -> dict:
        repaired_slices_by_file = {}
        current_file = None
        capturing = False
        captured_lines = []
        for line in self.repair_code.splitlines(keepends=True):
            if line.strip().startswith("// <FILE>"):
                current_file = line.strip().split(":", 1)[-1].strip()
                repaired_slices_by_file.setdefault(current_file, [])
                capturing = False
                captured_lines = []
            elif line.strip() == "// <SLICE_START>":
                capturing = True
                captured_lines = []
            elif line.strip() == "// <SLICE_END>":
                if current_file and capturing:
                    repaired_slices_by_file[current_file].append("".join(captured_lines))
                capturing = False
            elif capturing:
                captured_lines.append(line)
        return repaired_slices_by_file

    def merge_slices_into_files(self, repaired_slices_by_file: dict):
        slice_replacement_map = self.compute_slice_replacement_map(repaired_slices_by_file)
        _, line_maps_by_file = self.apply_repair_from_map(slice_replacement_map)
        return line_maps_by_file

    def compute_slice_replacement_map(self, repaired_slices_by_file: dict) -> dict:
        original_slice_info = json.loads(self.original_code_slice_json_path.read_text(encoding="utf-8"))
        slice_replacement_map = {}
        for filename, original_slices in original_slice_info.items():
            if filename not in repaired_slices_by_file:
                raise ValueError(f"Missing file in repaired code: {filename}")
            repaired_slices = repaired_slices_by_file[filename]
            if len(repaired_slices) != len(original_slices):
                raise ValueError(f"Slice count mismatch for {filename}: {len(original_slices)} original vs {len(repaired_slices)} repaired")
            mapping = []
            current_line_shift = 0
            for slice_info, repaired_code in zip(original_slices, repaired_slices):
                start_line = slice_info["start_line"] - 1
                end_line = slice_info["end_line"]
                original_length = end_line - start_line
                repaired_lines = normalize_lines(repaired_code)
                repaired_length = len(repaired_lines)
                adjusted_start = start_line + current_line_shift
                adjusted_end = adjusted_start + repaired_length
                mapping.append(
                    {
                        "original_slice": {
                            "start_line": slice_info["start_line"],
                            "end_line": slice_info["end_line"],
                        },
                        "repaired_slice": {
                            "start_line": adjusted_start + 1,
                            "end_line": adjusted_end,
                        },
                        "repaired_lines": repaired_lines,
                    }
                )
                current_line_shift += repaired_length - original_length
            slice_replacement_map[filename] = mapping
        return slice_replacement_map

    def apply_repair_from_map(self, slice_replacement_map: dict) -> Tuple[Path, Dict[str, Dict[int, int]]]:
        line_maps_by_file: Dict[str, Dict[int, int]] = {}
        for filename, replacements in slice_replacement_map.items():
            orig_path = self.copied_original_program_path / filename
            repaired_path = self.repaired_program_path / filename
            try:
                full_lines = normalize_lines(orig_path.read_text(encoding="utf-8"))
            except Exception as e:
                raise RuntimeError(f"Failed to read original file {filename}: {e}")
            original_lines_copy = full_lines.copy()
            for item in reversed(replacements):
                orig_start = item["original_slice"]["start_line"] - 1
                orig_end = item["original_slice"]["end_line"]
                full_lines = full_lines[:orig_start] + item["repaired_lines"] + full_lines[orig_end:]
            try:
                repaired_path.parent.mkdir(parents=True, exist_ok=True)
                repaired_path.write_text("".join(full_lines), encoding="utf-8")
                print(f"Patched file written to: {repaired_path}")
            except Exception as e:
                raise IOError(f"Failed to write patched file {filename}: {e}")
            before_code = "".join(original_lines_copy)
            after_code = "".join(full_lines)
            after_to_before = self.build_after_to_before_line_map(before_code, after_code)
            line_maps_by_file[filename] = {v: k for k, v in after_to_before.items()}
        return self.repaired_program_path, line_maps_by_file

    def generate_final_diff(self, slice_replacement_map: dict) -> Path:
        parsed_diffs_by_file = {}
        for filename in slice_replacement_map:
            orig_file = self.copied_original_program_path / filename
            repaired_file = self.repaired_program_path / filename
            if not repaired_file.exists():
                print(f"Repaired file missing: {filename}")
                continue
            try:
                orig_lines = normalize_lines(orig_file.read_text(encoding="utf-8"))
                repaired_lines = normalize_lines(repaired_file.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"Failed to read file for diff: {filename}, {e}")
                continue
            diff = list(difflib.ndiff(orig_lines, repaired_lines))
            added = []
            deleted = []
            orig_line_num = 1
            repaired_line_num = 1
            for line in diff:
                if line.startswith("  "):
                    orig_line_num += 1
                    repaired_line_num += 1
                elif line.startswith("- "):
                    deleted.append([orig_line_num, line[2:]])
                    orig_line_num += 1
                elif line.startswith("+ "):
                    added.append([repaired_line_num, line[2:]])
                    repaired_line_num += 1
            if added or deleted:
                parsed_diffs_by_file[filename] = {"added": added, "deleted": deleted}
            else:
                print(f"No changes in: {filename}")
        parsed_diff_path = self.repair_base_path / "final_file_level_diff_parsed.json"
        with parsed_diff_path.open("w", encoding="utf-8") as f:
            json.dump(parsed_diffs_by_file, f, indent=2)
        print(f"Parsed file-level diffs saved to: {parsed_diff_path.resolve()}")
        return parsed_diff_path

    def run(
        self,
    ) -> Tuple[Path, Path, Path, Dict[str, Dict[int, int]]]:
        self.setup_directories()
        self.save_repair_code()
        repaired_slices_by_file = self.extract_repaired_slices()
        slice_replacement_map = self.compute_slice_replacement_map(repaired_slices_by_file)
        final_repaired_path, line_maps_by_file = self.apply_repair_from_map(slice_replacement_map)
        parsed_diff_path = self.generate_final_diff(slice_replacement_map)
        self.export_merged_program_if_debug(slice_replacement_map)
        return (
            self.copied_original_program_path,
            final_repaired_path,
            parsed_diff_path,
            line_maps_by_file,
        )
