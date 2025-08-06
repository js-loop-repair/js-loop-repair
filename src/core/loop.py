from src.core.llm import LLMRepairAssistant
from src.core.merge_back import RepairMerger
from src.core.program_slicer import ProgramSlicer
import json
from pathlib import Path


def loop(
    cve_id,
    app_path,
    diff_list,
    temp_dir_path_for_code_slice_generation,
    abalation_slice,
    all_vul_funcs,
    logger,
    vul_type,
    llm_model,
    llm_log_base_path,
    simplifed_prompt,
    final_repaired_result_path,
    flags,
    get_LLM_log_base_path,
    get_repair_code_base_path,
    run_static_analysis_for_valiate,
    CheckStatus,
    MAX_ROUNDS=5,
    CALL_LLM=True,
):
    llm_repair_assistant = None
    feedback_prompt = None
    used_feedbacks = set()
    code_slice_json_path = None
    code_slice_text_path = None
    repair_code = None
    vul_graph_info_file_path = None
    slice_cmd = None
    diff_list_path = None
    cur_round = 1
    while cur_round <= MAX_ROUNDS:
        print(f"Starting round {cur_round} of repair for CVE {cve_id}...")
        if cur_round == 1:
            slicer = ProgramSlicer(cve_id=cve_id, flags=flags)
            if abalation_slice:
                code_slice_text_path, code_slice_json_path, vul_graph_info_file_path, slice_cmd, diff_list_path, app_copy_path = slicer.run_abalation(
                    app_dir=app_path, diff_list=diff_list, tmp_dir_path=temp_dir_path_for_code_slice_generation, all_vul_funcs=all_vul_funcs
                )
            else:
                code_slice_text_path, code_slice_json_path, vul_graph_info_file_path, slice_cmd, diff_list_path, app_copy_path = slicer.run(
                    app_dir=app_path, diff_list=diff_list, tmp_dir_path=temp_dir_path_for_code_slice_generation
                )
            logger.info(f"{cve_id} code slice generated at: {code_slice_text_path}")
            print(f"Vulnerability graph info file path: {vul_graph_info_file_path}")

        if cur_round == 1:
            llm_repair_assistant = LLMRepairAssistant(
                llm_log_base_path=get_LLM_log_base_path(cve_id), CVE_ID=cve_id, call_LLM=CALL_LLM, vulnerability_type=vul_type, model=llm_model
            )
            repair_code, repair_response = llm_repair_assistant.get_initial_repair_code(
                printed_code_slice_file_path=code_slice_text_path, simplifed_prompt=simplifed_prompt
            )
        else:
            if not llm_repair_assistant:
                raise ValueError("LLMRepairAssistant was not initialized.")
            repair_code, _ = llm_repair_assistant.get_feedback_repair_code(feedback_prompt)
            cur_round += 1

        vul_graph_info_file_path = "./tmp_log/vul_graph_info.json"
        merger = RepairMerger(
            original_code_slice_json_path=code_slice_json_path,
            original_program_path=app_path,
            text_code_slice_path=code_slice_text_path,
            repair_code=repair_code,
            llm_repair_assistant=llm_repair_assistant,
            output_dir=get_repair_code_base_path(CVE_ID=cve_id),
            cve_id=cve_id,
        )

        try:
            copied_original_program_path, repaired_program_path, parsed_diff_path, line_maps_by_file = merger.run()
        except Exception as e:
            print(f"[Round {cur_round}] Repair merging failed: {e}. Proceeding to next round with feedback...")
            error_msg = str(e)
            if "Missing file in repaired code":
                feedback_prompt = "You must preserve lines that contain the special tokens <FILE>, <SLICE_START>, and <SLICE_END>."
            logger.exception(f"Merging failed in round {cur_round} for {cve_id}")
            cur_round += 1
            continue

        with open(parsed_diff_path, "r", encoding="utf-8") as f:
            parsed_diff = json.load(f)
        with open(vul_graph_info_file_path, "r", encoding="utf-8") as f:
            original_info = json.load(f)
        original_info.update(
            {
                "parsed_diff": parsed_diff,
                "line_maps_by_file": line_maps_by_file,
            }
        )
        tainted_variable_names_and_paths = original_info.get("tainted_variable_names_and_paths")
        taint_location_info = original_info.get("taint_location_info")
        sanitization_funcs = original_info.get("sanitization_funcs")

        vul_graph_info_path = repaired_program_path / "vul_graph_info.json"
        with open(vul_graph_info_path, "w", encoding="utf-8") as f:
            json.dump(original_info, f, indent=2)
        with open(vul_graph_info_file_path, "w", encoding="utf-8") as f:
            json.dump(original_info, f, indent=2)

        print(f"Saved updated vulnerability graph info to: {vul_graph_info_path}")
        print(f"Repaired program path: {repaired_program_path}")

        validation_output_path = repaired_program_path / "validate_result.json"
        try:
            validation_status, validation_info = run_static_analysis_for_valiate(
                str(repaired_program_path),
                vul_graph_info_path,
                validation_output_path,
                slice_cmd,
                diff_list_path=diff_list_path,
                repair_diff_path=parsed_diff_path,
                cve_id=cve_id,
                flags=flags,
            )
        except Exception as e:
            print(f"[Round {cur_round}] Static analysis failed: {e}. Proceeding to next round...")
            logger.exception(f"Static analysis failed in round {cur_round} for {cve_id}")
            cur_round += 1
            continue

        if validation_status and not validation_output_path.exists():
            raise ValueError("Validation output file was not created.")

        if validation_status:
            with open(validation_output_path, "r", encoding="utf-8") as f:
                validation_result = json.load(f)
        else:
            validation_result = {}

        print(f"[Round {cur_round}] Validation result: {validation_result}")

        sec_check = validation_result.get("security_check")
        func_check = validation_result.get("functionality_check")

        if not llm_repair_assistant:
            raise ValueError("LLMRepairAssistant is missing.")

        reason_msg = ""
        if sec_check != CheckStatus.PASSED.value:
            reason_msg = "The repair does not eliminate the vulnerability."
        elif func_check != CheckStatus.PASSED.value:
            reason_msg = "The repair introduces a functionality issue."

        if sec_check == CheckStatus.PASSED.value and func_check == CheckStatus.PASSED.value:
            log_item = {
                "CVE_ID": cve_id,
                "conversation_id": llm_repair_assistant.conversation_id,
                "resp": llm_repair_assistant.last_llm_response_id,
                "copied_original_program_path": str(copied_original_program_path),
                "repaired_program_path": str(repaired_program_path),
                "parsed_diff_path": str(parsed_diff_path),
                "validation_output_path": str(validation_output_path),
                "code_slice_text_path": str(code_slice_text_path),
                "code_slice_json_path": str(code_slice_json_path),
                "vul_graph_info_path": str(vul_graph_info_path),
                "validation_result": validation_result,
                "feedback_round": cur_round,
                "diff_list_path": str(diff_list_path),
            }

            final_results = {}
            if final_repaired_result_path.exists():
                with open(final_repaired_result_path, "r", encoding="utf-8") as f:
                    try:
                        final_results = json.load(f)
                    except json.JSONDecodeError:
                        print(f"Warning: Could not parse {final_repaired_result_path}. Starting with an empty result log.")

            final_results[cve_id] = log_item

            if CALL_LLM:
                with open(final_repaired_result_path, "w", encoding="utf-8") as f:
                    json.dump(final_results, f, indent=4)
                print(f"Repair completed successfully and logged at: {final_repaired_result_path}")
            break

        print(f"Validation failed in round {cur_round}. Generating feedback for the next round...")
        print("\n")
        print("------------------------------------------------------------------------------------------------------")
        print("\n")

        tainted_variable_feedback = llm_repair_assistant.generate_feedback_for_tainted_variable(tainted_variable_names_and_paths, reason_msg)
        taint_location_feedback = llm_repair_assistant.generate_feedback_for_taint_location(taint_location_info, reason_msg)
        sanitization_funcs_feedbacks = llm_repair_assistant.generate_feedbacks_for_sanitization_funcs(sanitization_funcs, reason_msg)
        candidates = []
        if validation_info:
            validation_feedback = validation_info.get("message")
            if validation_feedback:
                candidates.append(validation_feedback)

        RETRY_FEEDBACK = "Please try to fix it in a different way."

        if tainted_variable_feedback:
            candidates.append(tainted_variable_feedback)
        if taint_location_feedback:
            candidates.append(taint_location_feedback)
        if sanitization_funcs_feedbacks:
            candidates.extend(sanitization_funcs_feedbacks)
        candidates.append(RETRY_FEEDBACK)

        for candidate in candidates:
            if candidate and candidate not in used_feedbacks:
                feedback_prompt = candidate
                used_feedbacks.add(candidate)
                break

        print(f"Feedback for next round: {feedback_prompt}")
        cur_round += 1
    else:
        print(f"Maximum number of rounds reached. The repair for CVE {cve_id} did not pass validation.")
