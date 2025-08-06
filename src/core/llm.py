from pathlib import Path
import json
from datetime import datetime, UTC
import difflib
from openai import OpenAI
from openai.types import responses
import tiktoken
from collections import defaultdict
from google import genai
import uuid
from dotenv import load_dotenv
import os


load_dotenv()


class LLMRepairAssistant:
    def __init__(self, llm_log_base_path, model="gpt-4o", vulnerability_type=None, CVE_ID=None, call_LLM=False):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        self.client = OpenAI(api_key=self.api_key)
        self.model = model

        self.llm_log_base_path = Path(llm_log_base_path)
        self.llm_log_base_path.mkdir(parents=True, exist_ok=True)

        if model.startswith("meta-llama"):
            self.client = OpenAI(api_key=self.TOGETHER_API_KEY, base_url="https://api.together.xyz/v1")
        elif model == "gemini-2.0-flash":
            self.gemini_client = genai.Client(api_key=self.google_api_key)
        else:
            self.client = OpenAI(api_key=self.api_key)

        self.CVE_ID = CVE_ID
        if not vulnerability_type:
            raise ValueError("vulnerability_type must be provided")
        self.vulnerability_type = vulnerability_type

        self.conversation_id = None
        self.messages = []

        self.call_LLM = call_LLM

        self.last_llm_response_id = None

        self._test_response_index = 0
        self._test_response_entries = None
        self._test_response_filename = None

    def start_new_conversation(self):
        counter_path = self.llm_log_base_path / ("conversation_counter.txt" if self.call_LLM else "test_conversation_counter.txt")
        prefix = "conv" if self.call_LLM else "test-conv"

        if counter_path.exists():
            with counter_path.open("r") as f:
                conv_id = int(f.read().strip()) + 1
        else:
            conv_id = 1

        with counter_path.open("w") as f:
            f.write(str(conv_id))

        self.conversation_id = f"{prefix}-{conv_id:04d}"
        self.log_file_path = self.llm_log_base_path / f"{self.conversation_id}.json"
        self.messages = []

        print(f"Started new conversation: {self.conversation_id}")
        print(f"Conversation log file: {self.log_file_path}")

    def clean_repair_code(self, code):
        code = code.strip()
        if code.startswith("```"):
            lines = code.splitlines()
            if len(lines) > 1 and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            code = "\n".join(lines)
        return code.strip()

    def generate_initial_repair_prompt_simplifed(self, code_slice):
        prompt = "You are a coding assistant. The following code is a code snippet and contains a"
        prompt += f" {self.vulnerability_type} vulnerability" if self.vulnerability_type else " vulnerability"
        prompt += "."
        prompt += "Please return the code to fix it. \n"
        prompt += f"{code_slice}\n"
        token_count = self.count_tokens(prompt)
        prompt_log_path = self.llm_log_base_path / "initial_prompt.txt"
        with prompt_log_path.open("w", encoding="utf-8") as f:
            f.write(prompt)
        token_log_path = self.llm_log_base_path / "initial_prompt_tokens.txt"
        with token_log_path.open("w", encoding="utf-8") as f:
            f.write(f"{token_count}\n")
        print(f"Initial prompt written to {prompt_log_path}")
        print(f"Prompt token count written to {token_log_path}")

        return prompt

    def generate_initial_repair_prompt(self, code_slice):
        prompt = "You are a coding assistant. The following code is a code snippet and contains a"
        prompt += f" {self.vulnerability_type} vulnerability" if self.vulnerability_type else " vulnerability"
        prompt += "."

        prompt += (
            "\n\nPlease return only the raw, corrected version of the code that fixes the vulnerability. "
            "Do not include any additional text, markdown, explanations, formatting markers, or modify the original formatting or indentation of the code. \n"
            "Preserve special tokens (e.g., `// <FILE>: index.js, // <SLICE_START>, and // <SLICE_END>`) as in the input. "
            "Do not remove or alter any existing comments in the code."
            "Do not add any imports, helper functions, or definitions already assumed to exist.\n\n"
        )

        prompt += f"{code_slice}\n"

        token_count = self.count_tokens(prompt)

        prompt_log_path = self.llm_log_base_path / "initial_prompt.txt"
        with prompt_log_path.open("w", encoding="utf-8") as f:
            f.write(prompt)

        token_log_path = self.llm_log_base_path / "initial_prompt_tokens.txt"
        with token_log_path.open("w", encoding="utf-8") as f:
            f.write(f"{token_count}\n")

        print(f"Initial prompt written to {prompt_log_path}")
        print(f"Prompt token count written to {token_log_path}")

        return prompt

    def count_tokens(self, text: str) -> int:
        try:
            encoding = tiktoken.encoding_for_model(self.model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))

    def format_llm_response(self, response):
        if self.call_LLM and self.model == "gpt-4o":
            return {
                "id": response["id"],
                "created": getattr(response, "created", None),
                "object": getattr(response, "object", None),
                "output_text": getattr(response, "output_text", None),
            }
        else:
            return {
                "id": response.get("id"),
            }

    def get_last_real_response(self):
        """Return output from the latest real conv-*.json file"""
        real_logs = sorted(self.llm_log_base_path.glob("conv-*.json"), reverse=True)
        if not real_logs:
            raise FileNotFoundError("No real conversation logs found (conv-*.json).")

        latest_log_file = real_logs[0]
        print(f"latest_log_file:  {latest_log_file}")
        with latest_log_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if not data:
                raise ValueError(f"Empty log in file: {latest_log_file}")
            last_entry = data[0]

        print(f"Loaded last real LLM response from: {latest_log_file}")

        response_output = last_entry["response_output"]
        response_json = last_entry["response"]

        if isinstance(response_json, str):
            try:
                response_json = json.loads(response_json)
            except json.JSONDecodeError:
                raise ValueError("Failed to parse `response` string as JSON.")

        return response_output, response_json

    def get_llm_response(self, prompt: str):
        if not self.call_LLM:
            # Fallback to local test log
            self.messages.append({"role": "user", "content": prompt})
            response_output, response_json = self.get_next_test_response_from_log()
            self.messages.append({"role": "assistant", "content": response_output})
            formatted_response = self.format_llm_response(response_json)
            self.last_llm_response_id = formatted_response.get("id")
            return self.clean_repair_code(response_output), formatted_response

        self.messages.append({"role": "user", "content": prompt})

        if self.model.startswith("meta-llama"):
            response = self.client.chat.completions.create(model=self.model, messages=self.messages, max_tokens=2048, temperature=0.2)
            msg = response.choices[0].message
            response_output = msg.content
            response_json = json.loads(response.model_dump_json())

        elif self.model == "gpt-4o":
            response = self.client.responses.create(model=self.model, input=self.messages)
            response_output = response.output_text
            response_json = json.loads(response.to_json())

        elif self.model.startswith("gpt-3.5"):
            response = self.client.chat.completions.create(model=self.model, messages=self.messages)
            msg = response.choices[0].message
            response_output = msg.content
            response_json = json.loads(response.model_dump_json())
        elif self.model == "gemini-2.0-flash":
            contents = []
            for msg in self.messages:
                role = "user" if msg["role"] == "user" else "assistant"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})
            response = self.gemini_client.models.generate_content(model="gemini-2.0-flash", contents=contents)
            response_output = response.text
            gemini_id = getattr(response, "response_id", None) or f"gemini-{uuid.uuid4().hex[:8]}"
            response_json = {"id": gemini_id, "text": response.text}

        self.messages.append({"role": "assistant", "content": response_output})
        formatted_response = self.format_llm_response(response_json)
        self.last_llm_response_id = formatted_response.get("id")
        repair_code = self.clean_repair_code(response_output)
        self.log_interaction(
            self.messages, response_output, response_json, cve_id=self.CVE_ID, vulnerability_type=self.vulnerability_type, response_id=response_json.get("id")
        )

        return repair_code, formatted_response

    def get_next_test_response_from_log(self):
        if self._test_response_entries is None:
            latest_log = sorted(self.llm_log_base_path.glob("conv-*.json"), reverse=True)[0]
            self._test_response_filename = latest_log

            with latest_log.open("r", encoding="utf-8") as f:
                self._test_response_entries = json.load(f)
                self._test_response_entries.reverse()

        entries = self._test_response_entries
        if self._test_response_index >= len(entries):
            raise IndexError(f"No more entries left in {self._test_response_filename}.")

        entry = entries[self._test_response_index]
        self._test_response_index += 1

        print(f"Loaded response #{self._test_response_index} from {self._test_response_filename}")

        response_output = entry["response_output"]
        response_json = entry["response"]

        if isinstance(response_json, str):
            try:
                response_json = json.loads(response_json)
            except json.JSONDecodeError:
                raise ValueError("Failed to parse response JSON.")

        return response_output, response_json

    def log_interaction(self, prompt, response_output, response, cve_id=None, vulnerability_type=None, response_id=None):
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "conversation_id": self.conversation_id,
            "prompt": self.messages,
            "response_id": response.get("id"),
            "response_output": response_output,
            "response": response,
            "model": self.model,
            "cve_id": self.CVE_ID or cve_id,
            "vulnerability_type": self.vulnerability_type or vulnerability_type,
        }

        data = []
        if self.log_file_path.exists():
            with self.log_file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)

        data.insert(0, log_entry)
        with self.log_file_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        print(f"Logging LLM interaction to: {self.log_file_path}")

    def get_initial_repair_code(self, printed_code_slice_file_path, cve_id=None, simplifed_prompt=False):
        if not self.conversation_id:
            self.start_new_conversation()

        if not self.conversation_id:
            raise ValueError("need conversation id")

        with open(printed_code_slice_file_path, "r", encoding="utf-8") as f:
            code_slice = f.read()

        if simplifed_prompt:
            prompt = self.generate_initial_repair_prompt_simplifed(code_slice)
        else:
            prompt = self.generate_initial_repair_prompt(code_slice)
        repair_code, repair_response = self.get_llm_response(prompt)

        return repair_code, repair_response

    def get_feedback_repair_code(self, feedback):
        if not self.messages:
            raise ValueError("no conversation started")

        if not self.conversation_id:
            raise ValueError("need conversation id")

        prompt = self.generate_feedback_prompt(feedback)
        print(f"prompt for LLM query:  {prompt}")
        repair_code, repair_response = self.get_llm_response(prompt)

        return repair_code, repair_response

    def generate_feedback_prompt(self, feedback):
        if feedback:
            return "The privous repair failed.\n" + feedback
        else:
            return "The privous repair failed.\n"

    def generate_feedback_for_tainted_variable(self, tainted_variable_names_and_paths, no_variable_info=False, on_taint_variable=True, reason_msg=None):
        if not tainted_variable_names_and_paths:
            return None

        merged = defaultdict(list)

        # Group variables by (file_path, line_content) — line_content can be None
        for info in tainted_variable_names_and_paths:
            file_path = info.get("file_path")
            line_content = info.get("line_content")
            variable_name = info.get("variable_name")
            key = (file_path, line_content)
            merged[key].append(variable_name)

        parts = []
        for (file_path, line_content), variables in merged.items():
            var_list = ", ".join(f"`{v}`" for v in sorted(set(variables)))
            if line_content:
                parts.append(f'{var_list} in `{file_path}` at Line "{line_content}"')
            else:
                parts.append(f"{var_list} in `{file_path}`")

        joined_parts = "; ".join(parts)
        prompt = f"The vulnerability involves the tainted variable(s): {joined_parts}."
        if on_taint_variable:
            prompt += "Please only change this line without other changes. Return Full Code."
        return prompt

    def generate_feedback_for_taint_location(self, file_path_and_line_content, reason_msg):
        if not file_path_and_line_content:
            return None

        parts = []
        for file_path in file_path_and_line_content:
            line_content = file_path_and_line_content[file_path]
            parts.append(f"`{line_content}` in `{file_path}`")

        joined_parts = "\n- ".join(parts)
        prompt = f"\n- Vulnerable Locations:\n- {joined_parts}"
        return prompt

    def generate_feedbacks_for_sanitization_funcs(self, sanitization_funcs, reason_msg):
        if not sanitization_funcs:
            return None

        unique_funcs = set(sanitization_funcs)
        prompts = [f"Consider using `{func}` to sanitize the tainted variable(s)." for func in unique_funcs]
        return prompts
