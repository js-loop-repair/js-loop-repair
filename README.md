# js-loop-repair

js-loop-repair
JSLoopRepair is a framework to automate the repair of JavaScript vulnerabilities. JSLoopRepair provides program slices and corresponding repair contexts as inputs to LLMs for repair and then validates the outputed repairs in terms of security and functionality by comparing the control-flow constraints and the data-flow expression before and after repairs. The validation results are further provided as repair contexts to LLMs for iterating the repair until final passes.

## Setup

To use **JSLoopRepair**, make sure the following are installed:

- **Python** 3.11 or higher
- **Node.js** 18 or higher
- **Ubuntu** 18.04.6 LTS

You will also need API keys as enviroment variables for the following LLMs Services:

```bash
OPENAI_API_KEY=your_openai_key_here
TOGETHER_API_KEY=your_together_key_here
GOOGLE_API_KEY=your_google_key_here
```

Then, navigate to the root directory of the project and run:

```
./install.sh
```

This command installs all required Python and Node.js dependencies. After it finishes, your environment will be ready.

## Getting Started

We provide an example script to demonstrate how to run JSLoopRepair:

```bash
./run.sh
```

## Side Effects
Running JSLoopRepair will create files on your local disk, such as logs, copies of the analyzed program, and intermediate graph outputs. These files will be saved inside the project's folder.
