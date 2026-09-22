# System Architecture
**Last Updated:** 2026-09-21
**Inspected Branch:** `main`

## 1. System Overview
SiliconSentinel is a distributed multi-agent system designed to automate firmware analysis and memory mapping. The architecture bridges a local physical environment (embedded ARM devices like the BeagleBone Black) with a cloud environment (Nebius AI Cloud). The system relies on LangGraph for stateful agent orchestration and Nebius Token Factory endpoints running NVIDIA open-source reasoning models to evaluate live JTAG memory dumps.

## 2. Interactive Architecture Map

Explore the logical separation of concerns between the local workstation and the cloud infrastructure:

## 3. Component Details

### 3.1 Edge Hardware Layer (Local Workstation)
*   **Target Device:** BeagleBone Black (AM335x ARM Cortex-A8).
*   **Physical Interface:** Hardware JTAG adapter connecting the workstation to the board's P2 header.
*   **Hardware Daemon:** `OpenOCD` runs locally on a Linux host (e.g., Kali or Ubuntu) translating standard GDB commands into JTAG electrical signals.
*   **Responsibility:** Expose CPU registers, memory banks, and execution states (halt/step) to the host machine.

### 3.2 Edge API Middleware
*   **Framework:** Python 3.12 with FastAPI.
*   **Translation Engine:** Utilizes `pyocd` or `subprocess` commands wrapping standard GDB to communicate with the local OpenOCD daemon.
*   **Endpoints:** Exposes atomic, hardware-level actions:
    *   `GET /api/v1/target/halt`
    *   `GET /api/v1/memory/read?address=0x80000000&size=256`
    *   `POST /api/v1/memory/write`
*   **Tunneling:** To allow the cloud agent to trigger these endpoints, the local port (e.g., 8000) is exposed via a secure `ngrok` tunnel protected by an API key.

### 3.3 Cloud Orchestration Layer (Nebius AI Cloud)
*   **Framework:** LangGraph (Node.js or Python).
*   **Hosting:** Deployed on Nebius AI Cloud instances.
*   **State Management:** LangGraph maintains the conversational state and the "Memory Map" state across iterative API calls.
*   **Tool Binding:** The LangGraph agent is equipped with a tool schema that maps directly to the FastAPI edge endpoints. When the LLM decides it needs to inspect the bootloader, LangGraph executes the HTTP request to the edge tunnel.

### 3.4 Inference Layer (Nebius Token Factory)
*   **LLM Provider:** Nebius Token Factory.
*   **Model:** NVIDIA Nemotron-3-Super (120B) or Nemotron-3-Ultra (550B). These hybrid MoE models offer the large context windows (up to 1M tokens) and advanced reasoning capabilities required to parse raw hex dumps and recognize ARM assembly/ASCII structures without hallucinatory drift.
*   **Responsibility:** Consume raw memory blocks, detect anomalies, identify execution flows, and determine the next logical memory address to scan.

## 4. Sequence of Operations: The Agent Loop

1.  **Prompt Initiation:** The user requests an analysis of the U-Boot sequence.
2.  **Reasoning Step:** LangGraph sends the prompt and available tools to the Nemotron model via Nebius API.
3.  **Tool Execution:** The model returns a tool call requesting a memory read at `0x402F0400`. LangGraph executes this HTTP call to the `ngrok` tunnel.
4.  **Hardware Interaction:** The FastAPI bridge receives the payload, executes the OpenOCD/GDB command to dump 256 bytes from the BeagleBone, and returns the hex string.
5.  **Context Update:** LangGraph appends the hex response to the context window and prompts the model again.
6.  **Analysis:** The model parses the hex, translates it into ARM instructions (similar to radare2/IDA Pro static analysis but dynamically), and logs findings to the state.
7.  **Termination:** The loop concludes when the model satisfies the initial prompt and generates the final markdown report.

## 5. Security & Trust Boundaries

*   **Trust Boundary 1: Internet to Localhost.** The most critical boundary. The ngrok tunnel MUST enforce API key authentication. The FastAPI server MUST validate this key via dependency injection on all routes.
*   **Trust Boundary 2: LangGraph to Nebius API.** Managed via standard Bearer tokens (`NEBIUS_API_KEY`).
*   **Data Residency:** Memory dumps are transiently processed by Nebius Token Factory. No persistent database stores the raw binary data to prevent leaking sensitive firmware IP.

## 6. Known Limitations
*   **Latency:** The round-trip time from the cloud LLM deciding to read memory -> edge API execution -> JTAG electrical read -> response propagation can take 1-3 seconds. The architecture restricts memory reads to 256/512-byte chunks to prevent API timeouts.
*   **Context Saturation:** While Nemotron supports massive context windows, continuously
