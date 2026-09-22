# Three-minute demonstration
1. 0:00–0:30: Run uv run python scripts/demo.py and sign in using the local launcher's password.
   Point out MOCK TARGET and SCRIPTED ANALYSIS. No board or paid model is implied.
2. 0:30–1:00: Select bootloader inspection and the two approved synthetic regions.
   Explain excluded ranges and visible action/byte/iteration/time budgets.
3. 1:00–1:45: Start audit. Follow planner, policy gate, captures, decoder, analyst and verifier events.
   Inspect code at 0x80000000, Capstone instructions and timestamped registers.
4. 1:45–2:20: Open an evidence link. Show the synthetic U-Boot label and shell string as observed bytes,
   not an authenticated shell or vulnerability. Show redaction and withheld raw bytes.
5. 2:20–3:00: Export Markdown/JSON, inspect evidence IDs, hashes, source modes and limitations.
   Delete the run from memory. Explain the independent hardware and provider gates.

The automated browser smoke exercises this path against real local HTTP services.
Targets of under two minutes per audit and two seconds per local tool require hardware/provider
benchmarking; offline measurements are not proof of production latency.
