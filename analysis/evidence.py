import hashlib
import re
from io import BytesIO

import capstone
from elftools.elf.elffile import ELFFile

from contracts.models import EvidenceBundle, Instruction, StringObservation

SECRET = re.compile(r"(?i)(?:password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^\s;]+")
EXTRA_SENSITIVE: tuple[str, ...] = ()


def sanitize(text: str) -> str:
    text = SECRET.sub("[REDACTED]", text)
    for value in EXTRA_SENSITIVE:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def sanitize_data(value):
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [sanitize_data(v) for v in value]
    if isinstance(value, dict):
        return {k: sanitize_data(v) for k, v in value.items()}
    return value


def derive(data, address, region, profile, source, evidence_id):
    digest = hashlib.sha256(data).hexdigest()
    strings = []
    for match in re.finditer(rb"[ -~]{4,}", data):
        original = match.group().decode("ascii")
        clean = sanitize(original)
        strings.append(
            StringObservation(
                address=address + match.start(), offset=match.start(), text=clean, redacted=clean != original
            )
        )
    sensitive = any(s.redacted for s in strings)
    instructions = []
    if region.executable:
        mode = capstone.CS_MODE_ARM if region.instruction_mode == "arm" else capstone.CS_MODE_THUMB
        mode |= (
            capstone.CS_MODE_LITTLE_ENDIAN if profile.endianness == "little" else capstone.CS_MODE_BIG_ENDIAN
        )
        decoded = list(capstone.Cs(capstone.CS_ARCH_ARM, mode).disasm(data, address))
        if not sensitive:
            instructions = [
                Instruction(address=i.address, size=i.size, mnemonic=i.mnemonic, operands=i.op_str)
                for i in decoded
            ]
    withheld = sensitive or source != "mock"
    return EvidenceBundle(
        evidence_id=evidence_id,
        base_address=address,
        length=len(data),
        content_hash=digest,
        source_mode=source,
        provenance=profile.provenance,
        endianness=profile.endianness,
        instruction_mode=region.instruction_mode if region.executable else "data",
        settings_source="Operator profile: " + region.name,
        decoder="Capstone " + capstone.__version__,
        strings=strings,
        instructions=instructions,
        approved_hex=None if withheld else data.hex(),
        withheld_reason="Raw bytes withheld by edge data policy" if withheld else None,
        uncertainties=[
            "Profile mode/code boundaries are assumptions; decoding does not prove reachability.",
            "Pattern redaction cannot identify all secrets; review ranges before cloud use.",
        ],
    )


def elf_metadata(data: bytes):
    elf = ELFFile(BytesIO(data))
    return {
        "architecture": elf.get_machine_arch(),
        "endianness": "little" if elf.little_endian else "big",
        "entry": elf.header.e_entry,
        "segments": [
            {"address": s.header.p_vaddr, "size": s.header.p_memsz}
            for s in elf.iter_segments()
            if s.header.p_type == "PT_LOAD"
        ],
        "provenance": "Operator ELF metadata; not proof of current load address",
    }
