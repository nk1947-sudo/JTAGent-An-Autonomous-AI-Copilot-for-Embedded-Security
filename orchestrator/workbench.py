"""Pure, offline binary patch validation for the guarded firmware workbench."""

import hashlib

import capstone

from contracts.models import PatchInstruction, PatchPreview, PatchPreviewRequest


def _decode(data: bytes, address: int, mode: str, endianness: str):
    capstone_mode = capstone.CS_MODE_ARM if mode == "arm" else capstone.CS_MODE_THUMB
    capstone_mode |= capstone.CS_MODE_LITTLE_ENDIAN if endianness == "little" else capstone.CS_MODE_BIG_ENDIAN
    decoder = capstone.Cs(capstone.CS_ARCH_ARM, capstone_mode)
    return [
        PatchInstruction(
            address=instruction.address,
            bytes_hex=bytes(instruction.bytes).hex(),
            mnemonic=instruction.mnemonic,
            operands=instruction.op_str,
        )
        for instruction in decoder.disasm(data, address)
    ]


def preview_patch(request: PatchPreviewRequest, plan, profile):
    original = bytes.fromhex(request.original_hex)
    replacement = bytes.fromhex(request.replacement_hex)
    end = request.address + len(original)
    capture = next(
        (
            item
            for item in plan.captures
            if item.base_address <= request.address and end <= item.base_address + item.returned_length
        ),
        None,
    )
    if capture is None:
        raise ValueError("Patch range is not covered by this plan's captured evidence")
    region = next(
        (
            item
            for item in profile.regions
            if item.approved and item.start <= request.address and end <= item.end
        ),
        None,
    )
    if region is None:
        raise ValueError("Patch range is outside the approved target profile")
    if region.kind != "ram":
        raise ValueError("Only approved RAM ranges can be drafted for volatile patching")
    warnings = [
        "Offline preview only: no target bytes were changed.",
        "The original live bytes are withheld from the orchestrator, so the supplied original bytes are not yet read-back verified.",
        "A future live executor must snapshot, verify, write, read back, and roll back under separate HITL approval.",
    ]
    original_instructions = _decode(original, request.address, request.instruction_mode, profile.endianness)
    replacement_instructions = _decode(
        replacement, request.address, request.instruction_mode, profile.endianness
    )
    if not original_instructions or not replacement_instructions:
        warnings.append(
            "One side did not decode completely; check mode, alignment, and instruction boundaries."
        )
    return PatchPreview(
        plan_id=request.plan_id,
        address=request.address,
        length=len(original),
        instruction_mode=request.instruction_mode,
        original_hex=original.hex(),
        replacement_hex=replacement.hex(),
        original_sha256=hashlib.sha256(original).hexdigest(),
        replacement_sha256=hashlib.sha256(replacement).hexdigest(),
        original_instructions=original_instructions,
        replacement_instructions=replacement_instructions,
        warnings=warnings,
    )
