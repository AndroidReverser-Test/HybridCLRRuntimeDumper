#!/usr/bin/env python3
"""Verify schema-2/3 raw captures without loading or executing managed code.

JSON goes to stdout, or to --output; concise summaries go to stderr. DLL checks
are structural, not IL semantic verification. PDB checks cover byte integrity,
not debug-table validity. Runtime associations and lifetime gates cannot be
independently re-run on the host. --compare-with adds raw DLL byte/identity
comparison only; reference IL/EH and runtime queries are not reverified.
"""

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import logging
from pathlib import Path
import re
import struct
import sys
import uuid


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def natural(value):
    return type(value) is int and value >= 0


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value),
            "missing or malformed SHA-256")
    return value.lower()


def address_value(value, alignment=1, allow_zero=False):
    require(type(value) is int or isinstance(value, str), "address/RVA must be an integer or integer string")
    number = int(value, 0) if isinstance(value, str) else value
    require(natural(number) and number < 1 << 64 and (allow_zero or number != 0) and
            number % alignment == 0, "invalid unsigned 64-bit address/RVA or alignment")
    return number


def verify_layout(layout, fields):
    require(isinstance(layout, dict), "layout must be an object")
    for field, alignment in fields.items():
        require(natural(layout.get(field)) and layout[field] <= 65536 and layout[field] % alignment == 0,
                "layout.{} has a missing/invalid offset or alignment".format(field))


def capture_path(session, filename):
    require(isinstance(filename, str) and filename and
            not any(c in filename for c in "/\\:\x00") and filename not in (".", ".."),
            "filename must be a plain session-local filename")
    path = (session / filename).resolve()
    require(path.parent == session, "filename resolves outside the session directory")
    require(path != session / "manifest.json", "blob filename cannot be manifest.json")
    return path


class BoundedBytes:
    """A zero-copy backing stream for dncil, limited to file-backed section data."""

    def __init__(self, data, start, end):
        self.data = memoryview(data)
        self.start, self.end, self.position = start, end, start

    def read(self, size):
        end = min(self.position + size, self.end)
        data = self.data[self.position:end].tobytes()
        self.position = end
        return data

    def tell(self):
        return self.position

    def seek(self, position):
        require(self.start <= position <= self.end, "method read/seek exceeds file-backed data")
        self.position = position
        return position


class ParserDiagnostics(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def rva_span(pe, data_length, rva, size):
    require(rva > 0 and size > 0, "empty or null RVA range")
    offset = pe.get_offset_from_rva(rva)
    section = pe.get_section_by_rva(rva)
    if section is None:
        end = min(pe.OPTIONAL_HEADER.SizeOfHeaders, data_length)
        require(offset == rva, "unmapped RVA")
        start = 0
    else:
        start = section.PointerToRawData
        end = min(start + section.SizeOfRawData, data_length)
    require(start <= offset and offset + size <= end,
            "RVA 0x{:x} + {} is not wholly file-backed".format(rva, size))
    return offset, end


def parse_il(data, pe, rva, tables):
    from dncil.cil.body import CilMethodBody
    from dncil.cil.body.reader import CilMethodBodyReaderBytes
    from dncil.cil.enums import OpCodeType, OperandType

    offset, end = rva_span(pe, len(data), rva, 1)
    reader = CilMethodBodyReaderBytes(b"")
    reader.stream = BoundedBytes(data, offset, end)
    body = CilMethodBody(reader)
    if body.flags.is_fat():
        require(rva % 4 == 0 and body.header_size >= 12, "invalid fat method header/alignment")
        require(body.flags.value & 0xFFF & ~0x1B == 0, "unsupported/reserved method header flags")
    require(body.code_size > 0, "RVA-bearing IL method has an empty body")
    code_start = offset + body.header_size
    code_end = code_start + body.code_size
    require(code_end <= end and sum(i.size for i in body.instructions) == body.code_size,
            "decoded instructions do not exactly cover the declared IL code size")
    starts = {i.offset for i in body.instructions}
    for instruction in body.instructions:
        require(instruction.opcode.op_code_type != OpCodeType.Nternal and
                not instruction.opcode.name.startswith("UNKNOWN"), "unknown/reserved IL opcode")
        operand_type = instruction.opcode.operand_type
        if operand_type in (OperandType.InlineBrTarget, OperandType.ShortInlineBrTarget):
            require(instruction.operand in starts, "branch target is not an instruction boundary")
        elif operand_type == OperandType.InlineSwitch:
            require(all(target in starts for target in instruction.operand),
                    "switch target is not an instruction boundary")
    if body.local_var_sig_tok is not None:
        token = body.local_var_sig_tok
        table = tables.tables.get(token.table)
        require(token.table == 0x11 and table is not None and 0 < token.rid <= table.num_rows,
                "invalid local-variable signature token")

    # dncil parses only the first extra section. Walk the full chain, using its
    # clause parsers, but check section sizes before accepting any parsed data.
    body.exception_handlers.clear()
    sections = 0
    position = (code_end + 3) & ~3
    more = body.flags.MoreSects
    while more:
        reader.seek(position)
        header = reader.read(4)
        require(len(header) == 4, "truncated EH section header")
        kind = header[0]
        require(kind & 0x3F == 1, "unsupported extra method section (not an EH table)")
        fat = bool(kind & 0x40)
        size = int.from_bytes(header[1:4] if fat else header[1:2], "little")
        clause_size = 24 if fat else 12
        require(size >= 4 and (size - 4) % clause_size == 0 and position + size <= end,
                "invalid/truncated EH section size")
        require(fat or header[2:4] == b"\x00\x00", "nonzero small EH section reserved bytes")
        reader.seek(position + 1)
        previous = len(body.exception_handlers)
        if fat:
            body.parse_fat_exception_handlers(reader)
        else:
            body.parse_tiny_exception_handlers(reader)
        require(reader.tell() == position + size and
                len(body.exception_handlers) - previous == (size - 4) // clause_size,
                "EH parser consumption does not match section size")
        sections += 1
        more = bool(kind & 0x80)
        position = (position + size + 3) & ~3

    boundaries = {start - code_start for start in starts}
    ends = boundaries | {body.code_size}
    for clause in body.exception_handlers:
        require(clause.exception_type & ~0xF == 0 and clause.exception_type & 7 in (0, 1, 2, 4),
                "invalid EH clause flags")
        for start, stop in ((clause.try_start, clause.try_end),
                            (clause.handler_start, clause.handler_end)):
            require(0 <= start < stop <= body.code_size and start in boundaries and stop in ends,
                    "EH try/handler range is outside IL or splits an instruction")
        if clause.is_filter():
            require(clause.filter_start in boundaries and clause.filter_start < clause.handler_start,
                    "EH filter offset is outside IL or is not before its handler")
        if clause.is_catch():
            token = clause.catch_type
            table = tables.tables.get(token.table) if token is not None else None
            require(token is not None and token.table in (0x01, 0x02, 0x1B) and
                    table is not None and 0 < token.rid <= table.num_rows,
                    "invalid EH catch type token")
    return len(body.instructions), sections, len(body.exception_handlers)


def inspect_dotnet(data, blob, result):
    import dnfile
    import pefile

    metrics = dict(types=0, methods=0, il_methods_expected=0, il_bodies_checked=0,
                   methods_without_rva=0, non_il_rva_methods=0, instructions_checked=0,
                   eh_sections_checked=0, eh_clauses_checked=0, resources_checked=0,
                   external_resources_not_checked=0)
    result["managed"] = metrics
    result["method_failures"] = []
    diagnostics = ParserDiagnostics()
    logger = logging.getLogger("dnfile")
    logger.addHandler(diagnostics)
    pe = None
    try:
        pe = dnfile.dnPE(data=data, fast_load=True, clr_lazy_load=True)
        require(pe.OPTIONAL_HEADER.Magic in (0x10B, 0x20B), "unsupported PE optional header")
        require(len(pe.sections) == pe.FILE_HEADER.NumberOfSections, "truncated PE section table")
        raw_ranges = sorted((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData)
                            for s in pe.sections if s.SizeOfRawData)
        for index, (start, end) in enumerate(raw_ranges):
            require(pe.OPTIONAL_HEADER.SizeOfHeaders <= start < end <= len(data),
                    "PE raw section overlaps headers or exceeds file")
            require(index == 0 or raw_ranges[index - 1][1] <= start, "overlapping PE raw sections")
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
        net = pe.net
        require(net is not None and net.metadata is not None and net.mdtables is not None,
                "independent parser could not read CLI metadata/tables")
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        require(72 <= net.struct.cb <= directory.Size, "invalid CLI header size")
        rva_span(pe, len(data), directory.VirtualAddress, net.struct.cb)
        rva_span(pe, len(data), net.struct.MetaDataRva, net.struct.MetaDataSize)
        streams = net.metadata.streams_list
        require(len(streams) == net.metadata.struct.NumberOfStreams, "incomplete metadata stream directory")
        require(len({s.struct.Name for s in streams}) == len(streams), "duplicate metadata streams")
        header_end = net.metadata.struct.sizeof() + sum(s.stream_table_entry_size() for s in streams)
        stream_ranges = []
        for stream in streams:
            start, size = stream.struct.Offset, stream.struct.Size
            require(start >= header_end and start + size <= net.struct.MetaDataSize and
                    stream.sizeof() == size, "metadata stream outside root or truncated")
            if size:
                stream_ranges.append((start, start + size))
        stream_ranges.sort()
        require(all(a[1] <= b[0] for a, b in zip(stream_ranges, stream_ranges[1:])),
                "overlapping metadata streams")
        tables = net.mdtables
        require(net.strings is not None and net.guids is not None and net.blobs is not None,
                "required metadata heaps are missing")
        for table in tables.tables_list:
            if table.num_rows:
                require(table.row_size > 0 and tables.rva <= table.rva and
                        table.rva + table.row_size * table.num_rows <= tables.rva + tables.sizeof(),
                        "metadata table exceeds its stream")
            table.parse(tables.tables_list)
        require(tables.Module is not None and tables.Module.num_rows == 1 and
                tables.Assembly is not None and tables.Assembly.num_rows == 1,
                "expected exactly one Module and one Assembly row")
        name = tables.Assembly.rows[0].Name
        require(name is not None and isinstance(name.value, str) and name.value,
                "missing/invalid Assembly name")
        module_mvid = tables.Module.rows[0].Mvid
        require(module_mvid is not None, "Module MVID is missing")
        mvid = str(uuid.UUID(bytes_le=module_mvid.value_bytes()))
        result["assembly_name"] = name.value
        result["mvid"] = mvid
        if name.value != blob.get("assembly_name_from_metadata"):
            result["reasons"].append("Assembly name differs from manifest metadata name")
        try:
            require(uuid.UUID(blob.get("mvid", "")) == uuid.UUID(mvid), "Module MVID differs from manifest")
        except (ValueError, AttributeError, TypeError) as error:
            result["reasons"].append("MVID comparison failed: {}".format(error))
        metrics["types"] = tables.TypeDef.num_rows if tables.TypeDef else 0
        methods = tables.MethodDef.rows if tables.MethodDef else []
        metrics["methods"] = len(methods)
        for index, method in enumerate(methods, 1):
            if not method.Rva:
                metrics["methods_without_rva"] += 1
                continue
            if method.struct.ImplFlags & 3 != 0:
                metrics["non_il_rva_methods"] += 1
                continue
            metrics["il_methods_expected"] += 1
            try:
                instructions, sections, clauses = parse_il(data, pe, method.Rva, tables)
                metrics["il_bodies_checked"] += 1
                metrics["instructions_checked"] += instructions
                metrics["eh_sections_checked"] += sections
                metrics["eh_clauses_checked"] += clauses
            except Exception as error:
                result["method_failures"].append(dict(token="0x{:08x}".format(0x06000000 | index),
                    name=str(method.Name), rva="0x{:x}".format(method.Rva), reason=str(error)))
        if result["method_failures"]:
            result["reasons"].append("{} IL method(s) failed structural parsing/boundary checks".format(
                len(result["method_failures"])))
        resources = tables.ManifestResource.rows if tables.ManifestResource else []
        if net.struct.ResourcesSize:
            rva_span(pe, len(data), net.struct.ResourcesRva, net.struct.ResourcesSize)
        for resource in resources:
            if resource.struct.Implementation_CodedIndex:
                require(resource.Implementation is not None and resource.Implementation.row is not None,
                        "invalid external resource metadata reference")
                metrics["external_resources_not_checked"] += 1
                continue
            require(resource.Offset + 4 <= net.struct.ResourcesSize, "resource length prefix outside directory")
            offset, _ = rva_span(pe, len(data), net.struct.ResourcesRva + resource.Offset, 4)
            length = struct.unpack_from("<I", data, offset)[0]
            require(resource.Offset + 4 + length <= net.struct.ResourcesSize,
                    "embedded resource payload outside directory")
            if length:
                rva_span(pe, len(data), net.struct.ResourcesRva + resource.Offset + 4, length)
            metrics["resources_checked"] += 1
    except Exception as error:
        result["reasons"].append("independent .NET parse failed: {}: {}".format(type(error).__name__, error))
    finally:
        logger.removeHandler(diagnostics)
        result["parser_diagnostics"] = list(dict.fromkeys(diagnostics.messages))
        if diagnostics.messages:
            result["reasons"].append("independent metadata parser reported warnings/errors (see parser_diagnostics)")
        if pe is not None:
            result["pe_warnings"] = list(dict.fromkeys(pe.get_warnings()))
            pe.close()


def verify_blob(session, blob, is_dll):
    result = dict(status="FAIL", reasons=[], chunks_checked=0)
    if not isinstance(blob, dict):
        result["reasons"].append("missing or malformed blob record")
        return result
    result.update(filename=blob.get("filename"), native_status=blob.get("status"),
                  native_reason=blob.get("reason"), declared_length=blob.get("declared_length"),
                  written_length=blob.get("written_length"))
    if blob.get("status") != "COMPLETE":
        optional_absence = (not is_dll and blob.get("status") in
                            ("ABSENT", "NOT_PRESENT", "NOT_REQUESTED", "SKIPPED", "DISABLED") and
                            blob.get("declared_length") == 0 and blob.get("written_length") == 0 and
                            not blob.get("filename") and not blob.get("chunks") and
                            not blob.get("output_sha256") and not blob.get("second_live_pass_sha256"))
        if optional_absence:
            result["status"] = "NOT_CAPTURED"
        else:
            result["reasons"].append("blob is not COMPLETE: {} ({})".format(
                blob.get("status"), blob.get("reason", "")))
        return result
    try:
        path = capture_path(session, blob.get("filename"))
        require(path.is_file(), "captured file is missing or not a regular file")
        data = path.read_bytes()
    except (OSError, ValueError) as error:
        result["reasons"].append(str(error))
        return result
    result["actual_length"] = len(data)
    actual_hash = hashlib.sha256(data).hexdigest()
    result["actual_sha256"] = actual_hash
    for field in ("declared_length", "written_length"):
        if not natural(blob.get(field)) or blob[field] == 0 or blob[field] != len(data):
            result["reasons"].append("{} does not match the nonempty file length".format(field))
    for field in ("output_sha256", "second_live_pass_sha256"):
        try:
            matches = digest(blob.get(field)) == actual_hash
            result[field + "_matches"] = matches
            require(matches, "SHA-256 differs from actual file")
        except ValueError as error:
            result[field + "_matches"] = False
            result["reasons"].append("{}: {}".format(field, error))
    if blob.get("coverage_complete") is not True:
        result["reasons"].append("manifest coverage_complete is not true")
    chunks = blob.get("chunks")
    ranges = []
    if not isinstance(chunks, list) or not chunks:
        result["reasons"].append("missing/non-list/empty chunk coverage")
        chunks = []
    for index, chunk in enumerate(chunks):
        try:
            require(isinstance(chunk, dict) and natural(chunk.get("offset")) and
                    natural(chunk.get("length")) and chunk["length"] > 0,
                    "invalid chunk offset/length")
            start, end = chunk["offset"], chunk["offset"] + chunk["length"]
            ranges.append((start, end))
            require(end <= len(data), "chunk exceeds actual file")
            expected = digest(chunk.get("sha256"))
            result["chunks_checked"] += 1
            require(hashlib.sha256(memoryview(data)[start:end]).hexdigest() == expected, "chunk SHA-256 mismatch")
        except ValueError as error:
            result["reasons"].append("chunk {}: {}".format(index, error))
    cursor = 0
    for start, end in sorted(ranges):
        if start != cursor:
            result["reasons"].append("chunk coverage gap/overlap at offset {} (next {})".format(cursor, start))
        cursor = max(cursor, end)
    if cursor != len(data) or cursor != blob.get("declared_length"):
        result["reasons"].append("chunks do not cover the complete declared/actual file")
    if blob.get("format_valid") is not True:
        result["reasons"].append("COMPLETE blob is not marked format_valid")
    if is_dll:
        inspect_dotnet(data, blob, result)
    else:
        result["format_validation"] = "not_performed; PDB byte integrity only"
    result["status"] = "FAIL" if result["reasons"] else "PASS"
    return result


def verify_session(session, manifest):
    require(isinstance(manifest, dict), "manifest root must be an object")
    schema = manifest.get("schema_version")
    require(type(schema) is int and schema in (2, 3),
            "only native manifest schema_version 2 or 3 is supported")
    captures = manifest.get("captures")
    require(isinstance(captures, list) and all(isinstance(c, dict) for c in captures),
            "captures must be a list of objects")
    report = dict(verification_schema_version=1, session_directory=str(session), status="FAIL",
                  errors=[], warnings=[], captures=[],
                  limitations=["Structural checks do not verify IL semantics, stack/type safety, or signature semantics.",
                               "PDBs receive length/hash/coverage checks, not independent debug-table validation.",
                                "Embedded resources receive bounds checks, not payload interpretation; external resources are not read.",
                                "Runtime query/association flags are manifest assertions, not independently replayed host queries.",
                                "Semantic discovery evidence receives metadata checks only; native discovery/code is not independently replayed.",
                                "Only manifest-listed registry inputs are checked; not all runtime or ordinary AOT assemblies.",
                                "Neither matching hashes nor unchanged registries prove an application lifetime gate or coherent snapshot."])
    mode = manifest.get("discovery_mode") if schema == 3 else None
    if schema == 3:
        report["discovery_mode"] = mode
        if mode not in ("auto", "profile"):
            report["errors"].append("discovery_mode must be auto or profile")
        for field, expected in (("supported_registry_abi", "ARM64_METADATA_V2_1024_HOT_THREE_POINTER_AOT_VECTOR"),
                                ("payload_copy", "FAILURE_REPORTING_KERNEL_READ")):
            if manifest.get(field) != expected:
                report["errors"].append("manifest {} must be {}".format(field, expected))
        unchanged = manifest.get("semantic_evidence_unchanged")
        if type(unchanged) is not bool or (mode == "auto" and unchanged is not True):
            report["errors"].append("semantic_evidence_unchanged must be boolean and true in auto mode")
        evidence = manifest.get("semantic_discovery_evidence")
        if not isinstance(evidence, list) or (mode == "auto" and not evidence):
            report["errors"].append("semantic_discovery_evidence must be a list, nonempty in auto mode")
            evidence = []
        evidence_ranges = {}
        for index, entry in enumerate(evidence):
            try:
                require(isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"],
                        "evidence must have a nonempty name")
                address = address_value(entry.get("address"))
                length = entry.get("length")
                require(natural(length) and length > 0 and address + length < 1 << 64,
                        "invalid evidence length/address range")
                sha256 = digest(entry.get("sha256"))
                key = (address, length)
                require(key not in evidence_ranges or evidence_ranges[key] == sha256,
                        "conflicting SHA-256 for the same evidence range")
                evidence_ranges[key] = sha256
            except ValueError as error:
                report["errors"].append("semantic_discovery_evidence[{}]: {}".format(index, error))
        try:
            registries = manifest.get("resolved_registry_rvas")
            require(isinstance(registries, dict), "resolved_registry_rvas must be an object")
            hot = address_value(registries.get("hot"), alignment=8)
            aot = address_value(registries.get("aot_vector"), alignment=8)
            require(hot != aot, "hot and aot_vector RVAs must be distinct")
        except ValueError as error:
            report["errors"].append("resolved_registry_rvas: {}".format(error))
        try:
            verify_layout(manifest.get("resolved_identity_layout"),
                          dict(image_token=4, image_assembly=8, assembly_image=8,
                               image_name=8, aot_target_assembly=8))
        except ValueError as error:
            report["errors"].append("resolved_identity_layout: {}".format(error))
        if mode == "auto":
            public_functions = {"il2cpp_" + name for name in ("domain_get", "assembly_get_image", "image_get_name",
                                "thread_current", "thread_attach", "thread_detach", "resolve_icall")}
            bindings = manifest.get("function_bindings")
            if not isinstance(bindings, list):
                report["errors"].append("auto function_bindings must be a list")
                bindings = []
            names = []
            for index, binding in enumerate(bindings):
                try:
                    require(isinstance(binding, dict) and isinstance(binding.get("name"), str) and
                            binding["name"] in public_functions,
                            "auto binding must name one of the seven public APIs")
                    names.append(binding["name"])
                    require(binding.get("source") == "ELF_DYNAMIC_SYMBOL_ABI",
                            "auto binding source must be ELF_DYNAMIC_SYMBOL_ABI")
                    require(binding.get("expected_sha256") == "",
                            "auto bindings must not claim prevalidated expected fingerprints")
                    address = address_value(binding.get("address"), alignment=4)
                    address_value(binding.get("rva"), alignment=4, allow_zero=True)
                    length = binding.get("fingerprint_length")
                    require(natural(length) and 0 < length <= 4096 and length % 4 == 0 and
                            address + length < 1 << 64, "invalid observed binding length/address range")
                    # This is an observation, not a fingerprint comparison against live code.
                    digest(binding.get("actual_sha256"))
                except ValueError as error:
                    report["errors"].append("function_bindings[{}]: {}".format(index, error))
            if len(bindings) != 7 or len(names) != 7 or set(names) != public_functions:
                report["errors"].append("auto function_bindings must contain exactly the seven public APIs once each")
    gate = manifest.get("stable_window_confirmed_by_caller")
    ungated = manifest.get("experimental_ungated_capture")
    report["snapshot"] = dict(stable_window_confirmed_by_caller=gate, experimental_ungated_capture=ungated,
        native_result_code=manifest.get("result_code"), native_error=manifest.get("error"),
        complete_within_declared_scope=manifest.get("complete_within_declared_scope"),
        coherent_snapshot_guaranteed_by_verifier=False, lifetime_gate_independently_verified=False,
        registry_snapshot_taken=manifest.get("registry_snapshot_taken"),
        registry_snapshots_unchanged=manifest.get("registry_snapshots_unchanged"),
        all_registered_inputs_exported=manifest.get("all_registered_inputs_exported"))
    if schema == 3:
        report["snapshot"]["semantic_evidence_unchanged"] = manifest.get("semantic_evidence_unchanged")
        report["snapshot"]["semantic_discovery_independently_replayed"] = False
    if type(gate) is not bool or type(ungated) is not bool or ungated == gate:
        report["errors"].append("inconsistent/missing lifetime-gate mode flags")
    if type(manifest.get("result_code")) is not int:
        report["errors"].append("native result_code must be an integer")
    if ungated is True:
        report["warnings"].append("No application lifetime gate: per-file validity does not establish a coherent runtime snapshot.")
        if manifest.get("complete_within_declared_scope") is not False or manifest.get("result_code") != 1:
            report["errors"].append("ungated capture must record result_code=1 and complete_within_declared_scope=false")
    elif manifest.get("complete_within_declared_scope") is not True or manifest.get("result_code") != 0:
        report["errors"].append("gated capture is not complete within its declared scope")
    for flag in ("registry_snapshot_taken", "registry_snapshots_unchanged", "all_registered_inputs_exported"):
        if manifest.get(flag) is not True:
            report["errors"].append("manifest {} is not true".format(flag))
    if manifest.get("cancelled") is not False:
        report["errors"].append("capture is cancelled or cancellation flag is missing")
    associated = set()
    ids = set()
    for capture in captures:
        item = {key: capture.get(key) for key in ("capture_id", "name", "kind", "status", "reason", "sources",
                    "registered", "query_confirmed", "association_verified", "duplicate_of_capture_id")}
        item["native_status"] = item.pop("status")
        item["reasons"] = []
        capture_id = capture.get("capture_id")
        if not natural(capture_id) or capture_id in ids:
            item["reasons"].append("invalid or duplicate capture_id")
        else:
            ids.add(capture_id)
        for flag in ("registered", "query_confirmed", "association_verified"):
            if capture.get(flag) is not True:
                item["reasons"].append("manifest {} is not true".format(flag))
        if not isinstance(capture.get("kind"), str) or not capture["kind"]:
            item["reasons"].append("capture kind is missing")
        sources = capture.get("sources")
        if not isinstance(sources, list) or not sources or not all(isinstance(s, str) and s for s in sources):
            item["reasons"].append("capture sources are missing or malformed")
        status = capture.get("status")
        if not isinstance(status, str) or not (status == "COMPLETE" or status.endswith("_COMPLETE")):
            item["reasons"].append("native capture status is not complete")
        try:
            address = int(capture.get("native_assembly", ""), 0) & 0x00FFFFFFFFFFFFFF
            require(address != 0, "null native assembly association")
            if capture.get("association_verified") is True:
                associated.add(address)
        except (ValueError, TypeError) as error:
            item["reasons"].append("invalid native assembly association: {}".format(error))
        item["dll"] = verify_blob(session, capture.get("dll"), True)
        item["pdb"] = verify_blob(session, capture.get("pdb"), False)
        if schema == 3:
            item.update({key: capture.get(key) for key in ("association_route", "private_query_status",
                         "native_name_matches_metadata", "representative_method", "resolved_owner_layout")})
            route, private_status = capture.get("association_route"), capture.get("private_query_status")
            valid_sources = sources if isinstance(sources, list) else []
            try:
                method = address_value(capture.get("representative_method"), allow_zero=True)
                if mode == "auto":
                    require(route == "SEMANTIC_REGISTRY_PUBLIC_API" and private_status == "NOT_REQUESTED",
                            "auto association_route/private_query_status must record public identity getters, not private queries")
                    require(method == 0, "auto representative_method must be zero")
                    require(all(source in valid_sources for source in
                                ("PUBLIC_API_REGISTRY_ASSOCIATION", "SEMANTIC_DLL_LOADER_AND_RAW_OWNER")),
                            "auto sources must include PUBLIC_API_REGISTRY_ASSOCIATION and SEMANTIC_DLL_LOADER_AND_RAW_OWNER")
                    require(not any(isinstance(source, str) and
                                    (source.upper() in ("GET_UNDERLYING_IMAGE_BY_METHOD", "FIND_AOT_BY_ASSEMBLY") or
                                     "NO_METHOD" in source.upper()) for source in valid_sources),
                            "auto sources must not claim private queries or token_no_method fallback")
                elif mode == "profile":
                    hot = capture.get("kind") == "HOT_UPDATE"
                    if route == "PROFILE_PRIVATE_QUERY":
                        require(private_status == "MATCH", "profile private query must record MATCH")
                        source = "GET_UNDERLYING_IMAGE_BY_METHOD" if hot else "FIND_AOT_BY_ASSEMBLY"
                        other_source = "FIND_AOT_BY_ASSEMBLY" if hot else "GET_UNDERLYING_IMAGE_BY_METHOD"
                        require(source in valid_sources and (method != 0 if hot else method == 0) and
                                other_source not in valid_sources and "TOKEN_REGISTRY_FALLBACK_NO_METHOD" not in valid_sources,
                                "profile MATCH sources/representative_method disagree with the capture kind")
                    else:
                        require(route == "PROFILE_TOKEN_REGISTRY_NO_METHOD" and private_status == "NOT_RUN_NO_METHOD" and
                                hot and method == 0 and "TOKEN_REGISTRY_FALLBACK_NO_METHOD" in valid_sources and
                                not any(source in valid_sources for source in
                                        ("GET_UNDERLYING_IMAGE_BY_METHOD", "FIND_AOT_BY_ASSEMBLY")),
                                "profile no-method route must be a hot token-registry fallback without a private query")
            except ValueError as error:
                item["reasons"].append(str(error))
            if capture.get("native_name_matches_metadata") is not True:
                item["reasons"].append("manifest native_name_matches_metadata is not true")
            name, assembly_name = capture.get("name"), item["dll"].get("assembly_name")
            if isinstance(name, str) and name[-4:].lower() == ".dll":
                name = name[:-4]
            if not isinstance(name, str) or not name or not isinstance(assembly_name, str) or name != assembly_name:
                item["reasons"].append("native image name differs from independently parsed DLL Assembly name")
            try:
                verify_layout(capture.get("resolved_owner_layout"), dict(hot_il2cpp_image=8, image_raw=8, image_pdb=8))
            except ValueError as error:
                item["reasons"].append("resolved_owner_layout: {}".format(error))
            for kind in ("dll", "pdb"):
                try:
                    blob = capture.get(kind)
                    require(isinstance(blob, dict), "missing blob record")
                    layout = blob.get("raw_layout")
                    verify_layout(layout, dict(data=8, length=4, end=8))
                    if blob.get("status") == "COMPLETE":
                        ranges = sorted((layout[field], layout[field] + width) for field, width in
                                        (("data", 8), ("length", 4), ("end", 8)))
                        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])),
                                "COMPLETE blob raw fields overlap")
                except ValueError as error:
                    item[kind]["reasons"].append("raw_layout: {}".format(error))
                    item[kind]["status"] = "FAIL"
        item["status"] = ("FAIL" if item["reasons"] or item["dll"]["status"] != "PASS" or
                          item["pdb"]["status"] == "FAIL" else "PASS")
        report["captures"].append(item)
    counts = manifest.get("counts")
    report["manifest_counts"] = counts
    if not isinstance(counts, dict):
        report["errors"].append("manifest counts are missing")
    else:
        expected = dict(union_candidates=len(captures), associated_native_assemblies=len(associated),
                        raw_files_complete=sum(isinstance(c.get("dll"), dict) and
                                               c["dll"].get("status") == "COMPLETE" for c in captures))
        for key, value in expected.items():
            if not natural(counts.get(key)) or counts[key] != value:
                report["errors"].append("counts.{} disagrees with capture records (expected {})".format(key, value))
        for key in ("hot_registry_objects", "aot_registry_elements"):
            if not natural(counts.get(key)):
                report["errors"].append("counts.{} is missing/invalid".format(key))
        if (natural(counts.get("hot_registry_objects")) and natural(counts.get("aot_registry_elements")) and
                counts["hot_registry_objects"] + counts["aot_registry_elements"] < len(captures)):
            report["errors"].append("registry object/element counts cannot cover all union candidates")
    files = [c[kind] for c in report["captures"] for kind in ("dll", "pdb")]
    report["summary"] = dict(captures=len(captures), captures_passed=sum(c["status"] == "PASS" for c in report["captures"]),
        files_passed=sum(f["status"] == "PASS" for f in files), files_failed=sum(f["status"] == "FAIL" for f in files),
        pdb_not_captured=sum(f["status"] == "NOT_CAPTURED" for f in files))
    report["status"] = ("PASS" if not report["errors"] and
                        all(c["status"] == "PASS" for c in report["captures"]) else "FAIL")
    return report


def read_dll_identity(data):
    """Read only Assembly/Module identity, without walking IL or executing code."""
    import dnfile

    pe = None
    try:
        pe = dnfile.dnPE(data=data, fast_load=True, clr_lazy_load=True)
        pe.parse_data_directories(directories=[14])
        require(pe.net is not None and pe.net.mdtables is not None, "missing CLI metadata tables")
        tables = pe.net.mdtables
        require(tables.Module is not None and tables.Module.num_rows == 1 and
                tables.Assembly is not None and tables.Assembly.num_rows == 1,
                "expected exactly one Module and one Assembly row")
        name, mvid = tables.Assembly.rows[0].Name, tables.Module.rows[0].Mvid
        require(name is not None and isinstance(name.value, str) and name.value and mvid is not None,
                "missing Assembly name or Module MVID")
        return name.value, str(uuid.UUID(bytes_le=mvid.value_bytes()))
    except Exception as error:
        raise ValueError("independent DLL identity parse failed: {}".format(error)) from error
    finally:
        if pe is not None:
            pe.close()


def compare_session(session, manifest, report, reference):
    """Add a raw comparison; return the reference manifest for output protection."""
    comparison = dict(reference_session=str(reference), count=0, status="SKIPPED", errors=[],
                      scope="Raw DLL bytes and metadata identity only; reference IL/EH and runtime queries are not reverified.")
    report["comparison"] = comparison
    if report["status"] != "PASS":
        comparison["reason"] = "current session verification did not pass"
        return None
    comparison["status"] = "FAIL"
    reference_manifest = None
    try:
        reference_manifest = json.loads((reference / "manifest.json").read_text(encoding="utf-8"),
                                       parse_constant=lambda value: require(False, "invalid JSON constant: " + value))
        require(isinstance(reference_manifest, dict) and type(reference_manifest.get("schema_version")) is int and
                reference_manifest["schema_version"] in (2, 3), "reference manifest must use schema_version 2 or 3")
        inputs = []
        for label, directory, native in (("current", session, manifest), ("reference", reference, reference_manifest)):
            captures = native.get("captures")
            require(isinstance(captures, list), "{} captures must be a list".format(label))
            files = Counter()
            for index, capture in enumerate(captures):
                try:
                    require(isinstance(capture, dict) and capture.get("kind") in ("HOT_UPDATE", "AOT_SUPPLEMENT"),
                            "missing/invalid DLL capture kind")
                    blob = capture.get("dll")
                    require(isinstance(blob, dict) and blob.get("status") == "COMPLETE", "DLL is not COMPLETE")
                    path = capture_path(directory, blob.get("filename"))
                    require(path.is_file(), "captured DLL is missing or not a regular file")
                    data = path.read_bytes()
                    actual_hash = hashlib.sha256(data).hexdigest()
                    for field in ("declared_length", "written_length"):
                        require(natural(blob.get(field)) and blob[field] == len(data) and len(data) > 0,
                                "{} differs from actual nonempty DLL length".format(field))
                    for field in ("output_sha256", "second_live_pass_sha256"):
                        require(digest(blob.get(field)) == actual_hash, "{} differs from actual DLL SHA-256".format(field))
                    name, mvid = read_dll_identity(data)
                    require(name == blob.get("assembly_name_from_metadata"), "Assembly name differs from DLL metadata")
                    require(isinstance(blob.get("mvid"), str) and uuid.UUID(blob["mvid"]) == uuid.UUID(mvid),
                            "MVID differs from DLL metadata")
                    files[(capture["kind"], name, str(uuid.UUID(mvid)), len(data), actual_hash)] += 1
                except (OSError, ValueError, TypeError) as error:
                    comparison["errors"].append("{} DLL #{}: {}".format(label, index, error))
            inputs.append(files)
        current_files, reference_files = inputs
        comparison.update(current_count=len(manifest["captures"]), reference_count=len(reference_manifest["captures"]),
                          count=sum((current_files & reference_files).values()))
        for label, missing in (("current", current_files - reference_files), ("reference", reference_files - current_files)):
            for (kind, name, mvid, length, sha256), count in sorted(missing.items()):
                comparison["errors"].append("{} has {} unmatched DLL(s): {} {} MVID={} length={} SHA-256={} "
                                            "(missing identity/multiplicity or different raw bytes)".format(
                                                label, count, kind, name, mvid, length, sha256))
        comparison["status"] = "FAIL" if comparison["errors"] else "PASS"
    except (OSError, ValueError, TypeError) as error:
        comparison["errors"].append("cannot compare reference session: {}".format(error))
    if comparison["status"] != "PASS":
        report["status"] = "FAIL"
    return reference_manifest


def print_summary(report):
    for capture in report.get("captures", []):
        for kind in ("dll", "pdb"):
            blob = capture[kind]
            metrics = blob.get("managed", {})
            text = "{} #{} {} {} bytes={} chunks={}".format(blob["status"], capture.get("capture_id"),
                kind.upper(), blob.get("filename") or "<none>", blob.get("actual_length", "?"), blob["chunks_checked"])
            if metrics:
                text += " types={} methods={} IL={}/{} EH={} resources={}".format(metrics["types"], metrics["methods"],
                    metrics["il_bodies_checked"], metrics["il_methods_expected"],
                    metrics["eh_clauses_checked"], metrics["resources_checked"])
            print(text, file=sys.stderr)
            reasons = blob["reasons"]
            if reasons:
                print("  " + "; ".join(reasons[:3]) + ("; see JSON for more" if len(reasons) > 3 else ""), file=sys.stderr)
        if capture["reasons"]:
            print("FAIL #{} association/capture: {}".format(capture.get("capture_id"),
                  "; ".join(capture["reasons"])), file=sys.stderr)
    for error in report.get("errors", []):
        print("FAIL: " + error, file=sys.stderr)
    for warning in report.get("warnings", []):
        print("WARNING: " + warning, file=sys.stderr)
    comparison = report.get("comparison")
    if comparison is not None:
        print("{}: DLL raw-byte comparison against {} matched={}; no reference IL/EH or runtime-query revalidation.".format(
              comparison["status"], comparison["reference_session"], comparison["count"]), file=sys.stderr)
        for error in comparison["errors"]:
            print("FAIL comparison: " + error, file=sys.stderr)
    print("{}: host file/manifest verification only; no coherent-snapshot or all-runtime-assemblies guarantee.".format(
          report["status"]), file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 = listed files/associations pass, 1 = verification failure, 2 = input/dependency/output error.")
    parser.add_argument("session_directory", type=Path, help="pulled session containing manifest.json and raw files")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout (parent must exist)")
    parser.add_argument("--compare-with", type=Path, metavar="reference_session",
                        help="compare actual DLL bytes/identities with a reference session after current verification passes")
    args = parser.parse_args(argv)
    session = args.session_directory.resolve()
    manifest = None
    exit_code = 2
    try:
        # Keep --help usable before dependencies are installed.
        import dnfile
        import dncil
        import pefile

        manifest = json.loads((session / "manifest.json").read_text(encoding="utf-8"),
                              parse_constant=lambda value: require(False, "invalid JSON constant: " + value))
        report = verify_session(session, manifest)
        report["parsers"] = dict(dnfile=dnfile.__version__, pefile=pefile.__version__, dncil=version("dncil"))
        exit_code = 0 if report["status"] == "PASS" else 1
    except ImportError as error:
        report = dict(verification_schema_version=1, session_directory=str(session), status="FAIL",
                      errors=["{}; install verification/requirements.txt in a venv".format(error)], captures=[])
    except (OSError, ValueError, TypeError) as error:
        report = dict(verification_schema_version=1, session_directory=str(session), status="FAIL",
                      errors=["cannot verify session: {}".format(error)], captures=[])
    reference = args.compare_with.resolve() if args.compare_with is not None else None
    reference_manifest = None
    if reference is not None:
        reference_manifest = compare_session(session, manifest, report, reference)
        if exit_code == 0 and report["status"] != "PASS":
            exit_code = 1
    text = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    if args.output is None:
        sys.stdout.write(text)
    else:
        try:
            output = args.output.resolve()
            protected = {session / "manifest.json"}
            if reference is not None:
                require(output != reference and reference not in output.parents,
                        "--output cannot write into the read-only reference session")
                protected.add(reference / "manifest.json")
                if isinstance(reference_manifest, dict) and isinstance(reference_manifest.get("captures"), list):
                    for capture in reference_manifest["captures"]:
                        if not isinstance(capture, dict):
                            continue
                        for kind in ("dll", "pdb"):
                            blob = capture.get(kind)
                            if isinstance(blob, dict) and isinstance(blob.get("filename"), str) and blob["filename"]:
                                try:
                                    protected.add((reference / blob["filename"]).resolve())
                                except (OSError, ValueError):
                                    pass
                elif output.exists():
                    require(output.stat().st_nlink == 1,
                            "--output cannot overwrite a multiply linked file without readable reference records")
            if isinstance(manifest, dict) and isinstance(manifest.get("captures"), list):
                for capture in manifest["captures"]:
                    if not isinstance(capture, dict):
                        continue
                    for kind in ("dll", "pdb"):
                        blob = capture.get(kind)
                        if isinstance(blob, dict) and blob.get("filename"):
                            protected.add((session / blob["filename"]).resolve())
            require(output not in protected, "--output cannot overwrite manifest or captured files")
            if output.exists():
                require(isinstance(manifest, dict) or output.parent != session,
                        "cannot overwrite a session file without a readable manifest")
                require(not any(path.exists() and output.samefile(path) for path in protected),
                        "--output aliases the manifest or a captured file")
            output.write_text(text, encoding="utf-8")
        except (OSError, ValueError, TypeError) as error:
            report.setdefault("errors", []).append("cannot write output: {}".format(error))
            report["status"] = "FAIL"
            sys.stdout.write(json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
            exit_code = 2
    print_summary(report)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
