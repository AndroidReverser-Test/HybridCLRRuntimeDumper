"""Fast manifest regressions; DLL parsing is mocked, PDB absence checks are real."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from . import verify_captures
else:
    import verify_captures


PUBLIC_APIS = (
    "il2cpp_domain_get", "il2cpp_assembly_get_image", "il2cpp_image_get_name",
    "il2cpp_thread_current", "il2cpp_thread_attach", "il2cpp_thread_detach", "il2cpp_resolve_icall",
)


def make_manifest(mode="auto", kind="HOT_UPDATE", no_method=False):
    hot = kind == "HOT_UPDATE"
    sources = ["HOT_REGISTRY_SLOT_256" if hot else "AOT_REGISTRY_ELEMENT_0"]
    if mode == "auto":
        route, private_status, method = "SEMANTIC_REGISTRY_PUBLIC_API", "NOT_REQUESTED", "0x0"
        sources += ["PUBLIC_API_REGISTRY_ASSOCIATION", "SEMANTIC_DLL_LOADER_AND_RAW_OWNER"]
    elif no_method:
        route, private_status, method = "PROFILE_TOKEN_REGISTRY_NO_METHOD", "NOT_RUN_NO_METHOD", "0x0"
        sources += ["TOKEN_REGISTRY_FALLBACK_NO_METHOD"]
    else:
        route, private_status = "PROFILE_PRIVATE_QUERY", "MATCH"
        method = "0x2000" if hot else "0x0"
        sources += ["GET_UNDERLYING_IMAGE_BY_METHOD" if hot else "FIND_AOT_BY_ASSEMBLY"]
    return dict(
        schema_version=3, discovery_mode=mode,
        supported_registry_abi="ARM64_METADATA_V2_1024_HOT_THREE_POINTER_AOT_VECTOR",
        payload_copy="FAILURE_REPORTING_KERNEL_READ", semantic_evidence_unchanged=mode == "auto",
        semantic_discovery_evidence=[dict(name="registry_code", address="0x10004000", length=16,
                                         sha256="a" * 64)] if mode == "auto" else [],
        resolved_registry_rvas=dict(hot="0x8000", aot_vector="0x7000"),
        resolved_identity_layout=dict(image_token=64, image_assembly=16, assembly_image=0,
                                      image_name=0, aot_target_assembly=248),
        function_bindings=[dict(name=name, source="ELF_DYNAMIC_SYMBOL_ABI" if mode == "auto" else "ELF_DYNAMIC_SYMBOL",
                               address=hex(0x10001000 + index * 4), rva=hex(0x1000 + index * 4),
                               fingerprint_length=4, expected_sha256="" if mode == "auto" else "b" * 64,
                               actual_sha256="b" * 64) for index, name in enumerate(PUBLIC_APIS)],
        stable_window_confirmed_by_caller=True, experimental_ungated_capture=False,
        complete_within_declared_scope=True, result_code=0, error="", cancelled=False,
        registry_snapshot_taken=True, registry_snapshots_unchanged=True, all_registered_inputs_exported=True,
        counts=dict(union_candidates=1, associated_native_assemblies=1, raw_files_complete=1,
                    hot_registry_objects=int(hot), aot_registry_elements=int(not hot)),
        captures=[dict(capture_id=1, name="Example.dll", kind=kind, status=kind + "_COMPLETE", reason="",
                       native_assembly="0x1000", registered=True, query_confirmed=True, association_verified=True,
                       association_route=route, private_query_status=private_status, representative_method=method,
                       native_name_matches_metadata=True, sources=sources,
                       resolved_owner_layout=dict(hot_il2cpp_image=256 if hot else 0, image_raw=8, image_pdb=0),
                       dll=dict(status="COMPLETE", assembly_name_from_metadata="Example", declared_length=4,
                                written_length=4, raw_layout=dict(data=8, length=16, end=24)),
                       pdb=dict(status="DISABLED", declared_length=0, written_length=0, filename="", chunks=[],
                                output_sha256="", second_live_pass_sha256="",
                                raw_layout=dict(data=0, length=0, end=0)))],
    )


class VerifyManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.session = Path(self.temporary.name).resolve()
        self.assembly_name = "Example"
        self.real_verify_blob = verify_captures.verify_blob
        mock = patch.object(verify_captures, "verify_blob", side_effect=self.verify_blob)
        self.blob_mock = mock.start()
        self.addCleanup(mock.stop)

    def verify_blob(self, session, blob, is_dll):
        if not is_dll:
            return self.real_verify_blob(session, blob, False)
        complete = isinstance(blob, dict) and blob.get("status") == "COMPLETE"
        return dict(status="PASS" if complete else "FAIL", assembly_name=self.assembly_name,
                    chunks_checked=1, reasons=[] if complete else ["DLL is not COMPLETE"])

    def check(self, manifest, expected="PASS", reason=None):
        report = verify_captures.verify_session(self.session, manifest)
        reasons = report["errors"] + [reason for capture in report["captures"]
                    for reason in capture["reasons"] + capture["dll"]["reasons"] + capture["pdb"]["reasons"]]
        self.assertEqual(report["status"], expected, reasons)
        if reason is not None:
            self.assertTrue(any(reason in text for text in reasons), reasons)
        return report

    def test_schema2_without_schema3_fields(self):
        manifest = make_manifest("profile")
        manifest["schema_version"] = 2
        for field in ("discovery_mode", "supported_registry_abi", "payload_copy", "semantic_evidence_unchanged",
                      "semantic_discovery_evidence", "resolved_registry_rvas", "resolved_identity_layout"):
            del manifest[field]
        capture = manifest["captures"][0]
        for field in ("association_route", "private_query_status", "native_name_matches_metadata", "resolved_owner_layout"):
            del capture[field]
        del capture["dll"]["raw_layout"]
        del capture["pdb"]["raw_layout"]
        self.check(manifest)

    def test_schema2_historical_captures(self):
        root = Path(__file__).resolve().parents[1] / "build" / "captures"
        sessions = (("1791179923565-12005-0", "PASS"), ("1791178476665-10483-0", "FAIL"))
        if not all((root / name / "manifest.json").is_file() for name, _ in sessions):
            self.skipTest("local historical capture fixtures are unavailable")
        for name, expected in sessions:
            with self.subTest(session=name):
                manifest = json.loads((root / name / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["schema_version"], 2)
                report = self.check(manifest, expected)
                self.assertEqual(report["summary"]["captures"], 25)

    def test_unknown_schema_rejected_before_blob_checks(self):
        for schema in (None, 0, 1, 4, -1, True, False, "3", [], {}):
            with self.subTest(schema=schema):
                manifest = make_manifest()
                manifest["schema_version"] = schema
                with self.assertRaisesRegex(ValueError, "schema_version 2 or 3"):
                    verify_captures.verify_session(self.session, manifest)
        self.blob_mock.assert_not_called()

    def test_schema3_auto_public_identity_confirmation(self):
        for kind in ("HOT_UPDATE", "AOT_SUPPLEMENT"):
            with self.subTest(kind=kind):
                report = self.check(make_manifest(kind=kind))
                self.assertEqual(report["captures"][0]["private_query_status"], "NOT_REQUESTED")
                self.assertTrue(report["captures"][0]["query_confirmed"])
                self.assertFalse(report["snapshot"]["semantic_discovery_independently_replayed"])
                self.assertFalse(report["snapshot"]["coherent_snapshot_guaranteed_by_verifier"])
                self.assertTrue(any("metadata checks only" in text for text in report["limitations"]))

    def test_discovery_mode_and_top_level_contract(self):
        bad_values = dict(discovery_mode=(None, "", "AUTO", "PROFILE", "semantic", False, [], {}),
                          supported_registry_abi=(None, "OTHER_ABI"), payload_copy=(None, "MEMCPY"))
        for field, values in bad_values.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    manifest = make_manifest()
                    manifest[field] = value
                    self.check(manifest, "FAIL", field)

    def test_auto_rejects_private_query_claims(self):
        changes = (("association_route", "PROFILE_PRIVATE_QUERY"),
                   ("association_route", "PROFILE_TOKEN_REGISTRY_NO_METHOD"),
                   ("association_route", None), ("private_query_status", "MATCH"),
                   ("private_query_status", "NOT_RUN_NO_METHOD"), ("private_query_status", None))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                manifest = make_manifest()
                manifest["captures"][0][field] = value
                self.check(manifest, "FAIL", "auto association_route/private_query_status")

    def test_auto_representative_method_must_be_zero(self):
        for method in ("0x2000", -1, True, None, {}, "not a pointer", "0x10000000000000000"):
            with self.subTest(method=method):
                manifest = make_manifest()
                manifest["captures"][0]["representative_method"] = method
                self.check(manifest, "FAIL")
        manifest = make_manifest()
        manifest["captures"][0]["representative_method"] = 0
        self.check(manifest)

    def test_auto_sources_required_and_private_sources_forbidden(self):
        for source in ("GET_UNDERLYING_IMAGE_BY_METHOD", "FIND_AOT_BY_ASSEMBLY",
                       "TOKEN_REGISTRY_FALLBACK_NO_METHOD", "token_no_method"):
            with self.subTest(forbidden=source):
                manifest = make_manifest()
                manifest["captures"][0]["sources"].append(source)
                self.check(manifest, "FAIL", "auto sources must not claim")
        for source in ("PUBLIC_API_REGISTRY_ASSOCIATION", "SEMANTIC_DLL_LOADER_AND_RAW_OWNER"):
            with self.subTest(missing=source):
                manifest = make_manifest()
                manifest["captures"][0]["sources"].remove(source)
                self.check(manifest, "FAIL", "auto sources must include")

    def test_auto_query_confirmed_is_still_required(self):
        for value in (False, 1, None):
            with self.subTest(value=value):
                manifest = make_manifest()
                manifest["captures"][0]["query_confirmed"] = value
                self.check(manifest, "FAIL", "query_confirmed is not true")

    def test_auto_evidence_unchanged_must_be_true_boolean(self):
        for value in (False, 1, "true", None):
            with self.subTest(value=value):
                manifest = make_manifest()
                manifest["semantic_evidence_unchanged"] = value
                self.check(manifest, "FAIL", "semantic_evidence_unchanged")

    def test_auto_evidence_required_and_metadata_validated(self):
        for evidence in (None, {}, [], [None], [{}]):
            with self.subTest(evidence=evidence):
                manifest = make_manifest()
                manifest["semantic_discovery_evidence"] = evidence
                self.check(manifest, "FAIL", "semantic_discovery_evidence")
        bad_values = dict(name=(None, "", False), address=(None, "0x0", "-1", "bad", True, {}),
                          length=(None, 0, -1, True, "16", 1 << 64), sha256=(None, "", "z" * 64, "a" * 63))
        for field, values in bad_values.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    manifest = make_manifest()
                    manifest["semantic_discovery_evidence"][0][field] = value
                    self.check(manifest, "FAIL", "semantic_discovery_evidence[0]")

    def test_evidence_address_overflow_and_conflicting_hashes(self):
        manifest = make_manifest()
        manifest["semantic_discovery_evidence"][0].update(address="0xfffffffffffffff0", length=32)
        self.check(manifest, "FAIL", "length/address range")
        manifest = make_manifest()
        duplicate = copy.deepcopy(manifest["semantic_discovery_evidence"][0])
        duplicate["sha256"] = "c" * 64
        manifest["semantic_discovery_evidence"].append(duplicate)
        self.check(manifest, "FAIL", "conflicting SHA-256")
        duplicate.update(address="0x10005000", sha256="A" * 64)
        self.check(manifest)

    def test_auto_bindings_exactly_seven_public_apis(self):
        for bindings in (None, [], make_manifest()["function_bindings"][:-1],
                         make_manifest()["function_bindings"] + [make_manifest()["function_bindings"][0]]):
            with self.subTest(bindings=bindings):
                manifest = make_manifest()
                manifest["function_bindings"] = bindings
                self.check(manifest, "FAIL", "function_bindings")
        for name in ("GetUnderlyingInterpreterImage", "FindImageByAssembly", "il2cpp_image_get_class",
                     "il2cpp_thread_detach", None, [], {}):
            with self.subTest(name=name):
                manifest = make_manifest()
                manifest["function_bindings"][0]["name"] = name
                self.check(manifest, "FAIL", "function_bindings")

    def test_auto_binding_metadata_and_no_expected_fingerprint(self):
        bad_values = dict(source=(None, "ELF_DYNAMIC_SYMBOL", "VERIFIED_CONFIG_RVA"),
                          expected_sha256=(None, "b" * 64), actual_sha256=(None, "", "not a hash"),
                          address=(None, "0x0", "0x1001", True), rva=(None, "-1", "0x1001", {}),
                          fingerprint_length=(None, 0, -4, True, 3, 4100))
        for field, values in bad_values.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    manifest = make_manifest()
                    manifest["function_bindings"][0][field] = value
                    self.check(manifest, "FAIL", "function_bindings[0]")
        manifest = make_manifest()
        manifest["function_bindings"][0]["actual_sha256"] = "C" * 64
        self.check(manifest)

    def test_native_name_extension_only_is_case_insensitive(self):
        for name in ("Example.dll", "Example.DLL", "Example.dLl", "Example"):
            with self.subTest(name=name):
                manifest = make_manifest()
                manifest["captures"][0]["name"] = name
                self.check(manifest)
        for name in ("example.dll", "Example.exe", "Example.dll.extra", "", ".dll", None):
            with self.subTest(name=name):
                manifest = make_manifest()
                manifest["captures"][0]["name"] = name
                self.check(manifest, "FAIL", "independently parsed DLL Assembly name")

    def test_native_name_flag_cannot_replace_independent_metadata(self):
        for mode in ("auto", "profile"):
            with self.subTest(mode=mode):
                manifest = make_manifest(mode)
                capture = manifest["captures"][0]
                capture["name"] = "Forged.dll"
                capture["dll"]["assembly_name_from_metadata"] = "Forged"
                self.assertTrue(capture["native_name_matches_metadata"])
                self.check(manifest, "FAIL", "independently parsed DLL Assembly name")
        for value in (False, 1, None, "true"):
            with self.subTest(flag=value):
                manifest = make_manifest()
                manifest["captures"][0]["native_name_matches_metadata"] = value
                self.check(manifest, "FAIL", "native_name_matches_metadata is not true")
        self.assembly_name = None
        self.check(make_manifest(), "FAIL", "independently parsed DLL Assembly name")

    def test_registry_and_identity_layout_metadata(self):
        for registries in (None, {}, dict(hot="0x0", aot_vector="0x7000"),
                           dict(hot="0x8001", aot_vector="0x7000"), dict(hot="0x8000", aot_vector="0x8000")):
            with self.subTest(registries=registries):
                manifest = make_manifest()
                manifest["resolved_registry_rvas"] = registries
                self.check(manifest, "FAIL", "resolved_registry_rvas")
        for layout in (None, {}, dict(image_token=True, image_assembly=16, assembly_image=0, image_name=0, aot_target_assembly=248)):
            with self.subTest(layout=layout):
                manifest = make_manifest()
                manifest["resolved_identity_layout"] = layout
                self.check(manifest, "FAIL", "resolved_identity_layout")

    def test_owner_and_blob_layouts_required_and_offsets_valid(self):
        for mode in ("auto", "profile"):
            for field, bad_value in (("hot_il2cpp_image", -8), ("image_raw", True), ("image_raw", 7),
                                     ("image_pdb", 65544), ("image_pdb", "16")):
                with self.subTest(mode=mode, field=field, value=bad_value):
                    manifest = make_manifest(mode)
                    manifest["captures"][0]["resolved_owner_layout"][field] = bad_value
                    self.check(manifest, "FAIL", "resolved_owner_layout")
        manifest = make_manifest()
        del manifest["captures"][0]["resolved_owner_layout"]
        self.check(manifest, "FAIL", "resolved_owner_layout")
        for kind in ("dll", "pdb"):
            for layout in (None, {}, dict(data=8, length=16, end=False), dict(data=8, length=15, end=24)):
                with self.subTest(kind=kind, layout=layout):
                    manifest = make_manifest()
                    manifest["captures"][0][kind]["raw_layout"] = layout
                    self.check(manifest, "FAIL", "raw_layout")
        manifest = make_manifest()
        manifest["captures"][0]["dll"]["raw_layout"]["length"] = 12
        self.check(manifest, "FAIL", "raw fields overlap")

    def test_profile_match_hot_and_aot_with_empty_semantic_evidence(self):
        for kind in ("HOT_UPDATE", "AOT_SUPPLEMENT"):
            with self.subTest(kind=kind):
                manifest = make_manifest("profile", kind)
                self.assertFalse(manifest["semantic_evidence_unchanged"])
                self.assertEqual(manifest["semantic_discovery_evidence"], [])
                report = self.check(manifest)
                self.assertEqual(report["captures"][0]["private_query_status"], "MATCH")

    def test_profile_no_method_hot_fallback(self):
        report = self.check(make_manifest("profile", no_method=True))
        self.assertEqual(report["captures"][0]["private_query_status"], "NOT_RUN_NO_METHOD")

    def test_profile_illegal_association_modes(self):
        changes = (("association_route", "SEMANTIC_REGISTRY_PUBLIC_API"), ("association_route", "UNKNOWN"),
                   ("private_query_status", "NOT_REQUESTED"), ("private_query_status", "NOT_RUN_NO_METHOD"),
                   ("representative_method", "0x0"), ("sources", ["HOT_REGISTRY_SLOT_256"]))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                manifest = make_manifest("profile")
                manifest["captures"][0][field] = value
                self.check(manifest, "FAIL", "profile")
        manifest = make_manifest("profile", "AOT_SUPPLEMENT")
        manifest["captures"][0]["representative_method"] = "0x2000"
        self.check(manifest, "FAIL", "profile MATCH")
        for field, value in (("private_query_status", "MATCH"), ("representative_method", "0x2000"),
                             ("sources", ["TOKEN_REGISTRY_FALLBACK_NO_METHOD", "GET_UNDERLYING_IMAGE_BY_METHOD"])):
            with self.subTest(fallback_field=field, value=value):
                manifest = make_manifest("profile", no_method=True)
                manifest["captures"][0][field] = value
                self.check(manifest, "FAIL", "profile no-method")
        self.check(make_manifest("profile", "AOT_SUPPLEMENT", no_method=True), "FAIL", "profile no-method")

    def test_profile_semantic_boolean_and_evidence_types_still_checked(self):
        for value in (None, 0, "false"):
            with self.subTest(unchanged=value):
                manifest = make_manifest("profile")
                manifest["semantic_evidence_unchanged"] = value
                self.check(manifest, "FAIL", "semantic_evidence_unchanged")
        manifest = make_manifest("profile")
        manifest["semantic_discovery_evidence"] = None
        self.check(manifest, "FAIL", "semantic_discovery_evidence")

    def test_pdb_not_discovered_is_not_absence(self):
        manifest = make_manifest()
        manifest["captures"][0]["pdb"]["status"] = "NOT_DISCOVERED"
        report = self.check(manifest, "FAIL", "blob is not COMPLETE: NOT_DISCOVERED")
        self.assertEqual(report["captures"][0]["pdb"]["status"], "FAIL")
        self.assertEqual(report["summary"]["pdb_not_captured"], 0)

    def test_pdb_disabled_and_not_present_rules_preserved(self):
        for mode in ("auto", "profile"):
            for status in ("DISABLED", "NOT_PRESENT"):
                with self.subTest(mode=mode, status=status):
                    manifest = make_manifest(mode)
                    manifest["captures"][0]["pdb"]["status"] = status
                    report = self.check(manifest)
                    self.assertEqual(report["summary"]["pdb_not_captured"], 1)
                    for field, value in (("declared_length", 4), ("written_length", 4), ("filename", "x.pdb"),
                                         ("chunks", [dict(offset=0, length=4, sha256="a" * 64)]),
                                         ("output_sha256", "a" * 64), ("second_live_pass_sha256", "a" * 64)):
                        with self.subTest(field=field):
                            invalid = copy.deepcopy(manifest)
                            invalid["captures"][0]["pdb"][field] = value
                            self.check(invalid, "FAIL", "blob is not COMPLETE")

    def test_complete_pdb_integrity_with_temporary_session(self):
        data = b"BSJBfixture"
        sha256 = hashlib.sha256(data).hexdigest()
        (self.session / "Example.pdb").write_bytes(data)
        manifest = make_manifest()
        capture = manifest["captures"][0]
        capture["resolved_owner_layout"]["image_pdb"] = 16
        capture["sources"].append("SEMANTIC_PDB_LOADER_AND_RAW_OWNER")
        capture["pdb"].update(status="COMPLETE", filename="Example.pdb", declared_length=len(data),
                              written_length=len(data), output_sha256=sha256, second_live_pass_sha256=sha256,
                              coverage_complete=True, format_valid=True, raw_layout=dict(data=8, length=16, end=24),
                              chunks=[dict(offset=0, length=len(data), sha256=sha256)])
        report = self.check(manifest)
        self.assertEqual(report["captures"][0]["pdb"]["actual_sha256"], sha256)
        (self.session / "Example.pdb").write_bytes(data + b"changed")
        self.check(manifest, "FAIL", "does not match the nonempty file length")

    def test_existing_gate_registry_and_count_failures_preserved(self):
        manifest = make_manifest()
        manifest.update(stable_window_confirmed_by_caller=False, experimental_ungated_capture=True,
                        complete_within_declared_scope=False, result_code=1)
        report = self.check(manifest)
        self.assertTrue(report["warnings"])
        manifest["registry_snapshots_unchanged"] = False
        self.check(manifest, "FAIL", "registry_snapshots_unchanged is not true")
        manifest = make_manifest()
        manifest["counts"]["union_candidates"] = 2
        self.check(manifest, "FAIL", "counts.union_candidates")


class CompareSessionTests(unittest.TestCase):
    MVID = "00000000-0000-0000-0000-000000000001"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.session = Path(temporary.name).resolve() / "current"
        self.reference = self.session.parent / "reference"
        self.session.mkdir()
        self.reference.mkdir()
        self.manifest = make_manifest()
        self.set_dll(self.session, self.manifest["captures"][0], "current.dll")
        self.reference_manifest = copy.deepcopy(self.manifest)
        self.reference_manifest["schema_version"] = 2
        self.reference_manifest["captures"][0]["capture_id"] = 99
        self.set_dll(self.reference, self.reference_manifest["captures"][0], "golden.dll")
        for name, replacement in (("read_dll_identity", self.identity), ("inspect_dotnet", self.inspect_dotnet)):
            mock = patch.object(verify_captures, name, side_effect=replacement)
            mock.start()
            self.addCleanup(mock.stop)
        self.write_manifests()

    def identity(self, data):
        identity = json.loads(data.split(b"\n", 1)[0])
        return identity["assembly_name"], str(verify_captures.uuid.UUID(identity["mvid"]))

    def inspect_dotnet(self, data, blob, result):
        name, mvid = self.identity(data)
        result.update(assembly_name=name, mvid=mvid, method_failures=[])
        if name != blob.get("assembly_name_from_metadata") or mvid != blob.get("mvid"):
            result["reasons"].append("fixture identity differs from manifest")

    def set_dll(self, directory, capture, filename, payload=b"raw bytes", name="Example", mvid=MVID):
        data = json.dumps(dict(assembly_name=name, mvid=mvid), sort_keys=True).encode("ascii") + b"\n" + payload
        (directory / filename).write_bytes(data)
        sha256 = hashlib.sha256(data).hexdigest()
        capture["name"] = name + ".dll"
        capture["dll"].update(filename=filename, assembly_name_from_metadata=name, mvid=mvid,
                              declared_length=len(data), written_length=len(data), output_sha256=sha256,
                              second_live_pass_sha256=sha256, coverage_complete=True, format_valid=True,
                              chunks=[dict(offset=0, length=len(data), sha256=sha256)])

    def write_manifests(self):
        for directory, manifest in ((self.session, self.manifest), (self.reference, self.reference_manifest)):
            captures = manifest["captures"]
            manifest["counts"].update(union_candidates=len(captures), raw_files_complete=len(captures),
                                      associated_native_assemblies=len({c["native_assembly"] for c in captures}),
                                      hot_registry_objects=sum(c["kind"] == "HOT_UPDATE" for c in captures),
                                      aot_registry_elements=sum(c["kind"] == "AOT_SUPPLEMENT" for c in captures))
            (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    def current_report(self):
        report = verify_captures.verify_session(self.session, self.manifest)
        self.assertEqual(report["status"], "PASS", report)
        return report

    def compare(self, expected="PASS", reason=None, report=None):
        if report is None:
            report = self.current_report()
        verify_captures.compare_session(self.session, self.manifest, report, self.reference)
        comparison = report["comparison"]
        self.assertEqual(comparison["status"], expected, comparison)
        self.assertEqual(report["status"], expected, comparison)
        if reason is not None:
            self.assertTrue(any(reason in error for error in comparison["errors"]), comparison)
        return report

    def run_cli(self, output=None):
        args = [str(self.session), "--compare-with", str(self.reference)]
        if output is not None:
            args += ["--output", str(output)]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_captures.main(args)
        report = json.loads(stdout.getvalue() or output.read_text(encoding="utf-8"))
        return code, report

    def test_success_rechecks_actual_bytes_and_preserves_report(self):
        original = self.current_report()
        report = self.compare(report=copy.deepcopy(original))
        self.assertEqual({key: value for key, value in report.items() if key != "comparison"}, original)
        self.assertEqual(report["comparison"]["count"], 1)
        self.assertEqual(report["comparison"]["reference_session"], str(self.reference))
        self.assertIn("runtime queries are not reverified", report["comparison"]["scope"])

    def test_same_identity_different_raw_bytes_fails(self):
        self.set_dll(self.reference, self.reference_manifest["captures"][0], "golden.dll", payload=b"new bytes")
        self.write_manifests()
        report = self.compare("FAIL", "different raw bytes")
        self.assertEqual(report["comparison"]["count"], 0)

    def test_reference_missing_or_extra_identity_fails(self):
        original = copy.deepcopy(self.reference_manifest)
        for extra in (False, True):
            with self.subTest(extra=extra):
                self.reference_manifest = copy.deepcopy(original)
                if extra:
                    capture = copy.deepcopy(original["captures"][0])
                    self.set_dll(self.reference, capture, "extra.dll", name="Extra")
                    self.reference_manifest["captures"].append(capture)
                else:
                    self.reference_manifest["captures"] = []
                self.write_manifests()
                self.compare("FAIL", "unmatched DLL")

    def test_missing_reference_session_manifest_or_dll_fails(self):
        original = self.reference
        self.reference = self.session.parent / "missing"
        self.compare("FAIL", "cannot compare reference session")
        self.reference = original
        (self.reference / "golden.dll").unlink()
        self.compare("FAIL", "captured DLL is missing")
        (self.reference / "manifest.json").unlink()
        self.compare("FAIL", "cannot compare reference session")

    def test_identity_includes_kind_assembly_and_mvid(self):
        original = copy.deepcopy(self.reference_manifest)
        for field in ("kind", "assembly_name", "mvid"):
            with self.subTest(field=field):
                self.reference_manifest = copy.deepcopy(original)
                capture = self.reference_manifest["captures"][0]
                if field == "kind":
                    capture["kind"] = "AOT_SUPPLEMENT"
                else:
                    self.set_dll(self.reference, capture, "golden.dll", name="Other" if field == "assembly_name" else "Example",
                                 mvid="00000000-0000-0000-0000-000000000002" if field == "mvid" else self.MVID)
                self.write_manifests()
                self.compare("FAIL", "unmatched DLL")

    def test_multiset_keeps_duplicates_and_ignores_ids_order_and_filenames(self):
        for directory, manifest in ((self.session, self.manifest), (self.reference, self.reference_manifest)):
            capture = copy.deepcopy(manifest["captures"][0])
            capture["capture_id"] = 2
            self.set_dll(directory, capture, "second.dll")
            manifest["captures"].append(capture)
        self.reference_manifest["captures"].reverse()
        self.write_manifests()
        report = self.compare()
        self.assertEqual(report["comparison"]["count"], 2)
        self.assertEqual(report["comparison"]["current_count"], 2)
        self.assertEqual(report["comparison"]["reference_count"], 2)

    def test_multiset_rejects_extra_duplicate_on_either_side(self):
        for directory, manifest in ((self.session, self.manifest), (self.reference, self.reference_manifest)):
            with self.subTest(side=directory.name):
                capture = copy.deepcopy(manifest["captures"][0])
                capture["capture_id"] = 2
                self.set_dll(directory, capture, "second.dll")
                manifest["captures"].append(capture)
                self.write_manifests()
                report = self.compare("FAIL", "multiplicity")
                self.assertEqual(report["comparison"]["count"], 1)
                manifest["captures"].pop()

    def test_multiset_matches_raw_variants_without_order_dependence(self):
        for directory, manifest in ((self.session, self.manifest), (self.reference, self.reference_manifest)):
            capture = copy.deepcopy(manifest["captures"][0])
            capture["capture_id"] = 2
            self.set_dll(directory, capture, "second.dll", payload=b"other raw bytes")
            manifest["captures"].append(capture)
        self.reference_manifest["captures"].reverse()
        self.write_manifests()
        self.assertEqual(self.compare()["comparison"]["count"], 2)
        self.set_dll(self.session, self.manifest["captures"][1], "second.dll")
        self.write_manifests()
        self.compare("FAIL", "different raw bytes")

    def test_reference_actual_bytes_tamper_is_detected(self):
        data = (self.reference / "golden.dll").read_bytes()
        for tampered in (data[:-1] + b"!", data + b"extra"):
            with self.subTest(length=len(tampered)):
                (self.reference / "golden.dll").write_bytes(tampered)
                self.compare("FAIL", "actual DLL SHA-256" if len(tampered) == len(data) else "actual nonempty DLL length")

    def test_current_actual_bytes_are_reread_after_verification(self):
        report = self.current_report()
        data = (self.session / "current.dll").read_bytes()
        (self.session / "current.dll").write_bytes(data[:-1] + b"!")
        self.compare("FAIL", "current DLL #0: output_sha256 differs from actual DLL SHA-256", report=report)

    def test_reference_manifest_lengths_hashes_and_identity_are_checked(self):
        original = copy.deepcopy(self.reference_manifest)
        for field, value in (("declared_length", 1), ("written_length", 1), ("output_sha256", "a" * 64),
                             ("second_live_pass_sha256", "b" * 64), ("assembly_name_from_metadata", "Forged"),
                             ("mvid", "00000000-0000-0000-0000-000000000002")):
            with self.subTest(field=field):
                self.reference_manifest = copy.deepcopy(original)
                self.reference_manifest["captures"][0]["dll"][field] = value
                self.write_manifests()
                self.compare("FAIL", "differs from")

    def test_unsafe_current_and_reference_paths_are_rejected(self):
        original = copy.deepcopy(self.reference_manifest)
        for filename in ("../outside.dll", "sub/file.dll", "C:\\outside.dll", "manifest.json", ".", "bad\x00.dll"):
            with self.subTest(filename=filename):
                self.reference_manifest = copy.deepcopy(original)
                self.reference_manifest["captures"][0]["dll"]["filename"] = filename
                self.write_manifests()
                self.compare("FAIL")
                report = self.current_report()
                self.manifest["captures"][0]["dll"]["filename"] = filename
                self.compare("FAIL", report=report)
                self.manifest["captures"][0]["dll"]["filename"] = "current.dll"

    def test_resolved_symlink_escape_is_rejected(self):
        target = self.session.parent / "outside.dll"
        target.write_bytes((self.reference / "golden.dll").read_bytes())
        link = self.reference / "escape.dll"
        original_resolve = Path.resolve

        def resolve(path, *args, **kwargs):
            return target if path == link else original_resolve(path, *args, **kwargs)

        self.reference_manifest["captures"][0]["dll"]["filename"] = link.name
        self.write_manifests()
        with patch.object(Path, "resolve", resolve):
            self.compare("FAIL", "resolves outside the session directory")

    def test_failed_current_verification_skips_reference_io(self):
        self.manifest["registry_snapshots_unchanged"] = False
        report = verify_captures.verify_session(self.session, self.manifest)
        with patch.object(Path, "read_text", side_effect=AssertionError("reference must not be read")):
            verify_captures.compare_session(self.session, self.manifest, report, self.reference)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["comparison"]["status"], "SKIPPED")
        self.assertEqual(report["comparison"]["count"], 0)

    def test_cli_success_and_comparison_failure_keep_original_fields(self):
        output = self.session / "host-verification.json"
        code, report = self.run_cli(output)
        self.assertEqual(code, 0)
        self.assertEqual(report["comparison"]["status"], "PASS")
        original_captures = copy.deepcopy(report["captures"])
        original_summary = copy.deepcopy(report["summary"])
        (self.reference / "golden.dll").write_bytes(b"tampered")
        code, report = self.run_cli(output)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["comparison"]["status"], "FAIL")
        self.assertEqual(report["captures"], original_captures)
        self.assertEqual(report["summary"], original_summary)
        self.assertIn("parsers", report)
        self.assertIn("snapshot", report)

    def test_cli_missing_reference_and_skip_exit_codes(self):
        original = self.reference
        self.reference = self.session.parent / "missing"
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(report["comparison"]["status"], "FAIL")
        self.reference = original
        self.manifest["registry_snapshots_unchanged"] = False
        self.write_manifests()
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(report["comparison"]["status"], "SKIPPED")

    def test_cli_output_cannot_overwrite_either_session_inputs(self):
        for path in (self.session / "manifest.json", self.session / "current.dll", self.reference / "manifest.json",
                     self.reference / "golden.dll", self.reference / "other-report.json"):
            with self.subTest(path=path):
                before = path.read_bytes() if path.exists() else None
                code, report = self.run_cli(path)
                self.assertEqual(code, 2)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(path.read_bytes() if path.exists() else None, before)
        alias = self.session / "alias.json"
        os.link(self.reference / "golden.dll", alias)
        before = alias.read_bytes()
        code, report = self.run_cli(alias)
        self.assertEqual(code, 2)
        self.assertEqual(alias.read_bytes(), before)
        self.manifest["registry_snapshots_unchanged"] = False
        self.write_manifests()
        code, report = self.run_cli(alias)
        self.assertEqual(code, 2)
        self.assertEqual(report["comparison"]["status"], "SKIPPED")
        self.assertEqual(alias.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
