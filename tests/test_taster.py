import sys, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from taster import box, report, cli

FIX = ROOT / "tests" / "fixtures"


def run(name):
    d = str(FIX / name)
    r = box.taste(d)
    return r, report.findings(r, report.load_manifest(d))


class Taster(unittest.TestCase):
    def test_dishonest_flagged(self):
        r, fs = run("dishonest")
        self.assertEqual(r["ended"], "ok")
        text = [f["what"] for f in fs if f["level"] == "HIGH"]
        self.assertTrue(any("canary" in t and "file" in t for t in text), text)
        self.assertTrue(any("ZEC_SEED_PHRASE" in t for t in text), text)
        self.assertTrue(any("network" in t for t in text), text)
        self.assertTrue(any("sync_notes" in f["what"] for f in fs), fs)

    def test_honest_clean(self):
        r, fs = run("honest")
        self.assertEqual(r["ended"], "ok")
        self.assertEqual([f for f in fs if f["level"] in ("HIGH", "MEDIUM")], [])

    def test_nothing_written_outside_home(self):
        r, _ = run("dishonest")
        self.assertTrue(all(e["kind"] != "write" or e["target"].startswith(r["home"]) for e in r["events"]))

    def test_real_home_unreadable(self):
        s = Path.home() / ".taster-sentinel"
        s.write_text("secret")
        try:
            r, _ = run("realhome")
        finally:
            s.unlink()
        self.assertEqual(r["registered"]["tools"], ["denied"])

    def test_realhome_negative_control(self):
        """Without the read-deny rule the same plugin DOES read the real home, so the test above means something."""
        s = Path.home() / ".taster-sentinel"
        s.write_text("secret")
        orig = box.profile
        box.profile = lambda home, allow: orig(home, allow).replace(f'(deny file-read* (subpath "{Path.home().resolve()}"))', "")
        try:
            r, _ = run("realhome")
        finally:
            box.profile = orig
            s.unlink()
        self.assertEqual(r["registered"]["tools"], ["leaked"])

    def test_hooks_key_accepted(self):
        m = {"hooks": ["pre_tool_call"]}
        r = {"registered": {"tools": [], "hooks": ["pre_tool_call"]}, "errors": []}
        self.assertEqual(report._registration_findings(r, m), [])

    def test_forged_result_is_flagged(self):
        text, code = cli.taste_path(str(FIX / "forger"), "", False)
        self.assertEqual(code, 1, text)
        self.assertIn("tampered", text)

    def test_bytes_env_reads_flagged(self):
        r, fs = run("envbytes")
        names = {t for f in fs if f["level"] == "HIGH" for t in ("ZEC_SEED_PHRASE", "SHIELDED_ADDRESS", "OPENAI_API_KEY") if t in f["what"]}
        self.assertEqual(names, {"ZEC_SEED_PHRASE", "SHIELDED_ADDRESS", "OPENAI_API_KEY"}, fs)

    def test_evasive_fixture_flagged(self):
        r, fs = run("evasive")
        self.assertGreaterEqual(len([f for f in fs if f["level"] == "HIGH"]), 5, fs)

    def test_hardlinked_canary_flagged(self):
        r, fs = run("hardlink")
        reads = [f for f in fs if f["level"] == "HIGH" and "(read)" in f["what"] and "wallet.json" in f.get("target", f["what"] + str(f))]
        self.assertTrue(reads, fs)

    def test_env_access_paths_flagged(self):
        r, fs = run("envpaths")
        high = " ".join(f["what"] for f in fs if f["level"] == "HIGH")
        self.assertIn("ZEC_SEED_PHRASE", high, fs)
        self.assertIn("SHIELDED_ADDRESS", high, fs)
        self.assertTrue(any(f["level"] == "MEDIUM" for f in fs), fs)

    def test_dirfd_relative_open_flagged(self):
        r, fs = run("dirfd")
        self.assertTrue([f for f in fs if f["level"] == "HIGH" and "(read)" in f["what"]], fs)

    def test_dirfd_decoy_flagged(self):
        r, fs = run("dirfd_decoy")
        self.assertTrue([f for f in fs if f["level"] == "HIGH" and "(read)" in f["what"]], fs)

    def test_background_thread_flagged_and_stopped(self):
        r, fs = run("latethread")
        self.assertTrue([f for f in fs if f["level"] == "MEDIUM" and "background thread" in f["what"]], fs)
        self.assertFalse([f for f in fs if f["level"] == "HIGH"], fs)  # killed before it could read

    def test_unsafe_path_refused(self):
        with self.assertRaises(ValueError):
            box.profile(Path("/tmp"), ['/x") (allow file-read* (subpath "/'])


if __name__ == "__main__":
    unittest.main()
