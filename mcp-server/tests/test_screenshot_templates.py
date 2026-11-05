"""Screenshot templates + filename/size helpers — pure, no server import."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from praetor.tools.burp_ui import _templates
from praetor.tools.burp_ui._shared import _descriptive_base, _shot_name, _size_preset


class TemplateResolveTest(unittest.TestCase):
    def test_builtin_clean_has_redaction_and_pretty(self):
        cfg = _templates.resolve("clean")
        self.assertEqual(cfg["redact"], "defaults")
        self.assertIn("browser", cfg["hide_groups"])
        self.assertEqual(cfg["view"], "pretty")

    def test_unknown_template_is_empty(self):
        self.assertEqual(_templates.resolve("nope"), {})

    def test_resolve_ignores_path_traversal_name(self):
        self.assertEqual(_templates.resolve("../../etc/passwd"), {})


class TemplateExpandTest(unittest.TestCase):
    def test_explicit_arg_overrides_template(self):
        out = _templates.expand("clean", {"view": "raw"})
        self.assertEqual(out["view"], "raw")

    def test_empty_override_keeps_template_value(self):
        out = _templates.expand("clean", {"view": "", "redact": ""})
        self.assertEqual(out["view"], "pretty")
        self.assertEqual(out["redact"], "defaults")

    def test_unknown_override_key_dropped(self):
        out = _templates.expand("", {"evil": "x", "redact": "defaults"})
        self.assertNotIn("evil", out)
        self.assertEqual(out["redact"], "defaults")


class TemplateSaveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="tmpl-"))
        self.prev = Path.cwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.prev)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_then_resolve_round_trip(self):
        r = _templates.save("mine", {"redact": "defaults", "size": "a4", "junk": 1})
        self.assertIn("saved", r)
        self.assertNotIn("junk", r["config"])      # unknown key dropped
        back = _templates.resolve("mine")
        self.assertEqual(back["size"], "a4")
        self.assertIn("mine", _templates.names()["user"])

    def test_cannot_overwrite_builtin(self):
        self.assertIn("error", _templates.save("clean", {"redact": "defaults"}))

    def test_save_rejects_no_recognised_keys(self):
        self.assertIn("error", _templates.save("x", {"junk": 1}))


class DescriptiveNameTest(unittest.TestCase):
    def test_method_path_status(self):
        d = {"method": "POST", "url": "http://h.example/api/v1/users/42", "status_code": 200}
        self.assertEqual(_descriptive_base(d, "both"), "post-api-v1-users-42-200")

    def test_query_is_excluded_from_filename(self):
        d = {"method": "GET", "url": "http://h/x?token=secret", "status_code": 200}
        base = _descriptive_base(d, "both")
        self.assertNotIn("secret", base)
        self.assertNotIn("token", base)

    def test_which_suffix_appended(self):
        d = {"method": "GET", "url": "http://h/a", "status_code": 200}
        self.assertTrue(_descriptive_base(d, "request").endswith("-request"))

    def test_missing_detail_is_blank(self):
        self.assertEqual(_descriptive_base(None, "both"), "")


class ShotNameHintTest(unittest.TestCase):
    def test_name_hint_replaces_burp_lead(self):
        n = _shot_name("msg-both", "", "", "", "20260101-000000-0", "post-api-users-200")
        self.assertTrue(n.startswith("post-api-users-200-"))
        self.assertNotIn("burp-", n)

    def test_no_hint_keeps_burp_lead(self):
        n = _shot_name("msg-both", "", "", "", "20260101-000000-0")
        self.assertTrue(n.startswith("burp-msg-both-"))


class SizePresetTest(unittest.TestCase):
    def test_presets(self):
        self.assertEqual(_size_preset("a4"), (1240, 1754))
        self.assertEqual(_size_preset("letter"), (1275, 1650))
        self.assertEqual(_size_preset("fit"), (0, 4000))
        self.assertEqual(_size_preset(""), (0, 0))
        self.assertEqual(_size_preset("bogus"), (0, 0))


if __name__ == "__main__":
    unittest.main()
