import json
import tempfile
import unittest
from pathlib import Path

from app_preferences import (
    THEMES, contrast_ratio, default_preferences, effective_palette, load_preferences,
    normalize_color, save_preferences,
)


class PreferencesTests(unittest.TestCase):
    def test_custom_colors_and_options_survive_reload(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            preferences = default_preferences()
            preferences["options"]["exclude_cpu"] = False
            preferences["options"]["mac_fmt"] = "AAAA.BBBB.CCCC"
            preferences["colors"]["dark"]["bg"] = "#112233"
            preferences["window"].update(width=1420, height=900, x=50, y=70, split_ratio=0.63)
            save_preferences(preferences, path)
            restored = load_preferences(path)
            self.assertEqual(restored, preferences)
            self.assertEqual(effective_palette(restored, "dark")["bg"], "#112233")
            self.assertEqual(effective_palette(restored, "light")["bg"], THEMES["light"]["bg"])

    def test_invalid_or_unknown_saved_values_are_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            path.write_text(json.dumps({"options": {"exclude_po": "false", "mac_fmt": "bad"},
                                        "colors": {"dark": {"bg": "red", "fg": "#AABBCC",
                                                            "unknown": "#123456"}}}), encoding="utf-8")
            restored = load_preferences(path)
            self.assertTrue(restored["options"]["exclude_po"])
            self.assertEqual(restored["options"]["mac_fmt"], "AA:BB:CC:DD:EE:FF")
            self.assertEqual(restored["colors"]["dark"], {"fg": "#aabbcc"})

    def test_invalid_window_geometry_is_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            path.write_text(json.dumps({"window": {"width": -1, "height": "huge", "x": 999999,
                                                   "split_ratio": 0.99}}), encoding="utf-8")
            self.assertEqual(load_preferences(path)["window"], default_preferences()["window"])

    def test_reset_defaults_and_hex_validation(self):
        self.assertEqual(normalize_color(" #Ab12EF "), "#ab12ef")
        for value in ("red", "#123", "#12345678", "123456", "#xxxxxx"):
            with self.assertRaises(ValueError):
                normalize_color(value)
        self.assertEqual(default_preferences()["colors"], {"dark": {}, "light": {}})
        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21)
        self.assertLess(contrast_ratio("#777777", "#888888"), 4.5)


if __name__ == "__main__":
    unittest.main()
