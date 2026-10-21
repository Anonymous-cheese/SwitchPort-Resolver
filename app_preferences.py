"""Validated, per-user appearance and resolver preferences."""

import json
import os
import re
import tempfile
from pathlib import Path


THEMES = {
    "light": {
        "bg": "#f0f0f0", "panel_bg": "#f0f0f0", "fg": "#000000",
        "muted_fg": "#333333", "entry_bg": "#ffffff",
        "button_bg": "#f5f5f5", "button_active": "#e5e5e5",
        "button_pressed": "#d9d9d9", "border": "#b8b8b8",
        "tree_bg": "#ffffff", "tree_alt": "#f7f7f7",
        "heading_bg": "#eeeeee", "select_bg": "#0078d7",
        "select_fg": "#ffffff", "disabled_fg": "#6f6f6f",
        "insert": "#000000", "error_fg": "#b42318",
        "tooltip_bg": "#343c46", "tooltip_fg": "#ffffff",
    },
    "dark": {
        "bg": "#1f2227", "panel_bg": "#252a31", "fg": "#f1f5f9",
        "muted_fg": "#cbd5e1", "entry_bg": "#111827",
        "button_bg": "#303741", "button_active": "#3b4450",
        "button_pressed": "#46515f", "border": "#46515f",
        "tree_bg": "#151a20", "tree_alt": "#1d232b",
        "heading_bg": "#2b323b", "select_bg": "#0f766e",
        "select_fg": "#ffffff", "disabled_fg": "#8b95a3",
        "insert": "#f8fafc", "error_fg": "#ef7777",
        "tooltip_bg": "#343c46", "tooltip_fg": "#f1f5f9",
    },
}

COLOR_LABELS = {
    "bg": "Window background", "panel_bg": "Panel / tab background",
    "fg": "Main text", "muted_fg": "Secondary text",
    "entry_bg": "Inputs / text areas", "button_bg": "Buttons",
    "button_active": "Button hover", "button_pressed": "Button pressed",
    "border": "Borders / splitter", "tree_bg": "Result rows",
    "tree_alt": "Alternating rows", "heading_bg": "Table headings",
    "select_bg": "Accent / selection", "select_fg": "Selected text",
    "disabled_fg": "Disabled text", "insert": "Text cursor",
    "error_fg": "Error text", "tooltip_bg": "Tooltip background",
    "tooltip_fg": "Tooltip text",
}

MAC_FORMATS = ("As seen", "AA:BB:CC:DD:EE:FF", "AAAA.BBBB.CCCC")
DEFAULT_OPTIONS = {
    "dark_mode": True, "auto_lookup_after_drop": True,
    "mac_fmt": "AA:BB:CC:DD:EE:FF", "exclude_po": True,
    "exclude_cpu": True, "only_ip": False,
}
DEFAULT_WINDOW = {"width": 1200, "height": 800, "x": None, "y": None, "split_ratio": 0.52}
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def settings_path():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = Path.home() / ".config"
    return Path(base) / "SwitchPort Resolver" / "settings.json"


def default_preferences():
    return {"options": DEFAULT_OPTIONS.copy(), "colors": {"dark": {}, "light": {}},
            "window": DEFAULT_WINDOW.copy()}


def normalize_color(value):
    if not isinstance(value, str) or not HEX_COLOR.fullmatch(value.strip()):
        raise ValueError("Use a 6-digit hex color, such as #1F2227.")
    return value.strip().lower()


def contrast_ratio(first, second):
    """Return relative luminance contrast for two validated #RRGGBB colors."""
    def luminance(value):
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        channels = [channel / 12.92 if channel <= 0.04045 else
                    ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return sum(channel * weight for channel, weight in zip(channels, (0.2126, 0.7152, 0.0722)))
    lighter, darker = sorted((luminance(normalize_color(first)), luminance(normalize_color(second))), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def effective_palette(preferences, theme):
    return {**THEMES[theme], **preferences["colors"][theme]}


def load_preferences(path=None):
    preferences = default_preferences()
    try:
        data = json.loads(Path(path or settings_path()).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return preferences
        options = data.get("options", {})
        if isinstance(options, dict):
            for key, default in DEFAULT_OPTIONS.items():
                value = options.get(key)
                if isinstance(default, bool) and type(value) is bool:
                    preferences["options"][key] = value
                elif key == "mac_fmt" and value in MAC_FORMATS:
                    preferences["options"][key] = value
        colors = data.get("colors", {})
        if isinstance(colors, dict):
            for theme in THEMES:
                overrides = colors.get(theme, {})
                if not isinstance(overrides, dict):
                    continue
                for key, value in overrides.items():
                    if key in THEMES[theme]:
                        try:
                            preferences["colors"][theme][key] = normalize_color(value)
                        except ValueError:
                            pass
        window = data.get("window", {})
        if isinstance(window, dict):
            for key in ("width", "height"):
                value = window.get(key)
                if type(value) is int and 600 <= value <= 10000:
                    preferences["window"][key] = value
            for key in ("x", "y"):
                value = window.get(key)
                if type(value) is int and -10000 <= value <= 10000:
                    preferences["window"][key] = value
            ratio = window.get("split_ratio")
            if type(ratio) in (int, float) and 0.15 <= ratio <= 0.85:
                preferences["window"]["split_ratio"] = float(ratio)
    except (OSError, ValueError, TypeError):
        pass
    return preferences


def save_preferences(preferences, path=None):
    path = Path(path or settings_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix="settings-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(preferences, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
