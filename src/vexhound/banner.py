"""Terminal banner and minimal ANSI color helpers.

Colors are 24-bit truecolor and degrade to plain text when stdout is not a TTY,
when NO_COLOR is set, or when the caller disables them (vexhound --no-color). Use
color sparingly: the logo and a couple of labels, never whole paragraphs.
"""
import os
import sys

# Restrained palette; only the logo and short labels are painted.
RED = (0xE6, 0x39, 0x46)
CREAM = (0xF1, 0xFA, 0xEE)
MUTED = (0x6C, 0x75, 0x7D)
CYAN = (0xA8, 0xDA, 0xDC)
AMBER = (0xE9, 0xC4, 0x6A)      # HIGH severity / warnings
DARKRED = (0x7E, 0x14, 0x1C)    # dried-blood shading for the wordmark drip
GREEN = (0x83, 0xC0, 0x92)      # confirmed / present mitigation

# Semantic severity colors, kept separate from the brand red so the two roles
# (identity vs. risk) don't blur together.
SEV_COLORS = {"CRITICAL": RED, "HIGH": AMBER, "MEDIUM": MUTED, "LOW": MUTED, "-": MUTED}

_enabled = False

# The ASCII variant is used when the terminal cannot be trusted with unicode
# half-block glyphs (redirected output, dumb terminals, Windows pipes).
_LOGO_ASCII = [
    " /\\   /\\ ",
    "(  o.o  )",
    " >  ^  < ",
    "(_______)",
    "         ",
]

# Alert hound head, defined at 2x vertical resolution (each pixel row becomes
# half a terminal row via unicode half-block glyphs, so a 16-row bitmap prints
# as 8 lines). Only the left half + center column is authored; _mirror_row()
# reflects it, so the head can't come out lopsided from a hand-typing slip.
# '.' empty  '#' fur (RED)  'o' eye (CYAN)  'm' nose (MUTED)
_HOUND_HALF = [
    ".#.....",
    ".##....",
    ".###...",
    ".######",
    "#######",
    "#######",
    "##o####",
    "#######",
    "#######",
    ".######",
    "..#####",
    "...####",
    "....###",
    ".....##",
    ".....mm",
    "......m",
]
_PIXEL_COLORS = {"#": RED, "o": CYAN, "m": MUTED}


def _mirror_row(half):
    return half + half[:-1][::-1]


_HOUND_ROWS = [_mirror_row(row) for row in _HOUND_HALF]


def set_enabled(flag):
    global _enabled
    _enabled = bool(flag)


def stdout_supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def paint(text, rgb, bold=False):
    if not _enabled:
        return text
    r, g, b = rgb
    lead = ("\x1b[1m" if bold else "") + f"\x1b[38;2;{r};{g};{b}m"
    return lead + text + "\x1b[0m"


def _paint_cell(glyph, fg, bg=None):
    if not _enabled:
        return glyph
    r, g, b = fg
    lead = f"\x1b[38;2;{r};{g};{b}m"
    if bg is not None:
        r2, g2, b2 = bg
        lead += f"\x1b[48;2;{r2};{g2};{b2}m"
    return lead + glyph + "\x1b[0m"


def _unicode_ok():
    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in enc and getattr(sys.stdout, "isatty", lambda: False)()


def _pixel_hound():
    """Render _HOUND_ROWS to terminal lines, two pixel rows per line via
    half-block glyphs: a cell with only a top or bottom pixel set uses ▀/▄
    with just a foreground color (transparent elsewhere); a cell with both
    pixels set uses ▀ with fg=top/bg=bottom, or █ when they're the same color.
    """
    lines = []
    for i in range(0, len(_HOUND_ROWS), 2):
        top, bot = _HOUND_ROWS[i], _HOUND_ROWS[i + 1]
        cells = []
        for tch, bch in zip(top, bot):
            fg = _PIXEL_COLORS.get(tch)
            bg = _PIXEL_COLORS.get(bch)
            if fg is None and bg is None:
                cells.append(" ")
            elif fg is not None and bg is None:
                cells.append(_paint_cell("▀", fg))
            elif bg is not None and fg is None:
                cells.append(_paint_cell("▄", bg))
            elif fg == bg:
                cells.append(_paint_cell("█", fg))
            else:
                cells.append(_paint_cell("▀", fg, bg))
        lines.append("".join(cells))
    return lines


def glyphs():
    """Box-drawing set for trees and rules, with an ASCII fallback for non-utf or
    redirected output so a piped log stays readable."""
    if _unicode_ok():
        return {"tee": "├─ ", "elbow": "└─ ", "pipe": "│  ", "gap": "   ",
                "h": "─", "dot": "·", "ok": "✓", "no": "✗", "dash": "—"}
    return {"tee": "|- ", "elbow": "`- ", "pipe": "|  ", "gap": "   ",
            "h": "-", "dot": ".", "ok": "+", "no": "x", "dash": "-"}


def rule(label="", width=64):
    """A horizontal section rule, optionally with a highlighted inline label."""
    h = glyphs()["h"]
    if not label:
        return paint(h * width, MUTED)
    n = max(3, width - len(label) - 5)
    return (paint(h * 3 + " ", MUTED) + paint(label, CYAN, bold=True)
            + " " + paint(h * n, MUTED))


def severity_label(sev):
    return paint(f"{sev:<8}", SEV_COLORS.get(sev, MUTED), bold=(sev == "CRITICAL"))


# FIGlet "Bloody" wordmark for VexHound, baked as static art (no runtime figlet
# dependency). Solid glyphs are bright red, the light shading is dried-blood red,
# giving the dripping look. On a non-unicode terminal we fall back to a plain
# ASCII figlet so the name still renders.
_BLOODY = [
    ' ██▒   █▓▓█████ ▒██   ██▒ ██░ ██  ▒█████   █    ██  ███▄    █ ▓█████▄ ',
    '▓██░   █▒▓█   ▀ ▒▒ █ █ ▒░▓██░ ██▒▒██▒  ██▒ ██  ▓██▒ ██ ▀█   █ ▒██▀ ██▌',
    ' ▓██  █▒░▒███   ░░  █   ░▒██▀▀██░▒██░  ██▒▓██  ▒██░▓██  ▀█ ██▒░██   █▌',
    '  ▒██ █░░▒▓█  ▄  ░ █ █ ▒ ░▓█ ░██ ▒██   ██░▓▓█  ░██░▓██▒  ▐▌██▒░▓█▄   ▌',
    '   ▒▀█░  ░▒████▒▒██▒ ▒██▒░▓█▒░██▓░ ████▓▒░▒▒█████▓ ▒██░   ▓██░░▒████▓ ',
    '   ░ ▐░  ░░ ▒░ ░▒▒ ░ ░▓ ░ ▒ ░░▒░▒░ ▒░▒░▒░ ░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒  ▒▒▓  ▒ ',
    '   ░ ░░   ░ ░  ░░░   ░▒ ░ ▒ ░▒░ ░  ░ ▒ ▒░ ░░▒░ ░ ░ ░ ░░   ░ ▒░ ░ ▒  ▒ ',
    '     ░░     ░    ░    ░   ░  ░░ ░░ ░ ░ ▒   ░░░ ░ ░    ░   ░ ░  ░ ░  ░ ',
    '      ░     ░  ░ ░    ░   ░  ░  ░    ░ ░     ░              ░    ░    ',
    '     ░                                                         ░      ',
]

_ASCII_WORDMARK = [
    '__     __        _   _                       _ ',
    '\\ \\   / /____  _| | | | ___  _   _ _ __   __| |',
    " \\ \\ / / _ \\ \\/ / |_| |/ _ \\| | | | '_ \\ / _` |",
    '  \\ V /  __/>  <|  _  | (_) | |_| | | | | (_| |',
    '   \\_/ \\___/_/\\_\\_| |_|\\___/ \\__,_|_| |_|\\__,_|',
]

_BLOODY_SOLID = set("\u2588\u2593")   # full block, dark shade -> bright red
_BLOODY_SHADE = set("\u2592\u2591")   # medium, light shade   -> dark red

# A line-art hound mascot drawn above the wordmark (pure ASCII, so it renders in
# every terminal). Grey line work with a red collar accent and a red eye.
_HOUND = [
    "     _",
    "    / \\____",
    "   (    @\\___",
    "   /         O",
    "  /   (_____/",
    " /_____/",
]


def _paint_hound(pad):
    """Return the coloured hound rows, indented by `pad`."""
    out = [pad + "  " + paint("_____", RED)]        # collar / leash accent
    for row in _HOUND:
        if "@" in row:                              # give the eye a red pop
            head, tail = row.split("@", 1)
            out.append(pad + paint(head, MUTED) + paint("@", RED) + paint(tail, MUTED))
        else:
            out.append(pad + paint(row, MUTED))
    return out


def _paint_bloody(line):
    """Colour one Bloody row by run: solid glyphs bright red, shading dark red."""
    out, run, cls = [], "", -1
    def flush():
        if run:
            out.append(run if cls is None else paint(run, cls, bold=(cls == RED)))
    for ch in line:
        c = None if ch == " " else (DARKRED if ch in _BLOODY_SHADE else RED)
        if c != cls:
            flush()
            run, cls = "", c
        run += ch
    flush()
    return "".join(out)


def render(version, tagline="firmware memory-safety analysis over VEX IR"):
    """Startup banner: a big FIGlet VexHound wordmark, a rule, and a version line.
    Uses the coloured Bloody art on a unicode TTY, a plain ASCII figlet otherwise,
    and strips all colour when disabled."""
    lines = _paint_hound(" " * 27)                  # the hound drawing, centered
    if _unicode_ok():
        lines += [_paint_bloody(row) for row in _BLOODY]
    else:
        lines += [paint(row, RED, bold=True) for row in _ASCII_WORDMARK]
    ruler = "\u2500" if _unicode_ok() else "-"
    lines.append(paint(ruler * 60, MUTED))
    lines.append(paint("VexHound", RED, bold=True) + " " + paint("v" + version, CYAN)
                 + paint("  //  ", MUTED) + paint(tagline, MUTED))
    return "\n".join(ln.rstrip() for ln in lines).rstrip() + "\n"
