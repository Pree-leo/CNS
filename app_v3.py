"""
File Integrity Verification Using the Digital Signature Algorithm (DSA)
CNS Project - Version 3
Ultra-Smooth Aesthetic UI Theme

Install:  pip install cryptography
Run:      python app_v3.py
"""

import os
import json
import hashlib
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.font import Font

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.exceptions import InvalidSignature

# ======================================================================
# PATHS & CONFIGURATION
# ======================================================================
DATA_DIR = os.path.join(os.path.expanduser("~"), "DSA_Verifier_Data")
HISTORY_FILE = os.path.join(DATA_DIR, "verification_history.json")

# ======================================================================
# ULTRA-SMOOTH COLOR PALETTE
# ======================================================================
# Surfaces & Backgrounds
BG_APP = "#f7f9fc"              # Ultra-smooth clean soft slate-50
CARD_BG = "#ffffff"             # Pure white card surface
CARD_BORDER = "#e2e8f0"         # Gentle hairline border
CARD_BORDER_HOVER = "#cbd5e1"
HEADER_C1 = "#182455"           # Deep elegant navy
HEADER_C2 = "#2b47aa"           # Smooth royal cobalt
NAV_TRACK = "#edf2f7"           # Smooth navigation pill track

# Typography Colors
TEXT_MAIN = "#192238"           # Deep readable slate
TEXT_SUB = "#4c5973"            # Balanced muted slate
TEXT_MUTED = "#738096"          # Secondary soft label text

# Accent & Status Colors
PRIMARY_BLUE = "#2454db"        # Smooth royal blue
PRIMARY_HOVER = "#1b42b5"       # Deeper blue on hover
PRIMARY_LIGHT = "#eef3ff"       # Soft pastel blue for badges

SUCCESS_GREEN = "#15803d"       # Natural emerald green
SUCCESS_BG = "#f0fdf4"          # Soft pastel green card
SUCCESS_BORDER = "#bbf7d0"      # Soft emerald outline

ALERT_RED = "#b91c1c"           # Natural ruby red
ALERT_BG = "#fef2f2"            # Soft pastel red card
ALERT_BORDER = "#fecaca"        # Soft ruby outline

PILL_BG = "#f1f4f9"             # Soft property pill background
PILL_BORDER = "#dde3ea"


# ======================================================================
# CRYPTOGRAPHIC CORE ENGINE (100% Preserved)
# ======================================================================

def file_sha256(path):
    """SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def key_fingerprint(public_key):
    """Short SHA-256 fingerprint of a public key."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(der).hexdigest()
    return ":".join(fp[i:i + 4] for i in range(0, 32, 4))


def is_encrypted(pem_path):
    with open(pem_path, "rb") as f:
        return b"ENCRYPTED" in f.read()


def generate_keys(folder, passphrase=None):
    """Create a 2048-bit DSA key pair. Optionally encrypt the private key."""
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    priv_path = os.path.join(folder, "private_key.pem")
    pub_path = os.path.join(folder, "public_key.pem")
    with open(priv_path, "wb") as f:
        f.write(private_pem)
    with open(pub_path, "wb") as f:
        f.write(public_pem)

    params = public_key.public_numbers().parameter_numbers
    return {
        "private_path": priv_path,
        "public_path": pub_path,
        "key_size": private_key.key_size,
        "q_bits": params.q.bit_length(),
        "encrypted": bool(passphrase),
        "fingerprint": key_fingerprint(public_key),
    }


def sign_file(file_path, private_key_path, passphrase=None):
    """Sign a file. Saves <file>.sig and a small <file>.sig.info manifest."""
    with open(private_key_path, "rb") as f:
        pem = f.read()
    private_key = serialization.load_pem_private_key(
        pem, password=passphrase.encode() if passphrase else None)
    if not isinstance(private_key, dsa.DSAPrivateKey):
        raise ValueError("The selected key is not a DSA private key.")

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(data, hashes.SHA256())
    r, s = decode_dss_signature(signature)
    digest = hashlib.sha256(data).hexdigest()
    fingerprint = key_fingerprint(private_key.public_key())

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    info = {
        "file": os.path.basename(file_path),
        "sha256": digest,
        "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "key_fingerprint": fingerprint,
    }
    with open(sig_path + ".info", "w") as f:
        json.dump(info, f, indent=2)

    return {"sig_path": sig_path, "sha256": digest, "r": r, "s": s,
            "fingerprint": fingerprint, "size": len(data)}


def verify_file(file_path, sig_path, public_key_path):
    """Verify a signature. Returns dictionary with result and parameters."""
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    if not isinstance(public_key, dsa.DSAPublicKey):
        raise ValueError("The selected key is not a DSA public key.")

    with open(file_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    current_hash = hashlib.sha256(data).hexdigest()

    try:
        r, s = decode_dss_signature(signature)
    except ValueError:
        r, s = None, None

    try:
        public_key.verify(signature, data, hashes.SHA256())
        valid = True
    except InvalidSignature:
        valid = False

    signed_hash = None
    info_path = sig_path + ".info"
    if os.path.exists(info_path):
        try:
            with open(info_path, "r") as f:
                signed_hash = json.load(f).get("sha256")
        except (json.JSONDecodeError, OSError):
            pass

    return {"valid": valid, "current_hash": current_hash, "signed_hash": signed_hash,
            "r": r, "s": s, "fingerprint": key_fingerprint(public_key)}


# ======================================================================
# HISTORY STORAGE
# ======================================================================

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def add_history(file_name, result, sha):
    history = load_history()
    history.append({
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file": file_name,
        "result": result,
        "sha256": sha,
    })
    save_history(history)


# ======================================================================
# SMOOTH VECTOR DRAWING HELPERS
# ======================================================================

def draw_smooth_pill(canvas, x1, y1, x2, y2, r=12, fill="#2454db", outline=""):
    """Draws a smooth rounded pill polygon with Bezier-interpolated corners."""
    pts = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1
    ]
    return canvas.create_polygon(pts, smooth=True, fill=fill, outline=outline)


def draw_shield(canvas, cx, cy, size, fill, check="white", outline="", width=0):
    """Draws a smooth shield with an embedded checkmark."""
    pts = [(-0.85, -0.65), (0, -1), (0.85, -0.65), (0.85, 0.1),
           (0.5, 0.65), (0, 1), (-0.5, 0.65), (-0.85, 0.1)]
    flat = []
    for x, y in pts:
        flat += [cx + x * size, cy + y * size]
    canvas.create_polygon(flat, fill=fill, outline=outline, width=width, joinstyle="round")
    if check:
        canvas.create_line(cx - 0.38 * size, cy + 0.05 * size,
                           cx - 0.1 * size, cy + 0.35 * size,
                           cx + 0.42 * size, cy - 0.28 * size,
                           fill=check, width=max(2, int(size * 0.17)),
                           capstyle="round", joinstyle="round")


def draw_warning_shield(canvas, cx, cy, size, fill=ALERT_RED, mark="white"):
    """Draws a smooth warning shield with an exclamation mark."""
    pts = [(-0.85, -0.65), (0, -1), (0.85, -0.65), (0.85, 0.1),
           (0.5, 0.65), (0, 1), (-0.5, 0.65), (-0.85, 0.1)]
    flat = []
    for x, y in pts:
        flat += [cx + x * size, cy + y * size]
    canvas.create_polygon(flat, fill=fill, outline="", joinstyle="round")
    canvas.create_line(cx, cy - 0.32 * size, cx, cy + 0.08 * size,
                       fill=mark, width=max(2, int(size * 0.17)), capstyle="round")
    canvas.create_oval(cx - 0.08 * size, cy + 0.24 * size,
                      cx + 0.08 * size, cy + 0.40 * size, fill=mark, outline="")


# ======================================================================
# SMOOTH PILL BUTTON WIDGET & TRANSITION ENGINE
# ======================================================================

def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def rgb_to_hex(rgb):
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(v))) for v in rgb)


def lerp_color(c1, c2, t):
    if not c1 or not c2 or not c1.startswith("#") or not c2.startswith("#"):
        return c2
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    return rgb_to_hex((r1 + (r2 - r1) * t, g1 + (g2 - g1) * t, b1 + (b2 - b1) * t))


def darken_color(c, factor=0.20):
    if not c or not c.startswith("#"):
        return c
    r, g, b = hex_to_rgb(c)
    return rgb_to_hex((r * (1 - factor), g * (1 - factor), b * (1 - factor)))


class SmoothButton(tk.Canvas):
    """A smooth, modern pill-shaped button with animated click and hover transitions."""

    def __init__(self, parent, text, command=None, bg_color=PRIMARY_BLUE,
                 hover_color=PRIMARY_HOVER, pressed_color=None, text_color="#ffffff",
                 font=("Segoe UI", 10, "bold"), padx=22, pady=7, radius=13,
                 outline_color="", hover_outline=""):
        self.cmd = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.pressed_color = pressed_color or darken_color(hover_color, 0.22)
        self.text_color = text_color
        self.radius = radius
        self.outline_color = outline_color
        self.hover_outline = hover_outline
        self.font = Font(family=font[0], size=font[1], weight=font[2] if len(font) > 2 else "normal")

        tw = self.font.measure(text)
        w = max(tw + padx * 2, 75)
        h = max(self.font.metrics("linespace") + pady * 2, 34)

        parent_bg = parent.cget("bg") if hasattr(parent, "cget") else BG_APP
        super().__init__(parent, width=w, height=h, bg=parent_bg, highlightthickness=0, bd=0, cursor="hand2")
        self.w, self.h = w, h
        self.text = text
        self.current_fill = bg_color
        self.current_outline = outline_color
        self.offset = 0
        self.anim_job = None
        self.is_hovered = False
        self.is_pressed = False
        self.redraw()

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def redraw(self):
        self.delete("all")
        dy = self.offset
        draw_smooth_pill(self, 2, 2 + dy, self.w - 2, self.h - 2 + dy,
                         r=self.radius, fill=self.current_fill, outline=self.current_outline)
        self.create_text(self.w // 2, self.h // 2 + dy, text=self.text,
                         fill=self.text_color, font=self.font)

    def animate(self, target_fill, target_offset=0, steps=3, delay=14, callback=None):
        if self.anim_job:
            self.after_cancel(self.anim_job)
            self.anim_job = None

        start_fill = self.current_fill
        start_offset = self.offset

        def _step(s):
            if not self.winfo_exists():
                return
            t = s / steps
            eased_t = t * (2 - t)
            self.current_fill = lerp_color(start_fill, target_fill, eased_t)
            self.offset = start_offset + (target_offset - start_offset) * eased_t
            self.redraw()
            if s < steps:
                self.anim_job = self.after(delay, lambda: _step(s + 1))
            else:
                self.anim_job = None
                self.current_fill = target_fill
                self.offset = target_offset
                self.redraw()
                if callback:
                    callback()

        _step(1)

    def _on_enter(self, e):
        self.is_hovered = True
        if self.hover_outline:
            self.current_outline = self.hover_outline
        if not self.is_pressed:
            self.animate(self.hover_color, target_offset=0, steps=3, delay=14)

    def _on_leave(self, e):
        self.is_hovered = False
        self.is_pressed = False
        self.current_outline = self.outline_color
        self.animate(self.bg_color, target_offset=0, steps=3, delay=14)

    def _on_press(self, e):
        self.is_pressed = True
        self.animate(self.pressed_color, target_offset=1.5, steps=2, delay=10)

    def _on_release(self, e):
        if not self.is_pressed:
            return
        self.is_pressed = False
        target = self.hover_color if self.is_hovered else self.bg_color
        self.animate(target, target_offset=0, steps=3, delay=14, callback=self.cmd)


class SmoothTabButton(SmoothButton):
    """Smooth pill tab button for segmented navigation bar."""

    def __init__(self, parent, text, command=None, is_active=False):
        self.is_active = is_active
        bg = "#ffffff" if is_active else NAV_TRACK
        hover = "#ffffff" if is_active else "#dfe6f0"
        pressed = "#f1f5f9" if is_active else "#cbd5e1"
        fg = PRIMARY_BLUE if is_active else TEXT_SUB
        outline = CARD_BORDER if is_active else ""
        super().__init__(parent, text, command=command, bg_color=bg,
                         hover_color=hover, pressed_color=pressed, text_color=fg,
                         font=("Segoe UI", 10, "bold"), padx=16, pady=6, radius=12,
                         outline_color=outline)

    def set_active(self, active):
        self.is_active = active
        self.bg_color = "#ffffff" if active else NAV_TRACK
        self.hover_color = "#ffffff" if active else "#dfe6f0"
        self.pressed_color = "#f1f5f9" if active else "#cbd5e1"
        self.text_color = PRIMARY_BLUE if active else TEXT_SUB
        self.outline_color = CARD_BORDER if active else ""
        self.current_outline = self.outline_color
        target = self.bg_color if not self.is_hovered else self.hover_color
        self.animate(target, target_offset=0, steps=3, delay=14)


# ======================================================================
# SMOOTH GRADIENT HEADER (Original Title Restored)
# ======================================================================

class SmoothGradientHeader(tk.Canvas):
    """Ultra-smooth blue gradient banner displaying the original app title."""

    def __init__(self, parent, height=66, c1=HEADER_C1, c2=HEADER_C2):
        super().__init__(parent, height=height, highlightthickness=0, bd=0)
        self.c1, self.c2 = c1, c2
        self.bind("<Configure>", self.redraw)

    def redraw(self, event=None):
        self.delete("all")
        w, h = max(self.winfo_width(), 2), self.winfo_height()
        r1, g1, b1 = [v // 256 for v in self.winfo_rgb(self.c1)]
        r2, g2, b2 = [v // 256 for v in self.winfo_rgb(self.c2)]
        step = 2
        for x in range(0, w, step):
            t = x / (w - 1)
            col = "#%02x%02x%02x" % (int(r1 + (r2 - r1) * t),
                                     int(g1 + (g2 - g1) * t),
                                     int(b1 + (b2 - b1) * t))
            self.create_rectangle(x, 0, x + step, h, fill=col, outline=col)

        # Smooth halo ring around shield
        self.create_oval(18, h // 2 - 20, 58, h // 2 + 20, fill="#233575", outline="")
        draw_shield(self, 38, h // 2, 18, "white", check=self.c1)

        # Original Main Title Restored
        self.create_text(70, h // 2 - 10, text="DSA File Integrity Verifier", anchor="w",
                         fill="white", font=("Segoe UI", 16, "bold"))
        self.create_text(70, h // 2 + 13, text="Digital signatures for tamper detection",
                         anchor="w", fill="#d5deff", font=("Segoe UI", 9))

        # Smooth status capsule
        pw, ph = 140, 26
        px, py = w - pw - 24, h // 2 - ph // 2
        draw_smooth_pill(self, px, py, px + pw, py + ph, r=13, fill="#1e327a", outline="#3b52ad")
        self.create_oval(px + 14, h // 2 - 3, px + 20, h // 2 + 3, fill="#34d399", outline="")
        self.create_text(px + 28, h // 2, text="Engine Ready", anchor="w",
                         fill="#e2e8f0", font=("Segoe UI", 9, "bold"))


# ======================================================================
# APPLICATION GUI
# ======================================================================

class App:
    def __init__(self, root):
        self.root = root
        root.title("DSA File Integrity Verifier")
        root.geometry("920x760")
        root.minsize(860, 700)
        root.configure(bg=BG_APP)

        self.last_hash = ""
        self.current_tab = 0

        self.setup_styles()

        # 1. Smooth Gradient Header
        self.header = SmoothGradientHeader(root)
        self.header.pack(fill="x", side="top")

        # 2. Smooth Segmented Pill Navigation Bar
        self.build_navigation()

        # 3. Main Body Container
        self.container = tk.Frame(root, bg=BG_APP)
        self.container.pack(fill="both", expand=True, padx=22, pady=(14, 8))

        # Bottom Dock / Status Bar
        self.build_status_bar()

        # Build Pages
        self.pages = []
        self.build_overview_tab()
        self.build_keys_tab()
        self.build_sign_tab()
        self.build_verify_tab()
        self.build_history_tab()

        # Show initial tab
        self.show_tab(0)

    def setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=BG_APP)
        style.configure("TLabel", background=BG_APP, font=("Segoe UI", 10), foreground=TEXT_MAIN)
        style.configure("Treeview",
                        background="white",
                        foreground=TEXT_MAIN,
                        rowheight=28,
                        fieldbackground="white",
                        font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                        background="#f1f4f9",
                        foreground=TEXT_SUB,
                        font=("Segoe UI", 9, "bold"),
                        relief="flat")
        style.map("Treeview.Heading", background=[("active", "#e2e8f0")])

    # ---------- Smooth Pill Navigation Bar ----------
    def build_navigation(self):
        nav_wrap = tk.Frame(self.root, bg=BG_APP)
        nav_wrap.pack(fill="x", padx=22, pady=(12, 0))

        bar = tk.Frame(nav_wrap, bg=NAV_TRACK, padx=4, pady=4)
        bar.pack(anchor="w")

        self.tab_buttons = []
        tabs_info = [
            (" Overview ", 0),
            (" 1. Generate Keys ", 1),
            (" 2. Sign File ", 2),
            (" 3. Verify Signature ", 3),
            (" History ", 4),
        ]

        for text, idx in tabs_info:
            btn = SmoothTabButton(bar, text=text,
                                  command=lambda i=idx: self.show_tab(i),
                                  is_active=(idx == 0))
            btn.pack(side="left", padx=2)
            self.tab_buttons.append(btn)

    def show_tab(self, idx):
        self.current_tab = idx
        for i, page in enumerate(self.pages):
            if i == idx:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()

        # Update smooth tab states
        for i, btn in enumerate(self.tab_buttons):
            btn.set_active(i == idx)

        if idx == 0:
            self.refresh_overview_metrics()
        elif idx == 4:
            self.refresh_history()

    # ---------- Status Dock ----------
    def build_status_bar(self):
        dock_wrap = tk.Frame(self.root, bg=BG_APP)
        dock_wrap.pack(fill="x", side="bottom")

        dock_border = tk.Frame(dock_wrap, bg=CARD_BORDER, height=1)
        dock_border.pack(fill="x")

        dock = tk.Frame(dock_wrap, bg="#ffffff", height=32, padx=22)
        dock.pack(fill="x")

        self.status = tk.StringVar(value="Ready")

        status_left = tk.Frame(dock, bg="#ffffff")
        status_left.pack(side="left", pady=6)

        self.status_dot = tk.Label(status_left, text="\u25cf", fg="#10b981",
                                   bg="#ffffff", font=("Segoe UI", 9))
        self.status_dot.pack(side="left", padx=(0, 6))

        tk.Label(status_left, textvariable=self.status, font=("Segoe UI", 9),
                 fg=TEXT_SUB, bg="#ffffff").pack(side="left")

        tk.Label(dock, text="DSA 2048-bit  \u2022  SHA-256", font=("Segoe UI", 9),
                 fg=TEXT_MUTED, bg="#ffffff").pack(side="right", pady=6)

    def busy(self, msg):
        self.status.set(msg)
        self.status_dot.config(fg=PRIMARY_BLUE)
        self.root.update_idletasks()

    def set_ready(self, msg="Ready"):
        self.status.set(msg)
        self.status_dot.config(fg="#10b981")

    # ---------- Smooth Card & Input Helpers ----------
    def create_card(self, parent, title=None, subtitle=None, badge=None,
                    badge_color=PRIMARY_BLUE, badge_bg=PRIMARY_LIGHT, padx=20, pady=18):
        card = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER,
                        highlightthickness=1, padx=padx, pady=pady)

        if title or badge:
            head = tk.Frame(card, bg=CARD_BG)
            head.pack(fill="x", pady=(0, 10))

            if badge:
                b_frame = tk.Frame(head, bg=badge_bg, highlightbackground=CARD_BORDER,
                                   highlightthickness=1, padx=9, pady=2)
                b_frame.pack(side="left", padx=(0, 10))
                tk.Label(b_frame, text=badge, font=("Segoe UI", 8, "bold"),
                         fg=badge_color, bg=badge_bg).pack()

            if title:
                tk.Label(head, text=title, font=("Segoe UI", 12, "bold"),
                         fg=TEXT_MAIN, bg=CARD_BG).pack(side="left")

        if subtitle:
            tk.Label(card, text=subtitle, font=("Segoe UI", 9),
                     fg=TEXT_SUB, bg=CARD_BG, wraplength=760, justify="left").pack(anchor="w", pady=(0, 10))

        return card

    def create_input_row(self, parent, label_text, var, browse_kind="open", filetypes=None):
        row = tk.Frame(parent, bg=CARD_BG)
        row.pack(fill="x", pady=6)

        lbl = tk.Label(row, text=label_text, font=("Segoe UI", 9, "bold"),
                       fg=TEXT_MAIN, bg=CARD_BG, width=17, anchor="w")
        lbl.pack(side="left")

        entry_frame = tk.Frame(row, bg=CARD_BG, highlightbackground=CARD_BORDER,
                               highlightthickness=1)
        entry_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))

        entry = tk.Entry(entry_frame, textvariable=var, font=("Segoe UI", 10),
                         relief="flat", bg=CARD_BG, fg=TEXT_MAIN, insertbackground=TEXT_MAIN)
        entry.pack(fill="x", padx=10, pady=7)

        # Smooth focus highlight
        def on_focus_in(e):
            entry_frame.config(highlightbackground=PRIMARY_BLUE)

        def on_focus_out(e):
            entry_frame.config(highlightbackground=CARD_BORDER)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

        btn = SmoothButton(row, "Browse...",
                           command=lambda: self.browse(var, browse_kind, filetypes),
                           bg_color="#f1f5f9", hover_color="#e2e8f0", text_color=TEXT_MAIN,
                           font=("Segoe UI", 9), padx=14, pady=5, radius=11,
                           outline_color=CARD_BORDER)
        btn.pack(side="right")
        return row

    def browse(self, var, kind, filetypes=None):
        if kind == "dir":
            p = filedialog.askdirectory(title="Select Destination Folder")
        else:
            p = filedialog.askopenfilename(title="Select Target File",
                                           filetypes=filetypes or [("All files", "*.*")])
        if p:
            var.set(p)

    def create_property_box(self, parent):
        box = tk.Frame(parent, bg=PILL_BG, highlightbackground=PILL_BORDER,
                       highlightthickness=1, padx=16, pady=14)
        box.pack(fill="both", expand=True, pady=(6, 0))
        return box

    # ==================================================================
    # TAB 0: OVERVIEW
    # ==================================================================
    def build_overview_tab(self):
        page = tk.Frame(self.container, bg=BG_APP)
        self.pages.append(page)

        # Top Metric Stat Tiles (100% computed from real data)
        metric_row = tk.Frame(page, bg=BG_APP)
        metric_row.pack(fill="x", pady=(0, 14))

        for col in range(4):
            metric_row.columnconfigure(col, weight=1, uniform="stat")

        self.m_total = tk.StringVar(value="0")
        self.m_valid = tk.StringVar(value="0")
        self.m_tamper = tk.StringVar(value="0")

        self.build_stat_tile(metric_row, 0, "Total Verifications", self.m_total,
                             "Logged inspections", PRIMARY_BLUE)
        self.build_stat_tile(metric_row, 1, "Authentic Files", self.m_valid,
                             "Passed verification", SUCCESS_GREEN)
        self.build_stat_tile(metric_row, 2, "Tamper Alerts", self.m_tamper,
                             "Modified / invalid", ALERT_RED)
        self.build_stat_tile(metric_row, 3, "Algorithm", tk.StringVar(value="DSA 2048"),
                             "SHA-256 Digest", "#4f46e5")

        # 3 Smooth Step Workflow Cards
        cards_row = tk.Frame(page, bg=BG_APP)
        cards_row.pack(fill="x", pady=(0, 14))
        for col in range(3):
            cards_row.columnconfigure(col, weight=1, uniform="flow_card")

        self.build_step_card(
            cards_row, 0, "1", "Generate Keys",
            "Create a 2048-bit DSA private and public key pair. Keep your private key secret and share the public key.",
            "Generate Keys  \u2192", 1, PRIMARY_BLUE
        )
        self.build_step_card(
            cards_row, 1, "2", "Sign a File",
            "Generate a mathematical digital signature for any file using your private key and SHA-256.",
            "Sign File  \u2192", 2, "#6366f1"
        )
        self.build_step_card(
            cards_row, 2, "3", "Verify Integrity",
            "Confirm that a file is genuine and has not been altered since it was signed.",
            "Verify File  \u2192", 3, SUCCESS_GREEN
        )

        # Smooth Trust Flow Banner
        flow_card = tk.Frame(page, bg=CARD_BG, highlightbackground=CARD_BORDER,
                             highlightthickness=1, padx=18, pady=14)
        flow_card.pack(fill="x")

        flow_inner = tk.Frame(flow_card, bg=CARD_BG)
        flow_inner.pack(fill="x")

        icon_c = tk.Canvas(flow_inner, width=28, height=28, bg=CARD_BG, highlightthickness=0)
        icon_c.pack(side="left", padx=(0, 12))
        draw_shield(icon_c, 14, 14, 11, PRIMARY_BLUE)

        f_text = tk.Frame(flow_inner, bg=CARD_BG)
        f_text.pack(side="left")

        tk.Label(f_text, text="How Digital Signatures Protect File Integrity",
                 font=("Segoe UI", 10, "bold"), fg=PRIMARY_BLUE, bg=CARD_BG).pack(anchor="w")
        tk.Label(f_text,
                 text="Private key signs file   \u27f6   File, signature (.sig) & public key are distributed   \u27f6   Public key verifies authenticity",
                 font=("Segoe UI", 9), fg=TEXT_SUB, bg=CARD_BG).pack(anchor="w")

    def build_stat_tile(self, parent, col, title, var, sub, color):
        tile = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER,
                        highlightthickness=1, padx=16, pady=14)
        tile.grid(row=0, column=col, sticky="nsew", padx=4)

        tk.Label(tile, text=title, font=("Segoe UI", 9, "bold"), fg=TEXT_MUTED, bg=CARD_BG).pack(anchor="w")
        tk.Label(tile, textvariable=var, font=("Segoe UI", 19, "bold"), fg=color, bg=CARD_BG).pack(anchor="w", pady=(2, 0))
        tk.Label(tile, text=sub, font=("Segoe UI", 8), fg=TEXT_MUTED, bg=CARD_BG).pack(anchor="w")

    def build_step_card(self, parent, col, num, title, desc, btn_text, target_tab, color):
        card = tk.Frame(parent, bg=CARD_BG, highlightbackground=CARD_BORDER,
                        highlightthickness=1, padx=18, pady=16, cursor="hand2")
        card.grid(row=0, column=col, sticky="nsew", padx=4)

        top_row = tk.Frame(card, bg=CARD_BG)
        top_row.pack(fill="x", pady=(0, 6))

        badge = tk.Frame(top_row, bg=PRIMARY_LIGHT, highlightbackground=CARD_BORDER,
                         highlightthickness=1, padx=8, pady=2)
        badge.pack(side="left")
        tk.Label(badge, text=f"Step {num}", font=("Segoe UI", 8, "bold"),
                 fg=color, bg=PRIMARY_LIGHT).pack()

        tk.Label(card, text=title, font=("Segoe UI", 12, "bold"),
                 fg=TEXT_MAIN, bg=CARD_BG).pack(anchor="w", pady=(4, 4))
        tk.Label(card, text=desc, font=("Segoe UI", 9), fg=TEXT_SUB, bg=CARD_BG,
                 wraplength=250, justify="left").pack(anchor="w", pady=(0, 14))

        btn = SmoothButton(card, btn_text, lambda: self.show_tab(target_tab),
                           bg_color=color, hover_color=TEXT_MAIN, padx=16, pady=6)
        btn.pack(anchor="w")

        def on_enter(e):
            card.config(highlightbackground=color)

        def on_leave(e):
            card.config(highlightbackground=CARD_BORDER)

        card.bind("<Enter>", on_enter)
        card.bind("<Leave>", on_leave)

    def refresh_overview_metrics(self):
        history = load_history()
        self.m_total.set(str(len(history)))
        self.m_valid.set(str(sum(1 for h in history if h.get("result") == "VALID")))
        self.m_tamper.set(str(sum(1 for h in history if h.get("result") == "INVALID")))

    # ==================================================================
    # TAB 1: GENERATE KEYS
    # ==================================================================
    def build_keys_tab(self):
        page = tk.Frame(self.container, bg=BG_APP)
        self.pages.append(page)

        self.keys_folder = tk.StringVar()
        self.keys_pass = tk.StringVar()

        card = self.create_card(
            page,
            title="Generate DSA Key Pair",
            subtitle="Create a 2048-bit DSA private key and public key pair. The private key remains private; the public key is shared to verify signatures.",
            badge="Key Management"
        )
        card.pack(fill="x", pady=(0, 12))

        self.create_input_row(card, "Save in folder:", self.keys_folder, browse_kind="dir")

        pass_row = tk.Frame(card, bg=CARD_BG)
        pass_row.pack(fill="x", pady=6)
        tk.Label(pass_row, text="Passphrase (optional):", font=("Segoe UI", 9, "bold"),
                 fg=TEXT_MAIN, bg=CARD_BG, width=17, anchor="w").pack(side="left")

        entry_frame = tk.Frame(pass_row, bg=CARD_BG, highlightbackground=CARD_BORDER,
                               highlightthickness=1)
        entry_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))

        pass_entry = tk.Entry(entry_frame, textvariable=self.keys_pass, font=("Segoe UI", 10),
                              show="*", relief="flat", bg=CARD_BG, fg=TEXT_MAIN)
        pass_entry.pack(fill="x", padx=10, pady=7)

        def on_f_in(e):
            entry_frame.config(highlightbackground=PRIMARY_BLUE)

        def on_f_out(e):
            entry_frame.config(highlightbackground=CARD_BORDER)

        pass_entry.bind("<FocusIn>", on_f_in)
        pass_entry.bind("<FocusOut>", on_f_out)

        tk.Label(pass_row, text="Encrypts the private key file",
                 font=("Segoe UI", 9), fg=TEXT_MUTED, bg=CARD_BG).pack(side="right")

        btn = SmoothButton(card, "Generate DSA Key Pair", self.do_generate, padx=22, pady=8)
        btn.pack(anchor="w", pady=(12, 0))

        # Output Details Card
        out_card = self.create_card(page, title="Key Pair Details", badge="Output")
        out_card.pack(fill="both", expand=True)

        self.keys_box = self.create_property_box(out_card)
        self.keys_status_lbl = tk.Label(self.keys_box, text="No key pair generated yet in this session.",
                                        font=("Segoe UI", 10), fg=TEXT_MUTED, bg=PILL_BG)
        self.keys_status_lbl.pack(anchor="w", pady=(2, 6))

        self.keys_grid = tk.Frame(self.keys_box, bg=PILL_BG)
        self.keys_grid.pack(fill="x")

    def do_generate(self):
        folder = self.keys_folder.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Folder Needed", "Please select a valid folder to save the keys.")
            return

        priv_target = os.path.join(folder, "private_key.pem")
        if os.path.exists(priv_target):
            if not messagebox.askyesno("Overwrite?",
                                       "Key pair already exists in this folder.\nOverwrite them?\n\n"
                                       "Previous signatures will not verify with newly generated keys."):
                return

        self.busy("Generating 2048-bit DSA key pair...")
        try:
            info = generate_keys(folder, self.keys_pass.get() or None)
        except Exception as e:
            self.set_ready("Key generation failed")
            messagebox.showerror("Error", f"Key generation failed:\n{str(e)}")
            return

        for child in self.keys_grid.winfo_children():
            child.destroy()

        self.keys_status_lbl.config(text="Key Pair Generated Successfully",
                                    font=("Segoe UI", 10, "bold"), fg=SUCCESS_GREEN)

        rows = [
            ("Private Key", info['private_path'] + "  (keep secret)"),
            ("Public Key", info['public_path'] + "  (share this)"),
            ("Key Parameters", f"{info['key_size']} bits (q = {info['q_bits']} bits)"),
            ("Passphrase Encrypted", "Yes (PKCS#8)" if info['encrypted'] else "No"),
            ("Public Key Fingerprint", info['fingerprint']),
        ]

        for k, v in rows:
            r = tk.Frame(self.keys_grid, bg=PILL_BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=k + ":", font=("Segoe UI", 9, "bold"), fg=TEXT_MAIN,
                     bg=PILL_BG, width=20, anchor="w").pack(side="left")
            val_lbl = tk.Label(r, text=v, font=("Segoe UI", 9), fg=TEXT_SUB, bg=PILL_BG)
            val_lbl.pack(side="left")

        self.sign_key.set(info["private_path"])
        self.verify_key.set(info["public_path"])
        self.set_ready("Key pair generated and loaded into Sign and Verify tabs")

    # ==================================================================
    # TAB 2: SIGN FILE
    # ==================================================================
    def build_sign_tab(self):
        page = tk.Frame(self.container, bg=BG_APP)
        self.pages.append(page)

        self.sign_file_var = tk.StringVar()
        self.sign_key = tk.StringVar()

        card = self.create_card(
            page,
            title="Sign a File",
            subtitle="Select a file and your DSA private key. A SHA-256 hash is computed and signed, producing a .sig signature file.",
            badge="Signature Creation"
        )
        card.pack(fill="x", pady=(0, 12))

        self.create_input_row(card, "File to sign:", self.sign_file_var)
        self.create_input_row(card, "Private key (.pem):", self.sign_key,
                              filetypes=[("PEM Private Key", "*.pem"), ("All files", "*.*")])

        btn = SmoothButton(card, "Sign File", self.do_sign, padx=24, pady=8)
        btn.pack(anchor="w", pady=(12, 0))

        out_card = self.create_card(page, title="Signature Summary", badge="Manifest")
        out_card.pack(fill="both", expand=True)

        self.sign_box = self.create_property_box(out_card)
        self.sign_status_lbl = tk.Label(self.sign_box, text="No file signed yet in this session.",
                                        font=("Segoe UI", 10), fg=TEXT_MUTED, bg=PILL_BG)
        self.sign_status_lbl.pack(anchor="w", pady=(2, 6))

        self.sign_grid = tk.Frame(self.sign_box, bg=PILL_BG)
        self.sign_grid.pack(fill="x")

    def do_sign(self):
        fp = self.sign_file_var.get().strip()
        kp = self.sign_key.get().strip()

        if not os.path.isfile(fp):
            messagebox.showwarning("File Needed", "Please select a file to sign.")
            return
        if not os.path.isfile(kp):
            messagebox.showwarning("Key Needed", "Please select your private key (.pem).")
            return

        pw = None
        try:
            if is_encrypted(kp):
                pw = simpledialog.askstring("Passphrase", "Enter the private key passphrase:",
                                            show="*", parent=self.root)
                if pw is None:
                    return

            self.busy("Signing file...")
            res = sign_file(fp, kp, pw)
        except Exception as e:
            self.set_ready("Signing failed")
            messagebox.showerror("Signing Failed",
                                 f"Could not sign. Wrong passphrase or not a DSA private key?\n\n{str(e)}")
            return

        self.last_hash = res["sha256"]

        for child in self.sign_grid.winfo_children():
            child.destroy()

        self.sign_status_lbl.config(text="File Signed Successfully",
                                    font=("Segoe UI", 10, "bold"), fg=SUCCESS_GREEN)

        rows = [
            ("File", fp),
            ("Size", f"{res['size']:,} bytes"),
            ("SHA-256 Digest", res['sha256']),
            ("Signature File", res['sig_path']),
            ("Signature Manifest", res['sig_path'] + ".info"),
            ("Key Fingerprint", res['fingerprint']),
            ("Parameters (r, s)", f"r: {res['r']:x}...\ns: {res['s']:x}..."),
        ]

        for k, v in rows:
            r = tk.Frame(self.sign_grid, bg=PILL_BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=k + ":", font=("Segoe UI", 9, "bold"), fg=TEXT_MAIN,
                     bg=PILL_BG, width=18, anchor="w").pack(side="left")
            val_lbl = tk.Label(r, text=v, font=("Segoe UI", 9), fg=TEXT_SUB, bg=PILL_BG, justify="left")
            val_lbl.pack(side="left")

        self.verify_file_var.set(fp)
        self.verify_sig.set(res["sig_path"])
        self.set_ready("File signed. Paths copied to Verify tab")

    # ==================================================================
    # TAB 3: VERIFY SIGNATURE
    # ==================================================================
    def build_verify_tab(self):
        page = tk.Frame(self.container, bg=BG_APP)
        self.pages.append(page)

        self.verify_file_var = tk.StringVar()
        self.verify_sig = tk.StringVar()
        self.verify_key = tk.StringVar()

        card = self.create_card(
            page,
            title="Verify File Integrity",
            subtitle="Check whether a file matches its digital signature and public key. Detects any tampering or unauthorized edits.",
            badge="Verification"
        )
        card.pack(fill="x", pady=(0, 10))

        self.create_input_row(card, "Signed file:", self.verify_file_var)
        self.create_input_row(card, "Signature (.sig):", self.verify_sig,
                              filetypes=[("Signature files", "*.sig"), ("All files", "*.*")])
        self.create_input_row(card, "Public key (.pem):", self.verify_key,
                              filetypes=[("PEM Public Key", "*.pem"), ("All files", "*.*")])

        btn = SmoothButton(card, "Verify Signature", self.do_verify, padx=24, pady=8)
        btn.pack(anchor="w", pady=(10, 0))

        # Smooth Dynamic Result Banner Card
        self.result_card = tk.Frame(page, bg=CARD_BG, highlightbackground=CARD_BORDER,
                                    highlightthickness=1, padx=18, pady=16)
        self.result_card.pack(fill="x", pady=(0, 10))

        res_head = tk.Frame(self.result_card, bg=CARD_BG)
        res_head.pack(fill="x")

        self.res_icon_c = tk.Canvas(res_head, width=32, height=32, bg=CARD_BG, highlightthickness=0)
        self.res_icon_c.pack(side="left", padx=(0, 12))
        draw_shield(self.res_icon_c, 16, 16, 12, "#94a3b8")

        res_titles = tk.Frame(res_head, bg=CARD_BG)
        res_titles.pack(side="left")

        self.res_title_lbl = tk.Label(res_titles, text="Awaiting Verification",
                                      font=("Segoe UI", 12, "bold"), fg=TEXT_MAIN, bg=CARD_BG)
        self.res_title_lbl.pack(anchor="w")

        self.res_desc_lbl = tk.Label(
            res_titles,
            text="Select the signed file, signature (.sig), and public key above, then click 'Verify Signature'.",
            font=("Segoe UI", 9), fg=TEXT_SUB, bg=CARD_BG)
        self.res_desc_lbl.pack(anchor="w")

        # Detailed Verification Breakdown
        out_card = self.create_card(page, title="Verification Details", badge="Breakdown")
        out_card.pack(fill="both", expand=True)

        self.verify_box = self.create_property_box(out_card)
        self.verify_grid = tk.Frame(self.verify_box, bg=PILL_BG)
        self.verify_grid.pack(fill="x")

        self.verify_default_lbl = tk.Label(self.verify_grid, text="Inspection details will appear here after verification.",
                                           font=("Segoe UI", 10), fg=TEXT_MUTED, bg=PILL_BG)
        self.verify_default_lbl.pack(anchor="w", pady=4)

        bottom_bar = tk.Frame(out_card, bg=CARD_BG)
        bottom_bar.pack(fill="x", pady=(8, 0))

        copy_btn = SmoothButton(bottom_bar, "Copy SHA-256 Hash", self.copy_hash,
                                bg_color="#f1f5f9", hover_color="#e2e8f0", text_color=TEXT_MAIN,
                                font=("Segoe UI", 9), padx=14, pady=5, radius=11,
                                outline_color=CARD_BORDER)
        copy_btn.pack(side="right")

    def copy_hash(self):
        if self.last_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.last_hash)
            self.set_ready("Hash copied to clipboard")
        else:
            messagebox.showinfo("No Hash", "Run a verification or signing task first.")

    def do_verify(self):
        fp = self.verify_file_var.get().strip()
        sp = self.verify_sig.get().strip()
        kp = self.verify_key.get().strip()

        for path, name in ((fp, "signed file"), (sp, "signature file"), (kp, "public key")):
            if not os.path.isfile(path):
                messagebox.showwarning("Missing Input", f"Please select {name}.")
                return

        self.busy("Verifying signature...")
        try:
            res = verify_file(fp, sp, kp)
        except Exception as e:
            self.set_ready("Verification error")
            messagebox.showerror("Error",
                                 f"Could not read the key or files. Is this a DSA public key?\n\n{str(e)}")
            return

        self.last_hash = res["current_hash"]

        for child in self.verify_grid.winfo_children():
            child.destroy()

        if res["valid"]:
            # Valid State (Smooth emerald green card)
            self.result_card.config(bg=SUCCESS_BG, highlightbackground=SUCCESS_BORDER)
            self.res_icon_c.config(bg=SUCCESS_BG)
            self.res_icon_c.delete("all")
            draw_shield(self.res_icon_c, 16, 16, 13, SUCCESS_GREEN)

            self.res_title_lbl.config(text="\u2714  Signature Valid: File Authentic",
                                      fg=SUCCESS_GREEN, bg=SUCCESS_BG)
            self.res_desc_lbl.config(
                text="The file is authentic and matches the original digital signature. No modifications detected.",
                fg=TEXT_SUB, bg=SUCCESS_BG)
            verdict_text = "VALID"
        else:
            # Tamper / Invalid State (Smooth ruby red card)
            self.result_card.config(bg=ALERT_BG, highlightbackground=ALERT_BORDER)
            self.res_icon_c.config(bg=ALERT_BG)
            self.res_icon_c.delete("all")
            draw_warning_shield(self.res_icon_c, 16, 16, 13, ALERT_RED)

            self.res_title_lbl.config(text="\u2718  Signature Invalid / File Tampered",
                                      fg=ALERT_RED, bg=ALERT_BG)
            self.res_desc_lbl.config(
                text="The file content has been modified since it was signed, or the signature does not match this public key.",
                fg=TEXT_SUB, bg=ALERT_BG)
            verdict_text = "INVALID"

        details = [
            ("Verification Result", "Valid & Authentic" if res["valid"] else "Invalid (Possible Tampering)"),
            ("File Name", os.path.basename(fp)),
            ("Current SHA-256", res["current_hash"]),
        ]

        if res["signed_hash"]:
            is_same = (res["signed_hash"] == res["current_hash"])
            status_note = " (Matches original)" if is_same else " (Changed from original!)"
            details.append(("Original SHA-256", res["signed_hash"] + status_note))
        else:
            details.append(("Original SHA-256", "Not available (.sig.info file not found)"))

        if res["r"] is not None:
            details.append(("Signature Parameters", f"r: {res['r']:x}...\ns: {res['s']:x}..."))
        else:
            details.append(("Signature Parameters", "Corrupted or non-DSA format"))

        details.append(("Signer Public Key", res["fingerprint"]))

        for k, v in details:
            r = tk.Frame(self.verify_grid, bg=PILL_BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=k + ":", font=("Segoe UI", 9, "bold"), fg=TEXT_MAIN,
                     bg=PILL_BG, width=20, anchor="w").pack(side="left")
            val_lbl = tk.Label(r, text=v, font=("Segoe UI", 9), fg=TEXT_SUB, bg=PILL_BG, justify="left")
            val_lbl.pack(side="left")

        add_history(os.path.basename(fp), verdict_text, res["current_hash"])
        self.set_ready(f"Verification complete: {verdict_text}")

    # ==================================================================
    # TAB 4: HISTORY
    # ==================================================================
    def build_history_tab(self):
        page = tk.Frame(self.container, bg=BG_APP)
        self.pages.append(page)

        ctrl = tk.Frame(page, bg=CARD_BG, highlightbackground=CARD_BORDER,
                        highlightthickness=1, padx=18, pady=12)
        ctrl.pack(fill="x", pady=(0, 10))

        ctrl_left = tk.Frame(ctrl, bg=CARD_BG)
        ctrl_left.pack(side="left")

        tk.Label(ctrl_left, text="Verification History", font=("Segoe UI", 11, "bold"),
                 fg=TEXT_MAIN, bg=CARD_BG).pack(anchor="w")
        tk.Label(ctrl_left, text="History of previous file verifications on this system.",
                 font=("Segoe UI", 9), fg=TEXT_MUTED, bg=CARD_BG).pack(anchor="w")

        ctrl_right = tk.Frame(ctrl, bg=CARD_BG)
        ctrl_right.pack(side="right")

        search_box = tk.Frame(ctrl_right, bg="#f8fafc", highlightbackground=CARD_BORDER,
                              highlightthickness=1, padx=8, pady=3)
        search_box.pack(side="left", padx=(0, 12))

        tk.Label(search_box, text="\U0001f50d", font=("Segoe UI", 9), bg="#f8fafc", fg=TEXT_MUTED).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_history())
        search_entry = tk.Entry(search_box, textvariable=self.search_var, font=("Segoe UI", 9),
                                relief="flat", bg="#f8fafc", fg=TEXT_MAIN, width=22)
        search_entry.pack(side="left", padx=4)

        clear_btn = SmoothButton(ctrl_right, "Clear History", self.clear_history,
                                 bg_color="#fef2f2", hover_color="#fee2e2", text_color=ALERT_RED,
                                 font=("Segoe UI", 9, "bold"), padx=14, pady=5, radius=11,
                                 outline_color=ALERT_BORDER)
        clear_btn.pack(side="left")

        table_card = tk.Frame(page, bg=CARD_BG, highlightbackground=CARD_BORDER,
                              highlightthickness=1)
        table_card.pack(fill="both", expand=True)

        cols = ("date", "file", "result", "hash")
        self.tree = ttk.Treeview(table_card, columns=cols, show="headings")

        self.tree.heading("date", text="Date & Time")
        self.tree.heading("file", text="File Name")
        self.tree.heading("result", text="Result")
        self.tree.heading("hash", text="SHA-256 Digest")

        self.tree.column("date", width=160, minwidth=140, anchor="w")
        self.tree.column("file", width=220, minwidth=180, anchor="w")
        self.tree.column("result", width=120, minwidth=100, anchor="center")
        self.tree.column("hash", width=360, minwidth=280, anchor="w")

        self.tree.tag_configure("VALID", foreground=SUCCESS_GREEN)
        self.tree.tag_configure("INVALID", foreground=ALERT_RED)

        sb = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

    def refresh_history(self):
        self.filter_history()

    def filter_history(self):
        query = self.search_var.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)

        history = load_history()
        for h in reversed(history):
            f_name = h.get("file", "")
            sha = h.get("sha256", "")
            if query and (query not in f_name.lower() and query not in sha.lower()):
                continue

            verdict = "\u2714 VALID" if h.get("result") == "VALID" else "\u2718 INVALID"
            self.tree.insert("", "end", tags=(h["result"],),
                             values=(h.get("date", ""), f_name, verdict, sha))

    def clear_history(self):
        if messagebox.askyesno("Clear History", "Delete all verification records?"):
            save_history([])
            self.refresh_history()
            self.set_ready("History cleared")


# ======================================================================
# LAUNCHER
# ======================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
