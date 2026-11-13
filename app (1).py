"""
app.py
------
Password Strength Checker - desktop UI built with tkinter.
Run with:  python app.py
"""

import tkinter as tk
from tkinter import ttk

from password_checker import check_password, generate_password

# ---------- Theme ----------
BG = "#0f172a"        # window background
CARD = "#1e293b"      # card background
TEXT = "#e2e8f0"
MUTED = "#94a3b8"
ACCENT = "#38bdf8"
GOOD = "#22c55e"
BAD = "#ef4444"

LEVEL_COLORS = {
    "Very Weak": "#ef4444",
    "Weak": "#f97316",
    "Fair": "#eab308",
    "Strong": "#84cc16",
    "Very Strong": "#22c55e",
    "Empty": "#475569",
}

FONT = "Segoe UI"


class PasswordCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("680x700")
        self.minsize(640, 640)
        self.configure(bg=BG)

        self.show_var = tk.BooleanVar(value=False)
        self.pw_var = tk.StringVar()
        self.pw_var.trace_add("write", lambda *_: self.update_result())

        self._build_style()
        self._build_ui()
        self.update_result()

    # ---------- Styling ----------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Strength.Horizontal.TProgressbar",
            troughcolor="#334155",
            background=LEVEL_COLORS["Empty"],
            bordercolor=CARD,
            lightcolor=CARD,
            darkcolor=CARD,
            thickness=14,
        )

    # ---------- Layout ----------
    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=28, pady=(26, 10))
        tk.Label(header, text="🔐 Password Strength Checker", bg=BG, fg=TEXT,
                 font=(FONT, 20, "bold")).pack(anchor="w")
        tk.Label(header, text="Type a password to see how secure it is. "
                              "Nothing is stored or sent anywhere.",
                 bg=BG, fg=MUTED, font=(FONT, 10), wraplength=500,
                 justify="left").pack(anchor="w", pady=(4, 0))

        # Input card
        card = tk.Frame(self, bg=CARD)
        card.pack(fill="x", padx=28, pady=10)
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="x", padx=18, pady=18)

        tk.Label(inner, text="Enter password", bg=CARD, fg=MUTED,
                 font=(FONT, 10)).pack(anchor="w")

        row = tk.Frame(inner, bg=CARD)
        row.pack(fill="x", pady=(6, 8))
        self.entry = tk.Entry(row, textvariable=self.pw_var, show="•",
                              font=(FONT, 14), bg="#0b1220", fg=TEXT,
                              insertbackground=TEXT, relief="flat",
                              highlightthickness=2, highlightbackground="#334155",
                              highlightcolor=ACCENT)
        self.entry.pack(side="left", fill="x", expand=True, ipady=8)
        self.entry.focus()

        tk.Checkbutton(inner, text="Show password", variable=self.show_var,
                       command=self.toggle_show, bg=CARD, fg=MUTED,
                       selectcolor="#0b1220", activebackground=CARD,
                       activeforeground=TEXT, font=(FONT, 10),
                       bd=0, highlightthickness=0).pack(anchor="w")

        # Strength meter
        meter = tk.Frame(inner, bg=CARD)
        meter.pack(fill="x", pady=(16, 0))
        top = tk.Frame(meter, bg=CARD)
        top.pack(fill="x")
        tk.Label(top, text="Strength", bg=CARD, fg=MUTED,
                 font=(FONT, 10)).pack(side="left")
        self.level_lbl = tk.Label(top, text="", bg=CARD, fg=TEXT,
                                  font=(FONT, 11, "bold"))
        self.level_lbl.pack(side="right")
        self.bar = ttk.Progressbar(meter, style="Strength.Horizontal.TProgressbar",
                                   maximum=100, length=400)
        self.bar.pack(fill="x", pady=(6, 0))

        # Stats
        stats = tk.Frame(inner, bg=CARD)
        stats.pack(fill="x", pady=(14, 0))
        self.score_lbl = self._stat(stats, "Score")
        self.entropy_lbl = self._stat(stats, "Entropy")
        self.crack_lbl = self._stat(stats, "Time to crack")

        # Requirements card
        req = tk.Frame(self, bg=CARD)
        req.pack(fill="x", padx=28, pady=10)
        req_in = tk.Frame(req, bg=CARD)
        req_in.pack(fill="x", padx=18, pady=14)
        tk.Label(req_in, text="Requirements", bg=CARD, fg=TEXT,
                 font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 6))
        grid = tk.Frame(req_in, bg=CARD)
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1, uniform="req")
        grid.columnconfigure(1, weight=1, uniform="req")
        self.check_labels = {}
        sample = check_password("x").checks
        for i, name in enumerate(sample):
            lbl = tk.Label(grid, text="", bg=CARD, fg=MUTED,
                           font=(FONT, 10), anchor="w")
            lbl.grid(row=i % 3, column=i // 3, sticky="ew", pady=1, padx=(0, 8))
            self.check_labels[name] = lbl

        # Buttons (packed first, at the bottom, so they never get cut off)
        btns = tk.Frame(self, bg=BG)
        btns.pack(side="bottom", fill="x", padx=28, pady=(0, 18))
        self._button(btns, "✨ Generate strong password", self.generate,
                     ACCENT, "#0f172a").pack(side="left", fill="x", expand=True, padx=(0, 6))
        self._button(btns, "Clear", self.clear, "#334155", TEXT).pack(
            side="left", padx=(6, 0))

        # Feedback card (takes whatever space is left)
        fb = tk.Frame(self, bg=CARD)
        fb.pack(fill="both", expand=True, padx=28, pady=10)
        fb_in = tk.Frame(fb, bg=CARD)
        fb_in.pack(fill="both", expand=True, padx=18, pady=12)
        tk.Label(fb_in, text="Feedback", bg=CARD, fg=TEXT,
                 font=(FONT, 11, "bold")).pack(anchor="w", pady=(0, 6))
        self.feedback = tk.Label(fb_in, text="", bg=CARD, fg=MUTED,
                                 font=(FONT, 10), justify="left", anchor="nw",
                                 wraplength=560)
        self.feedback.pack(fill="both", expand=True)
        fb_in.bind("<Configure>",
                   lambda e: self.feedback.config(wraplength=max(200, e.width - 10)))

    def _stat(self, parent, title):
        box = tk.Frame(parent, bg=CARD)
        box.pack(side="left", expand=True, fill="x")
        tk.Label(box, text=title, bg=CARD, fg=MUTED, font=(FONT, 9)).pack(anchor="w")
        val = tk.Label(box, text="-", bg=CARD, fg=TEXT, font=(FONT, 12, "bold"))
        val.pack(anchor="w")
        return val

    def _button(self, parent, text, command, bg, fg):
        return tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=bg, activeforeground=fg,
                         font=(FONT, 11, "bold"), relief="flat", cursor="hand2",
                         padx=14, pady=10, bd=0)

    # ---------- Actions ----------
    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "•")

    def generate(self):
        self.pw_var.set(generate_password(16))
        self.show_var.set(True)
        self.toggle_show()

    def clear(self):
        self.pw_var.set("")
        self.entry.focus()

    def update_result(self):
        pw = self.pw_var.get()
        res = check_password(pw)
        color = LEVEL_COLORS.get(res.label, LEVEL_COLORS["Empty"])

        ttk.Style(self).configure("Strength.Horizontal.TProgressbar", background=color)
        self.bar["value"] = res.score
        self.level_lbl.config(text="" if not pw else res.label, fg=color)

        if pw:
            self.score_lbl.config(text=f"{res.score}/100")
            self.entropy_lbl.config(text=f"{res.entropy} bits")
            self.crack_lbl.config(text=res.crack_time)
        else:
            for lbl in (self.score_lbl, self.entropy_lbl, self.crack_lbl):
                lbl.config(text="-")

        # Requirements checklist
        defaults = check_password("x").checks
        for name, lbl in self.check_labels.items():
            ok = res.checks.get(name, False) if pw else False
            lbl.config(text=f"{'✔' if ok else '✘'}  {name}",
                       fg=GOOD if ok else (MUTED if not pw else BAD))

        # Feedback text
        lines = []
        if not pw:
            lines.append("Start typing to get instant feedback.")
        else:
            for w in res.warnings:
                lines.append(f"⚠  {w}")
            for s in res.suggestions:
                lines.append(f"💡 {s}")
        self.feedback.config(text="\n".join(lines))


if __name__ == "__main__":
    PasswordCheckerApp().mainloop()
