"""Package-manager noise: real `pip` (and `npm`, if installed) traffic, in a throwaway environment.

People who write code don't only browse: their computers also talk to PyPI and npm.
This engine makes that traffic for real, so it looks exactly like the real thing:

  install     pip install <package>        (removed again later)
  uninstall   pip uninstall -y <package>   (local; keeps the environment small)
  download    pip download --no-deps <package>, then the file is deleted
  index       pip index versions <package> (just asks which versions exist)
  bundle      pip install -r requirements.txt  (a whole project's worth, 3-14 packages plus their
              dependencies, into a temporary folder that is deleted straight after)
  npm         npm view <package> / npm install <package> into a temporary folder, then deleted

Safety and isolation:
  * Everything happens in its own environment inside legalPrivacy's folder, never in yours, and it
    ignores your pip configuration (your own package index and credentials are never used).
  * Only ready-built packages (`--only-binary=:all:`), so no package's install code ever runs,
    and nothing installed is ever imported.
  * Package names come from fixed lists of very popular packages (no lookalike names).
  * The environment is rebuilt from scratch every day, or sooner if it grows past ~600 MB.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Popular, binary-wheel packages. Very large ones (torch, tensorflow, xgboost) are left out.
GENERAL = ["requests", "urllib3", "certifi", "idna", "charset-normalizer", "python-dateutil", "pyyaml",
           "packaging", "attrs", "click", "jinja2", "markupsafe", "rich", "tqdm", "pytz", "typing-extensions",
           "pydantic", "httpx", "beautifulsoup4", "lxml", "pillow", "colorama", "tomli", "platformdirs",
           "filelock", "python-dotenv", "black", "ruff", "pytest", "flask", "fastapi", "uvicorn", "boto3"]
DATA_SCIENCE = ["numpy", "pandas", "scipy", "scikit-learn", "matplotlib", "seaborn", "statsmodels", "plotly",
                "polars", "pyarrow", "duckdb", "lightgbm", "sympy", "networkx", "ipython", "openpyxl",
                "sqlalchemy", "joblib", "nltk", "shap", "jupyterlab", "notebook", "tabulate", "xlrd"]
WEB = ["flask", "fastapi", "uvicorn", "jinja2", "requests", "httpx", "sqlalchemy", "pydantic", "boto3",
       "python-dotenv", "pytest", "gunicorn", "alembic", "redis", "celery", "pyjwt", "click", "rich"]
STACKS = {"data": DATA_SCIENCE, "web": WEB, "tools": GENERAL}
NPM = ["lodash", "chalk", "axios", "express", "react", "react-dom", "typescript", "dayjs", "uuid", "commander",
       "dotenv", "zod", "prettier", "vite"]
TECHY_PERSONAS = ("Default mix", "Data scientist", "Developer")
NEVER_REMOVE = {"pip", "setuptools", "wheel"}


def _python() -> str | None:
    """A Python that can make a virtual environment (not the frozen app itself)."""
    if not getattr(sys, "frozen", False):
        return sys.executable
    return shutil.which("python3") or shutil.which("python")


def _size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


_DL = re.compile(r"Downloading .*?\(([\d.]+) ([kMG]?B)\)")
_UNIT = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9}


def downloaded_bytes(pip_output: str) -> int:
    return int(sum(float(n) * _UNIT.get(u, 1) for n, u in _DL.findall(pip_output)))


class PackageNoise:
    def __init__(self, base: Path, rng, persona: str = "", proxy: str | None = None,
                 run_fn=None, max_age: float = 86400, max_bytes: int = 600_000_000):
        self.base, self.rng, self.persona, self.proxy = Path(base), rng, persona, proxy
        self.run_fn = run_fn or self._run
        self.max_age, self.max_bytes = max_age, max_bytes
        self.venv = self.base / "venv"
        self.installed: list[str] = []
        self.npm = shutil.which("npm")

    # ── environment ────────────────────────────────────────────────────────
    def _env(self) -> dict:
        env = dict(os.environ)
        env.update({"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1", "PYTHONNOUSERSITE": "1",
                    "PIP_CACHE_DIR": str(self.base / "pip-cache"), "npm_config_cache": str(self.base / "npm-cache"),
                    "npm_config_userconfig": os.devnull, "npm_config_fund": "false", "npm_config_audit": "false"})
        env.pop("PIP_INDEX_URL", None)
        env.pop("PIP_EXTRA_INDEX_URL", None)
        if self.proxy:
            env["HTTPS_PROXY"] = env["HTTP_PROXY"] = self.proxy
        return env

    def _vpy(self) -> Path:
        return self.venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def ensure(self) -> str | None:
        """Make (or remake) the throwaway environment. Returns an error, or None."""
        stamp = self.base / "created"
        try:
            old = time.time() - float(stamp.read_text()) if stamp.exists() else None
        except (OSError, ValueError):
            old = None
        if self._vpy().exists() and old is not None and old < self.max_age and _size(self.base) < self.max_bytes:
            return None
        self.reset()
        py = _python()
        if not py:
            return "no Python found to make the package environment"
        self.base.mkdir(parents=True, exist_ok=True)
        r = self.run_fn([py, "-m", "venv", str(self.venv)], 180)
        if r[0] != 0:
            return "couldn't make the package environment: " + (r[1].strip().splitlines() or ["?"])[-1]
        stamp.write_text(str(time.time()))
        return None

    def reset(self) -> None:
        """Remove everything: the environment, caches, downloads."""
        shutil.rmtree(self.base, ignore_errors=True)
        self.installed = []

    # ── choosing what to do ────────────────────────────────────────────────
    def _pool(self) -> list[str]:
        if self.persona in TECHY_PERSONAS and self.rng.random() < 0.7:
            return DATA_SCIENCE
        return GENERAL if self.rng.random() < 0.6 else DATA_SCIENCE

    def choose(self) -> tuple[str, str]:
        r = self.rng.random()
        if self.npm and r < 0.15:
            return ("npm-install" if self.rng.random() < 0.6 else "npm-view"), self.rng.choice(NPM)
        if self.installed and r < 0.35:
            return "uninstall", self.installed[0]
        if r < 0.45:
            return "index", self.rng.choice(self._pool())
        if r < 0.55:
            return "download", self.rng.choice(self._pool())
        if r < 0.70:                     # sometimes a whole project's requirements at once
            stack = self.rng.choices(["data", "web", "tools"],
                                     weights=[3, 2, 1] if self.persona in TECHY_PERSONAS else [1, 1, 1])[0]
            return "bundle", f"{stack}:{self.rng.randint(3, 14)}"
        return "install", self.rng.choice(self._pool())

    def command(self, action: str, pkg: str, tmp: str | None = None) -> list[str]:
        pip = [str(self._vpy()), "-m", "pip"]
        if action == "install":
            return pip + ["install", "--only-binary=:all:", "--no-cache-dir", pkg]
        if action == "bundle":      # a requirements file, installed into a folder that is deleted afterwards
            return pip + ["install", "--only-binary=:all:", "--no-cache-dir", "--target",
                          os.path.join(tmp or ".", "site"), "-r", os.path.join(tmp or ".", "requirements.txt")]
        if action == "uninstall":
            return pip + ["uninstall", "-y", pkg]
        if action == "download":
            return pip + ["download", "--only-binary=:all:", "--no-deps", "--no-cache-dir", "-d", tmp or ".", pkg]
        if action == "index":
            return pip + ["index", "versions", pkg]
        if action == "npm-install":
            return [self.npm, "install", "--prefix", tmp or ".", "--no-audit", "--no-fund", "--ignore-scripts", pkg]
        if action == "npm-view":
            return [self.npm, "view", pkg, "version"]
        raise ValueError(action)

    def bundle_list(self, pkg: str) -> list[str]:
        """'data:8' -> eight packages from that stack, as a requirements file would list them."""
        stack, _, n = pkg.partition(":")
        pool = STACKS.get(stack, GENERAL)
        return self.rng.sample(pool, min(len(pool), max(1, int(n or 5))))

    @staticmethod
    def label(action: str, pkg: str) -> str:
        if action == "bundle":
            stack, _, n = pkg.partition(":")
            return f"pip install -r requirements.txt ({n or '?'} packages, {stack})"
        if action.startswith("npm"):
            return f"npm {action[4:]} {pkg}"
        return f"pip index versions {pkg}" if action == "index" else f"pip {action} {pkg}"

    # ── doing it ───────────────────────────────────────────────────────────
    def _run(self, cmd: list[str], timeout: float) -> tuple[int, str]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=self._env(),
                               cwd=str(self.base) if self.base.exists() else None)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            return 124, "timed out"
        except OSError as exc:
            return 127, str(exc)

    def do(self, action: str, pkg: str) -> dict:
        """Run one action. Returns {ok, label, bytes, error}."""
        err = self.ensure()
        if err:
            return {"ok": False, "label": self.label(action, pkg), "bytes": 0, "error": err}
        label = self.label(action, pkg)
        tmp = None
        if action in ("download", "npm-install", "bundle"):
            tmp = tempfile.mkdtemp(prefix="dl-", dir=str(self.base))
        if action == "bundle":
            (Path(tmp) / "requirements.txt").write_text("\n".join(self.bundle_list(pkg)) + "\n")
        try:
            rc, out = self.run_fn(self.command(action, pkg, tmp), 600)
            nbytes = downloaded_bytes(out)
            if tmp and not nbytes:
                nbytes = _size(Path(tmp))
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)        # downloads are never kept
        if rc == 0 and action == "install" and pkg not in self.installed:
            self.installed.append(pkg)
            while len(self.installed) > 4:                    # keep the environment small: remove the oldest
                old = self.installed.pop(0)
                if old not in NEVER_REMOVE:
                    self.run_fn(self.command("uninstall", old), 120)
        if rc == 0 and action == "uninstall" and pkg in self.installed:
            self.installed.remove(pkg)
        last = next((ln for ln in reversed(out.strip().splitlines()) if ln.strip()), "")
        return {"ok": rc == 0, "label": label, "bytes": nbytes, "error": None if rc == 0 else last[:200]}
