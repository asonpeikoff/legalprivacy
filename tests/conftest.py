"""Tests never install browsers or packages by themselves (the app does that for people; a test must not)."""
import os

os.environ.setdefault("LEGALPRIVACY_AUTOINSTALL", "0")
