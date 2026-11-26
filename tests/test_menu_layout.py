from pathlib import Path

HTML = (Path(__file__).parent.parent / "legalprivacy" / "web" / "index.html").read_text(encoding="utf-8")


def test_hiding_the_menu_leaves_one_full_width_column():
    """With the menu hidden the nav is display:none, so a leftover 0-width first column swallows the page content
    (every word wrapped one letter per line). The hidden layout must be a single column."""
    rule = next(r for r in HTML.split("}") if "#shell.hid{" in r)
    assert "grid-template-columns:minmax(0,1fr)" in rule and "0 minmax" not in rule
