from pathlib import Path

HTML = (Path(__file__).parent.parent / "legalprivacy" / "web" / "index.html").read_text(encoding="utf-8")


def test_hiding_the_menu_leaves_one_full_width_column():
    """With the menu hidden the nav is display:none, so a leftover 0-width first column swallows the page content
    (every word wrapped one letter per line). The hidden layout must be a single column."""
    rule = next(r for r in HTML.split("}") if "#shell.hid{" in r)
    assert "grid-template-columns:minmax(0,1fr)" in rule and "0 minmax" not in rule


def test_a_side_menu_adds_nothing_to_the_scroll_offset_and_the_page_has_room_to_scroll_cards_to_the_top():
    """The offset the page leaves above a scrolled-to card must not include the height of a side menu (it is as tall as the
    window, which put every target below the visible area), and there must be room below the last card."""
    assert "flexDirection==='column'?0:nv.offsetHeight" in HTML
    assert "#shell>main::after{" in HTML
