"""Namespace-agnostic XML loading for ARXML.

AUTOSAR schema revisions do not share an XML namespace: R3.x files carry
``http://autosar.org/3.1.4`` (and siblings), R4.x files carry
``http://autosar.org/schema/r4.0``.  Threading a namespace map through every
lookup makes the extractor silently version-specific, so instead we strip
namespaces once at load time and match on plain local tag names everywhere
downstream.
"""

from __future__ import annotations

from pathlib import Path

from lxml import etree


def strip_namespaces(root: etree._Element) -> etree._Element:
    """Rewrite every qualified tag/attribute in place to its local name."""
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue  # comments and processing instructions
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
        qualified = [name for name in el.attrib if "}" in name]
        for name in qualified:
            el.attrib[name.split("}", 1)[1]] = el.attrib.pop(name)
    etree.cleanup_namespaces(root)
    return root


def load_file(path: str | Path) -> etree._Element:
    """Parse one ARXML file and return its namespace-stripped root."""
    parser = etree.XMLParser(remove_comments=True, remove_blank_text=False, huge_tree=True)
    tree = etree.parse(str(path), parser)
    return strip_namespaces(tree.getroot())


def load_paths(paths: list[str | Path]) -> list[tuple[Path, etree._Element]]:
    """Parse an explicit list of ARXML files, sorted for deterministic output."""
    return [(Path(p), load_file(p)) for p in sorted(Path(p) for p in paths)]


def discover(directory: str | Path) -> list[Path]:
    """Find every .arxml under `directory`, recursively and deterministically."""
    return sorted(Path(directory).rglob("*.arxml"))


def short_name(el: etree._Element) -> str | None:
    """Return the element's own SHORT-NAME, or None if it is not identifiable."""
    child = el.find("SHORT-NAME")
    if child is None or child.text is None:
        return None
    text = child.text.strip()
    return text or None


def ref(el: etree._Element, tag: str) -> str | None:
    """Return the AUTOSAR path held by a direct child reference element."""
    child = el.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def ref_dest(el: etree._Element, tag: str) -> str | None:
    """Return the DEST attribute of a direct child reference element."""
    child = el.find(tag)
    return None if child is None else child.get("DEST")
