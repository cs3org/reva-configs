#!/usr/bin/env python3
#
# (AI-generated) script to redact sensitive information from TOML configuration files

import argparse
from pathlib import Path
import tomlkit


REDACTED_VALUE = "_redacted_"


def should_redact(key: str, keywords: list[str]) -> bool:
    key_lc = key.lower()
    l = [kw in key_lc for kw in keywords]
    rc = any(l)
    if rc:
        print(f"Redacting key: {key}")
    #else:
    #    print(f"Keeping key: {key}, l={l}")
    return rc


def redact_node(node, keywords: list[str]):
    """
    Recursively redact TOML nodes in place while preserving formatting.
    """
    if isinstance(node, tomlkit.TOMLDocument):
        for key, value in node.items():
            if should_redact(key, keywords):
                node[key] = REDACTED_VALUE
            else:
                redact_node(value, keywords)
        return

    elif isinstance(node, tomlkit.items.Table):
        for key, value in node.items():
            if should_redact(key, keywords):
                node[key] = REDACTED_VALUE
            else:
                redact_node(value, keywords)

    elif isinstance(node, tomlkit.container.OutOfOrderTableProxy):
        for key, value in node.items():
            if should_redact(key, keywords):
                node[key] = REDACTED_VALUE
            else:
                redact_node(value, keywords)

    elif isinstance(node, tomlkit.items.AoT):
        for table in node:
            redact_node(table, keywords)

    elif isinstance(node, tomlkit.items.Array):
        for item in node:
            redact_node(item, keywords)
    
    elif isinstance(node, tomlkit.items.String):
        pass  # Strings are leaf nodes; nothing to redact inside them
    
    else:
        print(f"Skipping node of type {type(node)} ({node})")


def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive keys in a TOML file while preserving formatting"
    )
    parser.add_argument("input", type=Path, help="Input .toml file")
    parser.add_argument(
        "-k",
        "--keywords",
        nargs="+",
        default=["secret", "password", "nats_token", "key", "db_host"],
        help="Keywords used to match sensitive keys (case-insensitive)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output file (default: overwrite input)",
    )

    args = parser.parse_args()

    text = args.input.read_text()
    doc = tomlkit.parse(text)

    redact_node(doc, args.keywords)

    output_path = args.output or args.input
    output_path.write_text(tomlkit.dumps(doc))


if __name__ == "__main__":
    main()
