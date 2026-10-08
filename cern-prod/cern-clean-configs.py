#!/usr/bin/env python3
#
# (AI-generated) script to redact sensitive information from TOML configuration files

import argparse
import re
from pathlib import Path
import tomlkit


REDACTED_VALUE = "your_value_here"


# Keys that contain a sensitive keyword but hold plain settings.
SAFE_KEY_PARTS = ["_cost", "_chain", "_endpoint", "skip_", "_strategy"]


def should_redact(key: str, keywords: list[str]) -> bool:
    key_lc = key.lower()
    if any(safe in key_lc for safe in SAFE_KEY_PARTS):
        return False
    rc = any(kw in key_lc for kw in keywords)
    if rc:
        print(f"Redacting key: {key}")
    return rc


# Values matching these patterns are rewritten, whatever the key is.
VALUE_PATTERNS = [
    # e-mail addresses (must precede the hostname rule)
    (re.compile(r"[\w.+-]+@(?:[\w-]+\.)*cern\.ch", re.I), "user@example.org"),
    # LDAP DNs: DC=cern,DC=ch -> DC=example,DC=org
    (re.compile(r"DC=cern,DC=ch", re.I), "DC=example,DC=org"),
    # CERN hostnames, e.g. cbox-*.cern.ch -> host.example.org
    (re.compile(r"\b[\w.-]*\.cern\.ch\b", re.I), "host.example.org"),
]


# Keys removed altogether (test entries and deployment-specific settings).
DROP_KEYS = {"doyletest", "miniflax", "opendata", "eoshomedev", "my_office_files_projects"}


def redact_value(value: str) -> str:
    for pattern, repl in VALUE_PATTERNS:
        value = pattern.sub(repl, value)
    return value


def redact_node(node, keywords: list[str]):
    """
    Recursively redact TOML nodes in place while preserving formatting.
    Only string leaves (or arrays of strings) are replaced by keyword match:
    tables, booleans and numbers under a sensitive-looking key are left alone
    but still traversed.
    """
    if isinstance(node, tomlkit.container.OutOfOrderTableProxy):
        # writes through the proxy are lost on dump: edit the real tables
        for table in node._tables:
            redact_node(table, keywords)

    elif isinstance(node, (dict, tomlkit.items.Table, tomlkit.items.InlineTable)):
        for key, value in list(node.items()):
            if key in DROP_KEYS:
                print(f"Dropping key: {key}")
                del node[key]
            elif isinstance(value, str):
                if should_redact(key, keywords):
                    node[key] = REDACTED_VALUE
                else:
                    new = redact_value(str(value))
                    if new != value:
                        node[key] = new
            elif isinstance(value, tomlkit.items.Array) and should_redact(key, keywords) \
                    and all(isinstance(i, str) for i in value):
                node[key] = [REDACTED_VALUE]
            else:
                redact_node(value, keywords)

    elif isinstance(node, (list, tomlkit.items.AoT, tomlkit.items.Array)):
        for i, item in enumerate(node):
            if isinstance(item, str):
                new = redact_value(str(item))
                if new != item:
                    node[i] = new
            else:
                redact_node(item, keywords)


def main():
    parser = argparse.ArgumentParser(
        description="Redact sensitive keys in a TOML file while preserving formatting"
    )
    parser.add_argument("input", type=Path, help="Input .toml file")
    parser.add_argument(
        "-k",
        "--keywords",
        nargs="+",
        default=["secret", "password", "nats_token", "key", "db_host", "token",
                 "db_username", "bind_username", "base_dn", "client_id", "certfile"],
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
