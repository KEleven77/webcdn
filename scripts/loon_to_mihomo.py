from pathlib import Path
import sys

SOURCE = Path("rule/Final.lpx")
YAML_TARGET = Path("rule/Final.yaml")
JS_TARGET = Path("rule/Final.js")

POLICY_MAP = {
    "REJECT-NO-DROP": "REJECT-DROP",
}

DIRECT_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "NETWORK",
}


def split_rule(line: str):
    parts = []
    current = []
    quoted = False
    escape = False

    for char in line:
        if escape:
            current.append(char)
            escape = False
            continue

        if char == "\\":
            current.append(char)
            escape = True
            continue

        if char == '"':
            current.append(char)
            quoted = not quoted
            continue

        if char == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    parts.append("".join(current).strip())
    return parts


def normalize_ip(rule_type, value):
    if rule_type == "IP-CIDR" and "/" not in value:
        return value + "/32"

    if rule_type == "IP-CIDR6" and "/" not in value:
        return value + "/128"

    return value


def convert_policy(policy):
    return POLICY_MAP.get(policy, policy)


def convert_rule(line, line_number):
    parts = split_rule(line)

    if len(parts) < 2:
        print(
            f"[WARN] Line {line_number}: invalid rule: {line}",
            file=sys.stderr,
        )
        return None

    rule_type = parts[0].upper()

    # FINAL 不能写入 +rules / Bettbox 前置规则
    if rule_type == "FINAL":
        print(
            f"[SKIP] Line {line_number}: FINAL skipped",
            file=sys.stderr,
        )
        return None

    # 按你当前 Final.yaml 的习惯处理
    if rule_type == "URL-REGEX":
        if len(parts) < 3:
            print(
                f"[WARN] Line {line_number}: invalid URL-REGEX",
                file=sys.stderr,
            )
            return None

        regex = parts[1]

        if len(regex) >= 2 and regex[0] == '"' and regex[-1] == '"':
            regex = regex[1:-1]

        policy = convert_policy(parts[2])

        result = [
            "DOMAIN-REGEX",
            regex,
            policy,
        ]

        if len(parts) > 3:
            result.extend(parts[3:])

        print(
            f"[WARN] Line {line_number}: "
            "URL-REGEX converted to DOMAIN-REGEX",
            file=sys.stderr,
        )

        return ",".join(result)

    if rule_type not in DIRECT_RULE_TYPES:
        print(
            f"[WARN] Line {line_number}: "
            f"unsupported rule type: {rule_type}",
            file=sys.stderr,
        )
        return None

    if len(parts) >= 2:
        parts[1] = normalize_ip(rule_type, parts[1])

    if len(parts) >= 3:
        parts[2] = convert_policy(parts[2])

    return ",".join(parts)


def yaml_quote(value):
    return "'" + value.replace("'", "''") + "'"


def js_quote(value):
    return (
        value
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\r", "")
        .replace("\n", "\\n")
    )


def main():
    if not SOURCE.exists():
        print(f"Source not found: {SOURCE}", file=sys.stderr)
        sys.exit(1)

    lines = SOURCE.read_text(
        encoding="utf-8-sig"
    ).splitlines()

    yaml_output = [
        "+rules:",
    ]

    js_rules = []

    in_rule = False
    found_rule = False

    converted_count = 0
    skipped_count = 0

    for line_number, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        if stripped == "[Rule]":
            in_rule = True
            found_rule = True
            continue

        if (
            in_rule
            and stripped.startswith("[")
            and stripped.endswith("]")
        ):
            break

        if not in_rule:
            continue

        # 空行
        if not stripped:
            yaml_output.append("")
            continue

        # 注释
        if stripped.startswith("#"):
            yaml_output.append(stripped)
            continue

        converted = convert_rule(
            stripped,
            line_number,
        )

        if converted is None:
            skipped_count += 1
            continue

        yaml_output.append(
            "- " + yaml_quote(converted)
        )

        js_rules.append(converted)

        converted_count += 1

    if not found_rule:
        print(
            "ERROR: [Rule] section not found",
            file=sys.stderr,
        )
        sys.exit(1)

    while yaml_output and yaml_output[-1] == "":
        yaml_output.pop()

    yaml_output.append("")

    YAML_TARGET.write_text(
        "\n".join(yaml_output),
        encoding="utf-8",
        newline="\n",
    )

    # ----------------------
    # Bettbox JS
    # ----------------------

    js_output = [
        "/**",
        " * Auto generated from rule/Final.lpx",
        " * DO NOT EDIT THIS FILE MANUALLY",
        " */",
        "",
        "// Bettbox compatibility",
        "const Compatible_With_Bettbox = {",
        "  ruleOptionsEnable: true,",
        "};",
        "",
        "const customRules = [",
    ]

    for rule in js_rules:
        js_output.append(
            f"  '{js_quote(rule)}',"
        )

    js_output.extend([
        "];",
        "",
        "function main(config) {",
        "  if (!config || typeof config !== 'object') {",
        "    return config;",
        "  }",
        "",
        "  if (!Array.isArray(config.rules)) {",
        "    config.rules = [];",
        "  }",
        "",
        "  // 自定义规则置于机场原规则之前",
        "  config.rules = [",
        "    ...customRules,",
        "    ...config.rules,",
        "  ];",
        "",
        "  return config;",
        "}",
        "",
    ])

    JS_TARGET.write_text(
        "\n".join(js_output),
        encoding="utf-8",
        newline="\n",
    )

    print(f"Generated: {YAML_TARGET}")
    print(f"Generated: {JS_TARGET}")
    print(f"Converted rules: {converted_count}")
    print(f"Skipped rules: {skipped_count}")


if __name__ == "__main__":
    main()
