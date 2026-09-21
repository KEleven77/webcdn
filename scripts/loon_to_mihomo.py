from pathlib import Path
import re
import sys

SOURCE = Path("rule/Final.lpx")
TARGET = Path("rule/Final.yaml")


# Loon -> Mihomo 动作映射
POLICY_MAP = {
    "REJECT-NO-DROP": "REJECT-DROP",
}


# 可直接转换到 Mihomo 的规则类型
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
    """
    简单解析 Loon Rule。
    会保护双引号中的逗号，避免普通 split(',') 出错。
    """
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


def normalize_ip_cidr(rule_type: str, value: str) -> str:
    """
    Mihomo 建议单 IP 使用明确 CIDR。
    例如：
      165.99.43.118 -> 165.99.43.118/32
    """
    if rule_type == "IP-CIDR":
        if "/" not in value:
            return value + "/32"

    if rule_type == "IP-CIDR6":
        if "/" not in value:
            return value + "/128"

    return value


def convert_policy(policy: str) -> str:
    return POLICY_MAP.get(policy, policy)


def quote_yaml_rule(rule: str) -> str:
    """
    用单引号包住整条规则。
    这样正则中的反斜杠不会被 YAML 双引号转义。
    """
    escaped = rule.replace("'", "''")
    return f"'{escaped}'"


def convert_rule(line: str, line_number: int):
    parts = split_rule(line)

    if len(parts) < 2:
        print(
            f"[WARN] Line {line_number}: invalid rule: {line}",
            file=sys.stderr,
        )
        return None

    rule_type = parts[0].upper()

    # FINAL 不应该放进 +rules:
    # 否则转换成 MATCH 后会提前截断机场原规则。
    if rule_type == "FINAL":
        print(
            f"[SKIP] Line {line_number}: FINAL skipped in +rules override",
            file=sys.stderr,
        )
        return None

    # Loon URL-REGEX 匹配 URL，
    # Mihomo DOMAIN-REGEX 匹配域名，两者不等价。
    #
    # 结合你当前文件的使用方式：
    # URL-REGEX,"\\.log\\.",REJECT
    #
    # 当前 Final.yaml 中已经人为映射成 DOMAIN-REGEX。
    # 因此这里只针对 URL-REGEX 做该转换。
    if rule_type == "URL-REGEX":
        if len(parts) < 3:
            print(
                f"[WARN] Line {line_number}: invalid URL-REGEX: {line}",
                file=sys.stderr,
            )
            return None

        regex = parts[1]

        # 去除 Loon 外层双引号
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
            f"URL-REGEX converted to DOMAIN-REGEX; semantics are not identical",
            file=sys.stderr,
        )

        return ",".join(result)

    if rule_type not in DIRECT_RULE_TYPES:
        print(
            f"[WARN] Line {line_number}: unsupported rule type "
            f"{rule_type}: {line}",
            file=sys.stderr,
        )
        return None

    # IP / 域名主体
    if len(parts) >= 2:
        parts[1] = normalize_ip_cidr(rule_type, parts[1])

    # 策略通常在第三列
    if len(parts) >= 3:
        parts[2] = convert_policy(parts[2])

    return ",".join(parts)


def main():
    if not SOURCE.exists():
        print(f"ERROR: source file not found: {SOURCE}", file=sys.stderr)
        sys.exit(1)

    text = SOURCE.read_text(encoding="utf-8-sig")

    lines = text.splitlines()

    output = [
        "+rules:",
    ]

    in_rule_section = False
    found_rule_section = False

    converted_count = 0
    skipped_count = 0

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()

        # 找 [Rule]
        if stripped == "[Rule]":
            in_rule_section = True
            found_rule_section = True
            continue

        # 遇到下一个 Section 则结束
        if (
            in_rule_section
            and stripped.startswith("[")
            and stripped.endswith("]")
        ):
            break

        if not in_rule_section:
            continue

        # -------------------------
        # 保留空行
        # -------------------------
        if not stripped:
            output.append("")
            continue

        # -------------------------
        # 保留注释
        # -------------------------
        if stripped.startswith("#"):
            output.append(stripped)
            continue

        # -------------------------
        # 转换规则
        # -------------------------
        converted = convert_rule(stripped, line_number)

        if converted is None:
            skipped_count += 1
            continue

        output.append("- " + quote_yaml_rule(converted))
        converted_count += 1

    if not found_rule_section:
        print(
            "ERROR: [Rule] section not found",
            file=sys.stderr,
        )
        sys.exit(1)

    # 删除文件末尾多余空行
    while output and output[-1] == "":
        output.pop()

    output.append("")

    new_content = "\n".join(output)

    old_content = ""
    if TARGET.exists():
        old_content = TARGET.read_text(encoding="utf-8-sig")

    if new_content == old_content:
        print("No changes.")
        return

    TARGET.write_text(
        new_content,
        encoding="utf-8",
        newline="\n",
    )

    print(f"Generated: {TARGET}")
    print(f"Converted rules: {converted_count}")
    print(f"Skipped rules: {skipped_count}")


if __name__ == "__main__":
    main()
