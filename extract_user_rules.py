#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 AdGuardHome.yaml 提取 user_rules 到纯文本文件。

默认读取：Adguardhome/bin/AdGuardHome.yaml
默认输出：user_rules.txt、allow_rules.txt、block_rules.txt
输出内容会去掉 YAML 列表前缀 `-` 和包裹用的引号。
黑白名单文件默认不保留注释；完整规则文件会保留原始注释。
"""

from __future__ import annotations

import argparse
from pathlib import Path


def _indent_width(line: str) -> int:
    """计算行首空格数量，用于判断 user_rules 块何时结束。"""
    return len(line) - len(line.lstrip(" "))


def _strip_yaml_scalar(value: str) -> str:
    """去掉 YAML 标量外层引号，并处理常见的 YAML 转义写法。"""
    value = value.strip()

    # user_rules 当前使用单引号包裹；这里同时兼容双引号。
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
        if quote == "'":
            # YAML 单引号内部用两个单引号表示一个单引号。
            value = value.replace("''", "'")
        else:
            # 双引号规则只做最常见的换行/制表/引号/反斜杠还原，避免误改过滤规则。
            value = (
                value.replace(r"\n", "\n")
                .replace(r"\t", "\t")
                .replace(r'\"', '"')
                .replace(r"\\", "\\")
            )

    return value


def extract_user_rules(source: Path) -> list[str]:
    """从 YAML 文件中提取 user_rules 列表内容。"""
    rules: list[str] = []
    in_user_rules = False
    user_rules_indent = 0

    for raw_line in source.read_text(encoding="utf-8").splitlines():
        line = raw_line.rstrip()

        if not in_user_rules:
            if line.strip() == "user_rules:":
                in_user_rules = True
                user_rules_indent = _indent_width(line)
            continue

        # 遇到同级或更高级的新字段，说明 user_rules 块已经结束。
        if line.strip() and _indent_width(line) <= user_rules_indent:
            break

        stripped = line.strip()
        if not stripped.startswith("-"):
            continue

        # 去掉列表前缀 `-`，再去掉外层引号。
        rule = _strip_yaml_scalar(stripped[1:].strip())
        rules.append(rule)

    if not in_user_rules:
        raise ValueError(f"未在 {source} 中找到 user_rules 字段")

    return rules


def split_rules(rules: list[str], keep_comments: bool = False) -> tuple[list[str], list[str]]:
    """按规则类型拆分为白名单和黑名单。

    - `@@` 开头：白名单规则。
    - `#` 或 `!` 开头：注释；默认不写入黑白名单。
    - 其他非空内容：黑名单规则。
    """
    allow_rules: list[str] = []
    block_rules: list[str] = []

    for rule in rules:
        stripped = rule.lstrip()

        # 空行不属于有效规则，跳过可避免导入 ADG 后产生无意义空白。
        if not stripped:
            continue

        if stripped.startswith(("#", "!")):
            if keep_comments:
                allow_rules.append(rule)
                block_rules.append(rule)
            continue

        if stripped.startswith("@@"):
            allow_rules.append(rule)
        else:
            block_rules.append(rule)

    return allow_rules, block_rules


def write_rules(path: Path, rules: list[str]) -> None:
    """写入规则文件，不在文件末尾额外追加空白行。"""
    path.write_text("\n".join(rules), encoding="utf-8")


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description="提取并拆分 AdGuard Home user_rules 到 txt")
    parser.add_argument(
        "source",
        nargs="?",
        default="Adguardhome/bin/AdGuardHome.yaml",
        help="AdGuardHome.yaml 路径，默认：Adguardhome/bin/AdGuardHome.yaml",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="user_rules.txt",
        help="完整规则输出路径，默认：user_rules.txt",
    )
    parser.add_argument(
        "--allow-output",
        default="allow_rules.txt",
        help="白名单规则输出路径，默认：allow_rules.txt",
    )
    parser.add_argument(
        "--block-output",
        default="block_rules.txt",
        help="黑名单规则输出路径，默认：block_rules.txt",
    )
    parser.add_argument(
        "--keep-comments",
        action="store_true",
        help="拆分黑白名单时保留 # 或 ! 开头的注释行",
    )
    args = parser.parse_args()

    source = Path(args.source)
    output = Path(args.output)
    allow_output = Path(args.allow_output)
    block_output = Path(args.block_output)

    rules = extract_user_rules(source)
    allow_rules, block_rules = split_rules(rules, keep_comments=args.keep_comments)

    write_rules(output, rules)
    write_rules(allow_output, allow_rules)
    write_rules(block_output, block_rules)

    print(f"已提取 {len(rules)} 条完整规则到 {output}")
    print(f"已写入 {len(allow_rules)} 条白名单规则到 {allow_output}")
    print(f"已写入 {len(block_rules)} 条黑名单规则到 {block_output}")


if __name__ == "__main__":
    main()
