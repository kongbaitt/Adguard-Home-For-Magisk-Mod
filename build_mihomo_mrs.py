#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合并 AdGuard 规则并生成 mihomo domain 类型 `.mrs` 规则集。

黑名单来源：GOODBYEADS dns.txt + 本仓库 block_rules.txt
白名单来源：GOODBYEADS allow.txt + 本仓库 allow_rules.txt

脚本会先把 AdGuard DNS 规则清洗为 mihomo `behavior: domain` 可转换的
文本规则，再调用 `mihomo convert-ruleset domain text` 生成 `.mrs`。
"""

from __future__ import annotations

import argparse
import ipaddress
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen


# 远程 GOODBYEADS 规则源。
GOODBYEADS_BLOCK_URL = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt"
GOODBYEADS_ALLOW_URL = "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt"


def read_text_source(source: str) -> str:
    """读取本地文件或远程 URL。"""
    if source.startswith(("http://", "https://")):
        request = Request(source, headers={"User-Agent": "AdGuardHome-rules-builder/1.0"})
        with urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8", errors="replace")

    return Path(source).read_text(encoding="utf-8")


def is_ip_or_cidr(value: str) -> bool:
    """判断是否为 IP 或 CIDR；domain 类型 mrs 不接收这类规则。"""
    candidate = value.strip("[]")
    try:
        if "/" in candidate:
            ipaddress.ip_network(candidate, strict=False)
        else:
            ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def looks_like_domain(value: str) -> bool:
    """粗略判断是否像 mihomo domain 文本规则。"""
    value = value.strip(".")
    if not value or value.startswith("-"):
        return False
    if any(char in value for char in "/:@[]\\"):
        return False
    if is_ip_or_cidr(value):
        return False
    # 单标签规则、纯数字分段和空分段都不适合 domain 类型 mrs。
    if "." not in value:
        return False
    labels = value.split(".")
    if any(not label for label in labels):
        return False
    if all(label.isdigit() for label in labels):
        return False
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*")
    return all(char in allowed_chars for char in value)


def split_adguard_options(rule: str) -> tuple[str, list[str]]:
    """拆分 AdGuard 规则主体和选项。

    `.mrs` 的 domain 规则无法表达 `$domain`、`$client`、`$dnstype` 等条件，
    所以后续只允许没有选项或仅包含 `$important` 的规则参与转换。
    """
    if "$" not in rule:
        return rule.strip(), []

    body, options_text = rule.split("$", 1)
    options = [option.split("=", 1)[0].strip().lower() for option in options_text.split(",")]
    return body.strip(), [option for option in options if option]


def has_only_safe_options(options: list[str]) -> bool:
    """判断 AdGuard 选项是否可安全丢弃。"""
    return all(option == "important" for option in options)


def extract_until_separator(value: str) -> str:
    """提取域名部分，遇到 AdGuard 分隔符或路径即停止。"""
    for separator in ("^", "/", "$"):
        if separator in value:
            value = value.split(separator, 1)[0]
    return value.strip("| .")


def convert_adguard_rule(line: str, allow_plain: bool = True) -> str | None:
    """把单条 AdGuard/hosts 规则转换为 mihomo domain 文本规则。

    返回值示例：
    - `.example.org`：匹配 example.org 及其子域名。
    - `example.org`：仅匹配 example.org。
    - `*.example.org`：保留原通配符表达式。
    """
    rule = line.strip().lstrip("\ufeff")
    if not rule or rule.startswith(("#", "!", "[")):
        return None

    # 白名单里的 @@ 只表示解除拦截；生成单独 allow.mrs 时需要去掉该前缀。
    if rule.startswith("@@"):
        rule = rule[2:].strip()

    # hosts 写法：127.0.0.1 example.org 或 0.0.0.0 example.org。
    parts = rule.split()
    if len(parts) >= 2 and is_ip_or_cidr(parts[0]):
        domain = parts[1].strip().lower()
        return domain if looks_like_domain(domain) else None

    # GOODBYEADS 的 allow.txt 含大量 `@@.example/path` 这类浏览器过滤例外。
    # 它们不能安全放大成 mihomo 域名白名单；白名单只接受 `||` 域名锚定规则。
    if not allow_plain and not rule.startswith("||"):
        return None

    # 正则规则无法可靠转换为 domain 类型 mrs，直接跳过。
    if len(rule) >= 2 and rule.startswith("/") and rule.endswith("/"):
        return None

    rule, options = split_adguard_options(rule)
    if not has_only_safe_options(options):
        return None
    # `.mrs` 的 domain 行无法表达路径/资源类型等条件；遇到路径规则时跳过，
    # 避免把 `@@||example.com/favicon.ico` 误放大成整个域名白名单。
    if "/" in rule:
        return None

    # AdGuard `||example.org^` 表示域名及子域名；mihomo 用 `.example.org` 表示。
    if rule.startswith("||"):
        domain = extract_until_separator(rule[2:]).lower()
        if not looks_like_domain(domain):
            return None
        # 含 `*` 的规则保留通配符；普通域名加 `.` 转为后缀匹配。
        return domain if "*" in domain else f".{domain}"

    # AdGuard `|example.org^` 或普通域名规则。
    domain = extract_until_separator(rule).lower()
    return domain if looks_like_domain(domain) else None


def collect_domain_rules(sources: list[str], allow_plain: bool = True) -> tuple[list[str], int]:
    """读取多个来源，清洗、去重并返回 domain 文本规则和跳过数量。"""
    rules: list[str] = []
    seen: set[str] = set()
    skipped = 0

    for source in sources:
        for line in read_text_source(source).splitlines():
            converted = convert_adguard_rule(line, allow_plain=allow_plain)
            if converted is None:
                skipped += 1
                continue
            if converted not in seen:
                seen.add(converted)
                rules.append(converted)

    return rules, skipped


def domain_suffix_covers(parent: str, child: str) -> bool:
    """判断 mihomo domain 后缀规则 parent 是否会覆盖 child。"""
    if not parent.startswith(".") or not child.startswith("."):
        return False
    return child != parent and child.endswith(parent)


def filter_allow_rules(allow_rules: list[str], block_rules: list[str]) -> tuple[list[str], int, int]:
    """收窄白名单，避免作为前置 DIRECT 规则时覆盖黑名单。

    - 含 `*` 的白名单规则语义过宽，跳过。
    - `.example.com` 若会覆盖黑名单里的 `.ad.example.com`，跳过。
    """
    filtered: list[str] = []
    removed_wildcard = 0
    removed_parent = 0

    for allow_rule in allow_rules:
        if "*" in allow_rule:
            removed_wildcard += 1
            continue
        if any(domain_suffix_covers(allow_rule, block_rule) for block_rule in block_rules):
            removed_parent += 1
            continue
        filtered.append(allow_rule)

    return filtered, removed_wildcard, removed_parent


def write_rules(path: Path, rules: list[str]) -> None:
    """写入清洗后的 domain 文本规则，不追加额外空白行。"""
    path.write_text("\n".join(rules), encoding="utf-8")


def convert_to_mrs(mihomo: str, source: Path, output: Path) -> None:
    """调用 mihomo 生成 domain 类型 `.mrs` 文件。"""
    subprocess.run(
        [mihomo, "convert-ruleset", "domain", "text", str(source), str(output)],
        check=True,
    )


def main() -> None:
    """命令行入口。"""
    parser = argparse.ArgumentParser(description="生成 mihomo 黑白名单 domain mrs")
    parser.add_argument("--local-block", default="block_rules.txt", help="本地黑名单 txt")
    parser.add_argument("--local-allow", default="allow_rules.txt", help="本地白名单 txt")
    parser.add_argument("--block-domain-output", default="mihomo_block_domains.txt", help="清洗后的黑名单 domain 文本")
    parser.add_argument("--allow-domain-output", default="mihomo_allow_domains.txt", help="清洗后的白名单 domain 文本")
    parser.add_argument("--block-mrs-output", default="block_rules.mrs", help="黑名单 mrs 输出路径")
    parser.add_argument("--allow-mrs-output", default="allow_rules.mrs", help="白名单 mrs 输出路径")
    parser.add_argument("--mihomo", default="mihomo", help="mihomo 可执行文件路径")
    parser.add_argument("--skip-mrs", action="store_true", help="只生成清洗后的 domain 文本，不生成 mrs")
    parser.add_argument("--require-mihomo", action="store_true", help="找不到 mihomo 时直接失败")
    args = parser.parse_args()

    block_domains, block_skipped = collect_domain_rules([GOODBYEADS_BLOCK_URL, args.local_block], allow_plain=True)
    allow_domains, allow_skipped = collect_domain_rules([GOODBYEADS_ALLOW_URL, args.local_allow], allow_plain=False)

    allow_domains, removed_allow_wildcard, removed_allow_parent = filter_allow_rules(allow_domains, block_domains)

    # 白名单用于覆盖黑名单时，黑名单里保留同一条规则会让最终效果依赖 mihomo 规则顺序。
    # 这里直接剔除精确交集，避免 allow/block provider 自相矛盾。
    allow_set = set(allow_domains)
    original_block_count = len(block_domains)
    block_domains = [rule for rule in block_domains if rule not in allow_set]
    removed_conflicts = original_block_count - len(block_domains)

    block_domain_output = Path(args.block_domain_output)
    allow_domain_output = Path(args.allow_domain_output)
    write_rules(block_domain_output, block_domains)
    write_rules(allow_domain_output, allow_domains)

    print(f"黑名单清洗完成：{len(block_domains)} 条，跳过 {block_skipped} 行 -> {block_domain_output}")
    print(f"白名单清洗完成：{len(allow_domains)} 条，跳过 {allow_skipped} 行 -> {allow_domain_output}")
    print(f"已从白名单剔除 {removed_allow_wildcard} 条含通配符的宽泛规则")
    print(f"已从白名单剔除 {removed_allow_parent} 条会覆盖黑名单子域的父域规则")
    print(f"已从黑名单剔除 {removed_conflicts} 条与白名单完全相同的规则")

    if args.skip_mrs:
        return

    mihomo_path = shutil.which(args.mihomo) or (args.mihomo if Path(args.mihomo).is_file() else "")
    if not mihomo_path:
        message = "未找到 mihomo，可用 --skip-mrs 只生成清洗 txt，或用 --mihomo 指定路径"
        if args.require_mihomo:
            raise FileNotFoundError(message)
        print(message, file=sys.stderr)
        return

    convert_to_mrs(mihomo_path, block_domain_output, Path(args.block_mrs_output))
    convert_to_mrs(mihomo_path, allow_domain_output, Path(args.allow_mrs_output))
    print(f"已生成 mrs：{args.block_mrs_output}、{args.allow_mrs_output}")


if __name__ == "__main__":
    main()
