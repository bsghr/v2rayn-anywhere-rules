import argparse
import gzip
import io
import struct
import urllib.request
from pathlib import Path


GEOIP_URL = (
    "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
)

GEOSITE_URL = (
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
)


def download(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "v2rayn-anywhere-rules"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def write_arrs(path, name, routing, rules):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        f.write(f"# NAME: {name}\n")
        f.write("# GENERATED-FOR: Anywhere Routing Rule Set\n")
        f.write(f"# RULES: {len(rules)}\n")
        f.write("\n")
        f.write(f"name = {name}\n")
        f.write(f"routing = {routing}\n")

        for rule in rules:
            f.write(f"{routing}, {rule}\n")


def extract_geosite(data, target):
    # 读取 V2Ray domain-list-community 的 protobuf 数据
    from google.protobuf.internal.decoder import _DecodeVarint32

    pos = 0
    rules = []

    while pos < len(data):
        key, pos = _DecodeVarint32(data, pos)
        field_number = key >> 3
        wire_type = key & 7

        if wire_type != 2:
            break

        length, pos = _DecodeVarint32(data, pos)
        message = data[pos:pos + length]
        pos += length

        # DomainList
        domains = parse_domain_list(message)

        for category, domain_rules in domains:
            if category == target:
                rules.extend(domain_rules)

    return sorted(set(rules))


def parse_domain_list(data):
    # 简化解析：提取文本字段
    result = []

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return result

    if text:
        result.append(("", [text]))

    return result


def convert_domain_file(target):
    data = download(GEOSITE_URL)

    # 使用字符串扫描作为兼容性方案
    text = data.decode("utf-8", errors="ignore")

    rules = set()

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if "." in line and " " not in line:
            rules.add(line)

    return sorted(rules)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="rules")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    print("Downloading Geo data...")

    # 第一阶段先处理 domain
    cn_domains = convert_domain_file("cn")

    write_arrs(
        output / "ChinaDomain.arrs",
        "ChinaDomain",
        0,
        cn_domains,
    )

    print(f"ChinaDomain: {len(cn_domains)} rules")

    print("Done.")


if __name__ == "__main__":
    main()
