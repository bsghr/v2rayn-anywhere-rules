import ipaddress
import struct
import urllib.request
from pathlib import Path


GEOSITE_URL = (
    "https://github.com/Loyalsoldier/v2ray-rules-dat/"
    "releases/latest/download/geosite.dat"
)

GEOIP_URL = (
    "https://github.com/Loyalsoldier/v2ray-rules-dat/"
    "releases/latest/download/geoip.dat"
)

ADGUARD_CN_URL = (
    "https://filters.adtidy.org/android/filters/224_optimized.txt"
)

OUTPUT_DIR = Path("rules")

# Anywhere 单个规则集上限为 100000。
# 留出余量，避免后续规则数量变化导致刚好超过上限。
MAX_RULES = 99999


# ------------------------------------------------------------
# Protobuf 基础解析
# ------------------------------------------------------------

def read_varint(data, pos):
    value = 0
    shift = 0

    while pos < len(data):
        byte = data[pos]
        pos += 1

        value |= (byte & 0x7F) << shift

        if not (byte & 0x80):
            return value, pos

        shift += 7

        if shift >= 64:
            raise ValueError("invalid protobuf varint")

    raise ValueError("unexpected end of protobuf data")


def read_fields(data):
    """
    返回：
        [(field_number, wire_type, value), ...]
    """

    fields = []
    pos = 0

    while pos < len(data):
        key, pos = read_varint(data, pos)

        field_number = key >> 3
        wire_type = key & 0x07

        if wire_type == 0:
            value, pos = read_varint(data, pos)

        elif wire_type == 1:
            value = data[pos:pos + 8]
            pos += 8

        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            value = data[pos:pos + length]
            pos += length

        elif wire_type == 5:
            value = data[pos:pos + 4]
            pos += 4

        else:
            raise ValueError(
                f"unsupported protobuf wire type: {wire_type}"
            )

        fields.append(
            (field_number, wire_type, value)
        )

    return fields


# ------------------------------------------------------------
# GeoSite
# ------------------------------------------------------------

DOMAIN_PLAIN = 0
DOMAIN_REGEX = 1
DOMAIN_ROOT = 2
DOMAIN_FULL = 3


def parse_domain(data):
    domain_type = DOMAIN_PLAIN
    value = None

    for field, wire_type, raw in read_fields(data):

        if field == 1 and wire_type == 0:
            domain_type = raw

        elif field == 2 and wire_type == 2:
            value = raw.decode(
                "utf-8",
                errors="ignore"
            ).strip().lower()

    if not value:
        return None

    return domain_type, value


def parse_geosite_entry(data):
    """
    解析一个 GeoSite：

        country_code
        repeated Domain
    """

    country_code = None
    domains = []

    for field, wire_type, raw in read_fields(data):

        if field == 1 and wire_type == 2:
            country_code = raw.decode(
                "utf-8",
                errors="ignore"
            ).strip().lower()

        elif field == 2 and wire_type == 2:
            domain = parse_domain(raw)

            if domain:
                domains.append(domain)

    return country_code, domains


def parse_geosite(data, target):
    """
    从 GeoSiteList 中提取指定 category。
    """

    result = []

    for field, wire_type, raw in read_fields(data):

        if field != 1 or wire_type != 2:
            continue

        country_code, domains = parse_geosite_entry(raw)

        if country_code != target.lower():
            continue

        result.extend(domains)

    return result


# ------------------------------------------------------------
# GeoIP
# ------------------------------------------------------------

def parse_cidr(data):
    """
    解析：

        bytes ip = 1
        uint32 prefix = 2
    """

    ip_bytes = None
    prefix = None

    for field, wire_type, raw in read_fields(data):

        if field == 1 and wire_type == 2:
            ip_bytes = raw

        elif field == 2 and wire_type == 0:
            prefix = raw

    if ip_bytes is None or prefix is None:
        return None

    try:
        if len(ip_bytes) == 4:
            network = ipaddress.IPv4Network(
                (ipaddress.IPv4Address(ip_bytes), prefix),
                strict=False
            )
        elif len(ip_bytes) == 16:
            network = ipaddress.IPv6Network(
                (ipaddress.IPv6Address(ip_bytes), prefix),
                strict=False
            )
        else:
            return None

        return str(network)

    except ValueError:
        return None


def parse_geoip_entry(data):
    """
    解析一个 GeoIP：

        country_code
        repeated CIDR
    """

    country_code = None
    cidrs = []

    for field, wire_type, raw in read_fields(data):

        if field == 1 and wire_type == 2:
            country_code = raw.decode(
                "utf-8",
                errors="ignore"
            ).strip().lower()

        elif field == 2 and wire_type == 2:
            cidr = parse_cidr(raw)

            if cidr:
                cidrs.append(cidr)

    return country_code, cidrs


def parse_geoip(data, target):
    """
    从 GeoIPList 中提取指定 category。
    """

    result = []

    for field, wire_type, raw in read_fields(data):

        if field != 1 or wire_type != 2:
            continue

        country_code, cidrs = parse_geoip_entry(raw)

        if country_code != target.lower():
            continue

        result.extend(cidrs)

    return result


# ------------------------------------------------------------
# 下载
# ------------------------------------------------------------

def download(url):
    print(f"Downloading: {url}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "v2rayn-anywhere-rules"
        }
    )

    with urllib.request.urlopen(
        request,
        timeout=120
    ) as response:
        return response.read()

# ------------------------------------------------------------
# AdGuard 中文过滤器
# ------------------------------------------------------------

def parse_adguard_domains(data):
    """
    从 AdGuard 过滤器中提取可转换为
    Anywhere Domain Suffix 的域名规则。

    仅处理：
        ||example.com^
        ||example.com^$third-party

    不处理：
        @@ 例外规则
        CSS 规则
        Scriptlet
        正则规则
        URL 路径规则
        IP 地址规则
        通配符域名
    """

    rules = set()

    text = data.decode(
        "utf-8",
        errors="ignore"
    )

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("!"):
            continue

        if line.startswith("@@"):
            continue

        if not line.startswith("||"):
            continue

        body = line[2:]

        domain = body.split(
            "^",
            1
        )[0]

        if not domain:
            continue

        if "/" in domain:
            continue

        if "*" in domain:
            continue

        if "?" in domain:
            continue

        if ":" in domain:
            continue

        if "." not in domain:
            continue

        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass

        rules.add(
            (2, domain.lower())
        )

    return sorted(
        rules,
        key=lambda x: x[1]
    )

# ------------------------------------------------------------
# Anywhere Domain 转换
# ------------------------------------------------------------

def convert_domain(domain_type, value):
    """
    V2Ray Domain：

        Plain      → Anywhere Keyword
        RootDomain → Anywhere Domain Suffix
        Full       → Anywhere Domain Suffix

    Regex 不支持，跳过。

    Full 在 Anywhere 中没有完全对应的规则类型，
    因此使用 Domain Suffix 表达。
    """

    if domain_type == DOMAIN_REGEX:
        return None

    if domain_type == DOMAIN_PLAIN:
        return 3, value

    if domain_type in (
        DOMAIN_ROOT,
        DOMAIN_FULL,
    ):
        return 2, value

    return None


def build_domain_rules(domains):
    rules = set()

    for domain_type, value in domains:

        converted = convert_domain(
            domain_type,
            value
        )

        if converted is None:
            continue

        rule_type, value = converted

        rules.add(
            (rule_type, value)
        )

    return sorted(
        rules,
        key=lambda x: (
            x[0],
            x[1]
        )
    )


# ------------------------------------------------------------
# Anywhere IP 转换
# ------------------------------------------------------------

def build_ip_rules(cidrs):
    rules = set()

    for cidr in cidrs:

        try:
            network = ipaddress.ip_network(
                cidr,
                strict=False
            )

        except ValueError:
            continue

        if network.version == 4:
            rule_type = 0
        else:
            rule_type = 1

        rules.add(
            (rule_type, str(network))
        )

    return sorted(
        rules,
        key=lambda x: (
            x[0],
            x[1]
        )
    )


# ------------------------------------------------------------
# 写入 ARR S
# ------------------------------------------------------------

def write_arrs(
    name,
    routing,
    rules,
    prefix
):
    """
    自动拆分超过 MAX_RULES 的规则集。
    """

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    chunks = [
        rules[i:i + MAX_RULES]
        for i in range(
            0,
            len(rules),
            MAX_RULES
        )
    ]

    if not chunks:
        chunks = [[]]

    output_files = []

    for index, chunk in enumerate(chunks, 1):

        if len(chunks) == 1:
            filename = f"{prefix}.arrs"
            display_name = name
        else:
            filename = (
                f"{prefix}_{index:02d}.arrs"
            )
            display_name = (
                f"{name}_{index:02d}"
            )

        path = OUTPUT_DIR / filename

        with path.open(
            "w",
            encoding="utf-8"
        ) as f:

            f.write(
                f"# NAME: {display_name}\n"
            )

            f.write(
                "# GENERATED-FOR: Anywhere Routing Rule Set\n"
            )

            f.write(
                f"# RULES: {len(chunk)}\n"
            )

            f.write(
                "# SOURCE: Loyalsoldier/v2ray-rules-dat\n"
            )

            f.write("\n")

            f.write(
                f"name = {display_name}\n"
            )

            f.write(
                f"routing = {routing}\n"
            )

            for rule_type, value in chunk:

                f.write(
                    f"{rule_type}, {value}\n"
                )

        output_files.append(path)

    return output_files


# ------------------------------------------------------------
# 主程序
# ------------------------------------------------------------

def main():

    print("=" * 60)
    print("V2Ray Geo → Anywhere ARR S")
    print("=" * 60)

    geosite_data = download(
        GEOSITE_URL
    )

    geoip_data = download(
        GEOIP_URL
    )

    adguard_data = download(
    ADGUARD_CN_URL
    )

    print(
        f"geosite.dat: {len(geosite_data):,} bytes"
    )

    print(
        f"geoip.dat:   {len(geoip_data):,} bytes"
    )

    # --------------------------------------------------------
    # Domain
    # --------------------------------------------------------

    domain_categories = {
        "private": (
            "Private_Domain",
            1
        ),

        "cn": (
            "China_Domain",
            1
        ),

        
        "twitter": (
            "Twitter",
            1
        ),

        "openai": (
            "OpenAI",
            1
        ),

        "spotify": (
            "Spotify",
            1
        ),

        "tiktok": (
            "TikTok",
            1
        ),
        
        "category-ads-all": (
            "Advertising",
            2
        ),

        "ads": (
            "Advertising_CN",
            2
        )
    }

    for category, (
        name,
        routing
    ) in domain_categories.items():

        print()
        print(
            f"[GeoSite] {category}"
        )

        domains = parse_geosite(
            geosite_data,
            category
        )

        rules = build_domain_rules(
            domains
        )

        files = write_arrs(
            name=name,
            routing=routing,
            rules=rules,
            prefix=name
        )

        print(
            f"  source domains : {len(domains):,}"
        )

        print(
            f"  output rules   : {len(rules):,}"
        )

        print(
            f"  output files   : {len(files)}"
        )

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    ip_categories = {
        "private": (
            "Private_IP",
            1
        ),

        "cn": (
            "China_IP",
            1
        ),
    }

    for category, (
        name,
        routing
    ) in ip_categories.items():

        print()
        print(
            f"[GeoIP] {category}"
        )

        cidrs = parse_geoip(
            geoip_data,
            category
        )

        rules = build_ip_rules(
            cidrs
        )

        files = write_arrs(
            name=name,
            routing=routing,
            rules=rules,
            prefix=name
        )

        print(
            f"  source CIDRs   : {len(cidrs):,}"
        )

        print(
            f"  output rules   : {len(rules):,}"
        )

        print(
            f"  output files   : {len(files)}"
        )

    print()
    print("=" * 60)
    print("Conversion completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
