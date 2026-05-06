import re
from dataclasses import dataclass, field
from typing import List, Tuple, Optional


@dataclass
class Field:
    num: int
    wt: int
    value: object
    nested: List["Field"] = field(default_factory=list)


def read_varint(buf: bytes, i: int) -> Tuple[Optional[int], int]:
    shift = 0
    result = 0
    start = i
    while i < len(buf) and shift <= 63:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i
        shift += 7
    return None, start


def parse_message(buf: bytes, max_depth: int = 8, depth: int = 0, budget: int = 5000) -> List[Field]:
    out: List[Field] = []
    i = 0
    n = len(buf)
    while i < n and budget > 0:
        budget -= 1
        tag, ni = read_varint(buf, i)
        if tag is None:
            break
        i = ni
        wt = tag & 0x7
        num = tag >> 3
        if num <= 0:
            break
        if wt == 0:
            v, i2 = read_varint(buf, i)
            if v is None:
                break
            i = i2
            out.append(Field(num, wt, v))
        elif wt == 1:
            if i + 8 > n:
                break
            v = int.from_bytes(buf[i:i+8], "little", signed=False)
            i += 8
            out.append(Field(num, wt, v))
        elif wt == 5:
            if i + 4 > n:
                break
            v = int.from_bytes(buf[i:i+4], "little", signed=False)
            i += 4
            out.append(Field(num, wt, v))
        elif wt == 2:
            ln, i2 = read_varint(buf, i)
            if ln is None:
                break
            i = i2
            if i + ln > n:
                break
            b = buf[i:i+ln]
            i += ln
            f = Field(num, wt, b)
            if depth < max_depth and ln >= 2:
                nested = parse_message(b, max_depth=max_depth, depth=depth+1, budget=budget)
                if nested:
                    f.nested = nested
            out.append(f)
        else:
            # groups not expected
            break
    return out


def collect_varints(fields: List[Field], depth: int = 0) -> List[int]:
    out: List[int] = []
    for f in fields:
        if f.wt == 0 and isinstance(f.value, int):
            out.append(f.value)
        if f.nested:
            out.extend(collect_varints(f.nested, depth + 1))
    return out


def find_first_iso_packet(text: str) -> Optional[Tuple[int, bytes]]:
    pos = text.find("ISO (RECURSOS)")
    if pos < 0:
        return None
    # Expand to the full line containing it
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end < 0:
        line_end = len(text)
    header_line = text[line_start:line_end].strip("\r\n")
    mhdr = re.search(r"#(\d+)\b", header_line)
    if not mhdr:
        return None
    idx = int(mhdr.group(1))

    after = text[line_end:]
    hex_pos = after.find("HEX:")
    if hex_pos < 0:
        return None
    # saltar el resto de la línea "HEX:" y empezar en la siguiente
    tail = after[hex_pos:]
    nl = tail.find("\n")
    if nl >= 0:
        tail = tail[nl + 1 :]
    else:
        tail = ""
    # Collect hex lines until blank line or separator
    hex_lines = []
    for line in tail.splitlines():
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if line.startswith("----") or line.startswith("#"):
            break
        hex_lines.append(line)
        if len(hex_lines) > 5000:
            break
    # Extract byte tokens (2 hex)
    toks = re.findall(r"\b[0-9A-Fa-f]{2}\b", "\n".join(hex_lines))
    if not toks:
        return None
    raw = bytes.fromhex("".join(toks))
    return idx, raw


def main():
    path = r"C:\Users\fabia\Desktop\dc\20260504_203229_ll_p1_to_190.txt"
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    found = find_first_iso_packet(text)
    if not found:
        print("No se encontró ISO (RECURSOS) en el log.")
        return
    pkt, raw = found
    print("ISO packet #", pkt, "bytes=", len(raw))
    fields = parse_message(raw)
    all_vars = collect_varints(fields)
    # Find candidate nested blobs that contain resource-ish IDs (513k-519k)
    resource_ids = [v for v in all_vars if 512000 <= v <= 519999]
    print("resource-like varints found:", len(resource_ids), "unique:", len(set(resource_ids)))
    if resource_ids:
        print("sample:", sorted(set(resource_ids))[:20])
    # Print top-level field stats
    from collections import Counter
    top = Counter([f.num for f in fields])
    print("top-level field numbers:", top.most_common(20))
    # Print nested candidates: length-delimited fields whose nested contains many resource ids
    candidates = []
    def scan(fs: List[Field], path_nums: Tuple[int,...]):
        for f in fs:
            if f.wt == 2 and f.nested:
                vars2 = collect_varints(f.nested)
                rid = [v for v in vars2 if 512000 <= v <= 519999]
                if len(set(rid)) >= 2 or len(rid) >= 3:
                    candidates.append((path_nums + (f.num,), len(rid), len(set(rid)), len(f.value)))
                scan(f.nested, path_nums + (f.num,))
    scan(fields, ())
    candidates.sort(key=lambda x: (x[2], x[1], x[3]), reverse=True)
    print("\nCandidates (path, count, uniq, bytes):")
    for c in candidates[:30]:
        print(" ", c)


if __name__ == "__main__":
    main()

