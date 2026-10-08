#!/usr/bin/env python3
"""Dump every memory-map region from the FDTs embedded in a Qualcomm xbl_config.img.

Why this exists: `ghostlock-extract` parses this same FDT to recover
`kernel_phys_load`, but it only returns the Kernel row. `kernel_phys_offset`
(the DRAM base) has no other static source — `iomem.rs` only reads it from
`/proc/iomem`, which needs root, and `/proc/device-tree/*/reg` is usually
blocked by SELinux for shell. Leaving `kernel_phys_offset` unset makes native
fall back to the compiled `P0_PHYS_OFFSET` (0x80000000), and when that is wrong
for the platform every kernel write lands at the wrong address — the route
still reports success, but W1's read-back never changes.

This prints the whole table so the DRAM base can be read off it, with the
Kernel row cross-checked against what the extractor reported.

    python3 -I xbl_memory_map.py /path/to/xbl_config.img

Read-only. No device, no root.
"""
import argparse
import struct
import sys

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def be32(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def find_fdts(data):
    """Every plausible FDT blob in the image, as (offset, size)."""
    out, pos = [], 0
    while True:
        pos = data.find(b"\xd0\x0d\xfe\xed", pos)
        if pos < 0:
            return out
        if pos + 40 <= len(data):
            total = be32(data, pos + 4)
            version = be32(data, pos + 20)
            if 40 < total <= len(data) - pos and version in (16, 17):
                out.append((pos, total))
        pos += 4


def parse_fdt(blob):
    """Walk the struct block; yield (path, {prop: bytes})."""
    total, off_struct, off_strings = be32(blob, 4), be32(blob, 8), be32(blob, 12)
    size_struct = be32(blob, 36) if be32(blob, 20) >= 17 else total - off_struct
    end = min(off_struct + size_struct, total, len(blob))
    pos, stack, nodes = off_struct, [], []
    props = {}
    while pos + 4 <= end:
        tok = be32(blob, pos)
        pos += 4
        if tok == FDT_BEGIN_NODE:
            nul = blob.index(b"\0", pos)
            name = blob[pos:nul].decode("utf-8", "replace")
            pos = (nul + 4) & ~3
            stack.append(name)
            props = {}
            nodes.append(("/" + "/".join(s for s in stack if s), props))
        elif tok == FDT_END_NODE:
            if stack:
                stack.pop()
        elif tok == FDT_PROP:
            if pos + 8 > end:
                break
            length, nameoff = be32(blob, pos), be32(blob, pos + 4)
            pos += 8
            nul = blob.index(b"\0", off_strings + nameoff)
            key = blob[off_strings + nameoff:nul].decode("utf-8", "replace")
            props[key] = bytes(blob[pos:pos + length])
            pos = (pos + length + 3) & ~3
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            break
        else:
            break
    return nodes


def cells(reg, ac, sc):
    """Split a `reg` blob into (base, size) pairs using #address/#size-cells."""
    width = 4 * (ac + sc)
    if width == 0 or len(reg) % width:
        return []
    out = []
    for i in range(0, len(reg), width):
        off, base, size = i, 0, 0
        for _ in range(ac):
            base = (base << 32) | be32(reg, off)
            off += 4
        for _ in range(sc):
            size = (size << 32) | be32(reg, off)
            off += 4
        out.append((base, size))
    return out


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n/1:.0f} {unit}"
        n /= 1024.0
    return str(n)


def size_h(n):
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GiB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.0f} MiB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KiB"
    return f"{n} B"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", help="xbl_config.img (or any image with embedded FDTs)")
    ap.add_argument("--all-nodes", action="store_true",
                    help="list every node carrying a reg, not only memorymap ones")
    args = ap.parse_args()

    data = open(args.image, "rb").read()
    blobs = find_fdts(data)
    if not blobs:
        sys.exit("no FDT magic found in this image")
    print(f"image: {args.image}  ({len(data)} bytes)")
    print(f"embedded FDTs: {len(blobs)}  "
          f"at {', '.join(hex(o) for o, _ in blobs[:8])}"
          f"{' …' if len(blobs) > 8 else ''}\n")

    rows = []
    for off, total in blobs:
        blob = data[off:off + total]
        try:
            nodes = parse_fdt(blob)
        except Exception as err:  # a false-positive magic is expected
            print(f"  (FDT @ {hex(off)} unparsable: {err})", file=sys.stderr)
            continue
        depth_cells = {}
        for path, props in nodes:
            if "#address-cells" in props:
                depth_cells[path] = (
                    be32(props["#address-cells"], 0),
                    be32(props.get("#size-cells", b"\0\0\0\1"), 0),
                )
        for path, props in nodes:
            if "reg" not in props:
                continue
            if not args.all_nodes and "/memorymap" not in path:
                continue
            ac, sc = 1, 1
            parent = path.rsplit("/", 1)[0] or "/"
            while parent:
                if parent in depth_cells:
                    ac, sc = depth_cells[parent]
                    break
                if parent == "/":
                    break
                parent = parent.rsplit("/", 1)[0] or "/"
            label = props.get("label", props.get("name", b"")).split(b"\0")[0]
            for base, size in cells(props["reg"], ac, sc):
                rows.append((base, size, label.decode("utf-8", "replace"),
                             path, hex(off)))

    if not rows:
        sys.exit("no memorymap reg entries found (try --all-nodes)")

    rows = sorted(set(rows))
    print(f"{'base':>14}  {'size':>14}  {'size':>10}  label / node")
    for base, size, label, path, fdt_off in rows:
        name = label or path.rsplit("/", 1)[-1]
        print(f"  0x{base:010x}  0x{size:010x}  {size_h(size):>10}  {name}")

    bases = [r[0] for r in rows if r[1] > 0]
    print()
    print(f"lowest region base            = 0x{min(bases):x}  "
          f"({min(bases)})   <- kernel_phys_offset candidate")
    kernel = [r for r in rows if r[2].lower() == "kernel"
              or r[3].rstrip("/").endswith("kernel")]
    if kernel:
        print("rows labelled Kernel          = "
              + ", ".join(f"0x{b:x}/0x{s:x}" for b, s, *_ in kernel)
              + "   <- cross-check against the extractor's kernel_phys_load")
    print()
    print("Treat the lowest base as a CANDIDATE, not a fact: Linux takes "
          "PHYS_OFFSET from\nthe first memblock of its own DT /memory node, which "
          "is not necessarily the\nlowest row the bootloader lists. Confirm against "
          "a rooted /proc/iomem\n(`ghostlock-extract --iomem <dump>`) before "
          "treating it as verified.")


if __name__ == "__main__":
    main()
