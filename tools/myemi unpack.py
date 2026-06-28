#!/usr/bin/env python3

from __future__ import annotations

import argparse
import io
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAGIC = b"MTK_BLOADER_INFO"


@dataclass
class BloaderElement:
    index: int
    sub_version: int
    type: int
    emmc_id: bytes
    fw_id: bytes
    emi_cona_val: int
    dramc_drvctl0_val: int
    dramc_drvctl1_val: int
    dramc_actim_val: int
    dramc_gddr3ctl1_val: int
    dramc_conf1_val: int
    dramc_ddr2ctl_val: int
    dramc_test2_3_val: int
    dramc_conf2_val: int
    dramc_pd_ctrl_val: int
    dramc_padctl3_val: int
    dramc_dqodly_val: int
    dramc_addr_output_dly: int
    dramc_clk_output_dly: int
    dramc_actim1_val: int
    dramc_misctl0_val: int
    dramc_actim05t_val: int
    dram_rank_size: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    lpddr3_mode_reg1: int = 0
    lpddr3_mode_reg2: int = 0
    lpddr3_mode_reg3: int = 0
    lpddr3_mode_reg5: int = 0
    lpddr3_mode_reg10: int = 0
    lpddr3_mode_reg63: int = 0

    @property
    def emmc_id_hex(self) -> str:
        return "0x" + self.emmc_id.hex().upper() if self.emmc_id else ""

    @property
    def fw_id_hex(self) -> str:
        return "0x" + self.fw_id.hex().upper() if self.fw_id else ""

    def to_dict(self) -> dict[str, Any]:
        def _fmt(v: int) -> str:
            return f"0x{v:08X}"

        return {
            "index": self.index,
            "sub_version": self.sub_version,
            "type": _fmt(self.type),
            "emmc_id": self.emmc_id_hex,
            "fw_id": self.fw_id_hex,
            "emi_cona_val": _fmt(self.emi_cona_val),
            "dramc_drvctl0_val": _fmt(self.dramc_drvctl0_val),
            "dramc_drvctl1_val": _fmt(self.dramc_drvctl1_val),
            "dramc_actim_val": _fmt(self.dramc_actim_val),
            "dramc_gddr3ctl1_val": _fmt(self.dramc_gddr3ctl1_val),
            "dramc_conf1_val": _fmt(self.dramc_conf1_val),
            "dramc_ddr2ctl_val": _fmt(self.dramc_ddr2ctl_val),
            "dramc_test2_3_val": _fmt(self.dramc_test2_3_val),
            "dramc_conf2_val": _fmt(self.dramc_conf2_val),
            "dramc_pd_ctrl_val": _fmt(self.dramc_pd_ctrl_val),
            "dramc_padctl3_val": _fmt(self.dramc_padctl3_val),
            "dramc_dqodly_val": _fmt(self.dramc_dqodly_val),
            "dramc_addr_output_dly": _fmt(self.dramc_addr_output_dly),
            "dramc_clk_output_dly": _fmt(self.dramc_clk_output_dly),
            "dramc_actim1_val": _fmt(self.dramc_actim1_val),
            "dramc_misctl0_val": _fmt(self.dramc_misctl0_val),
            "dramc_actim05t_val": _fmt(self.dramc_actim05t_val),
            "dram_rank_size": [_fmt(v) for v in self.dram_rank_size],
            "lpddr3_mode_reg1": _fmt(self.lpddr3_mode_reg1),
            "lpddr3_mode_reg2": _fmt(self.lpddr3_mode_reg2),
            "lpddr3_mode_reg3": _fmt(self.lpddr3_mode_reg3),
            "lpddr3_mode_reg5": _fmt(self.lpddr3_mode_reg5),
            "lpddr3_mode_reg10": _fmt(self.lpddr3_mode_reg10),
            "lpddr3_mode_reg63": _fmt(self.lpddr3_mode_reg63),
        }


@dataclass
class BloaderInfo:
    offset: int
    header: str
    pre_bin: str
    hex_1: int
    hex_2: int
    hex_3: int
    mtk_bin: str
    elements: list[BloaderElement] = field(default_factory=list)
    trailing_size: int = 0


class _Reader:
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self._data = data
        self._pos = offset

    @property
    def pos(self) -> int:
        return self._pos

    def read(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        if len(chunk) < n:
            raise ValueError(
                f"Unexpected end of data at offset 0x{self._pos:X}: "
                f"need {n} bytes, got {len(chunk)}"
            )
        self._pos += n
        return chunk

    def uint32(self) -> int:
        return struct.unpack_from("<I", self.read(4))[0]

    def uint32_array(self, count: int) -> list[int]:
        return list(struct.unpack_from(f"<{count}I", self.read(4 * count)))

    def cstring(self, n: int) -> str:
        raw = self.read(n)
        return raw.split(b"\x00")[0].decode("ascii", errors="replace")

    def raw(self, n: int) -> bytes:
        return self.read(n)


def _parse_element(r: _Reader, index: int, verbose: bool = False) -> BloaderElement:
    sub_version  = r.uint32()
    type_        = r.uint32()
    emmc_id_len  = r.uint32()
    fw_id_len    = r.uint32()

    emmc_id_raw  = r.raw(16)
    fw_id_raw    = r.raw(8)

    emmc_id = emmc_id_raw[: min(emmc_id_len, 16)]
    fw_id   = fw_id_raw  [: min(fw_id_len,   8)]

    emi_cona_val          = r.uint32()
    dramc_drvctl0_val     = r.uint32()
    dramc_drvctl1_val     = r.uint32()
    dramc_actim_val       = r.uint32()
    dramc_gddr3ctl1_val   = r.uint32()
    dramc_conf1_val       = r.uint32()
    dramc_ddr2ctl_val     = r.uint32()
    dramc_test2_3_val     = r.uint32()
    dramc_conf2_val       = r.uint32()
    dramc_pd_ctrl_val     = r.uint32()
    dramc_padctl3_val     = r.uint32()
    dramc_dqodly_val      = r.uint32()
    dramc_addr_output_dly = r.uint32()
    dramc_clk_output_dly  = r.uint32()
    dramc_actim1_val      = r.uint32()
    dramc_misctl0_val     = r.uint32()
    dramc_actim05t_val    = r.uint32()

    dram_rank_size = r.uint32_array(4)
    _reserved      = r.uint32_array(10)

    lpddr3_mode_reg1  = r.uint32()
    lpddr3_mode_reg2  = r.uint32()
    lpddr3_mode_reg3  = r.uint32()
    lpddr3_mode_reg5  = r.uint32()
    lpddr3_mode_reg10 = r.uint32()
    lpddr3_mode_reg63 = r.uint32()

    if verbose:
        print(f"  [debug] element {index}: type=0x{type_:X}  "
              f"emmc_id_len={emmc_id_len}  fw_id_len={fw_id_len}",
              file=sys.stderr)

    return BloaderElement(
        index=index,
        sub_version=sub_version,
        type=type_,
        emmc_id=emmc_id,
        fw_id=fw_id,
        emi_cona_val=emi_cona_val,
        dramc_drvctl0_val=dramc_drvctl0_val,
        dramc_drvctl1_val=dramc_drvctl1_val,
        dramc_actim_val=dramc_actim_val,
        dramc_gddr3ctl1_val=dramc_gddr3ctl1_val,
        dramc_conf1_val=dramc_conf1_val,
        dramc_ddr2ctl_val=dramc_ddr2ctl_val,
        dramc_test2_3_val=dramc_test2_3_val,
        dramc_conf2_val=dramc_conf2_val,
        dramc_pd_ctrl_val=dramc_pd_ctrl_val,
        dramc_padctl3_val=dramc_padctl3_val,
        dramc_dqodly_val=dramc_dqodly_val,
        dramc_addr_output_dly=dramc_addr_output_dly,
        dramc_clk_output_dly=dramc_clk_output_dly,
        dramc_actim1_val=dramc_actim1_val,
        dramc_misctl0_val=dramc_misctl0_val,
        dramc_actim05t_val=dramc_actim05t_val,
        dram_rank_size=dram_rank_size,
        lpddr3_mode_reg1=lpddr3_mode_reg1,
        lpddr3_mode_reg2=lpddr3_mode_reg2,
        lpddr3_mode_reg3=lpddr3_mode_reg3,
        lpddr3_mode_reg5=lpddr3_mode_reg5,
        lpddr3_mode_reg10=lpddr3_mode_reg10,
        lpddr3_mode_reg63=lpddr3_mode_reg63,
    )


def parse_preloader(data: bytes, verbose: bool = False) -> BloaderInfo:
    magic_offset = data.find(MAGIC)
    if magic_offset == -1:
        raise ValueError("MTK_BLOADER_INFO magic not found in file.")

    if verbose:
        print(f"[debug] magic found at offset 0x{magic_offset:X}", file=sys.stderr)

    r = _Reader(data, magic_offset)

    header  = r.cstring(27)
    pre_bin = r.cstring(61)
    hex_1   = r.uint32()
    hex_2   = r.uint32()
    hex_3   = r.uint32()
    mtk_bin = r.cstring(8)
    total   = r.uint32()

    info = BloaderInfo(
        offset=magic_offset,
        header=header,
        pre_bin=pre_bin,
        hex_1=hex_1,
        hex_2=hex_2,
        hex_3=hex_3,
        mtk_bin=mtk_bin,
    )

    for i in range(total):
        elem = _parse_element(r, i, verbose=verbose)
        info.elements.append(elem)

    info.trailing_size = r.uint32()

    return info


def _h(v: int) -> str:
    return f"0x{v:08X}"


def print_verbose(info: BloaderInfo, out: io.TextIOBase = sys.stdout) -> None:
    sep = "=" * 60

    out.write(f"{sep}\n")
    out.write(f"  MTK Bloader Info  (file offset: 0x{info.offset:X})\n")
    out.write(f"{sep}\n")
    out.write(f"  header          : {info.header}\n")
    out.write(f"  pre_bin         : {info.pre_bin}\n")
    out.write(f"  hex_1           : 0x{info.hex_1:X}\n")
    out.write(f"  hex_2           : 0x{info.hex_2:X}\n")
    out.write(f"  hex_3           : 0x{info.hex_3:X}\n")
    out.write(f"  mtk_bin         : {info.mtk_bin}\n")
    out.write(f"  total elements  : {len(info.elements)}\n")
    out.write(f"  trailing size   : {info.trailing_size}\n\n")

    for e in info.elements:
        dash = "─" * 50
        out.write(f"┌{dash}┐\n")
        out.write(f"│  Element [{e.index}]\n")
        out.write(f"├{dash}┤\n")
        out.write(f"│  sub_version          : {e.sub_version}\n")
        out.write(f"│  type                 : {_h(e.type)}\n")
        out.write(f"│  emmc_id              : {e.emmc_id_hex or '(none)'}\n")
        out.write(f"│  fw_id                : {e.fw_id_hex   or '(none)'}\n")
        out.write(f"│  emi_cona_val         : {_h(e.emi_cona_val)}\n")
        out.write(f"│  dramc_drvctl0_val    : {_h(e.dramc_drvctl0_val)}\n")
        out.write(f"│  dramc_drvctl1_val    : {_h(e.dramc_drvctl1_val)}\n")
        out.write(f"│  dramc_actim_val      : {_h(e.dramc_actim_val)}\n")
        out.write(f"│  dramc_gddr3ctl1_val  : {_h(e.dramc_gddr3ctl1_val)}\n")
        out.write(f"│  dramc_conf1_val      : {_h(e.dramc_conf1_val)}\n")
        out.write(f"│  dramc_ddr2ctl_val    : {_h(e.dramc_ddr2ctl_val)}\n")
        out.write(f"│  dramc_test2_3_val    : {_h(e.dramc_test2_3_val)}\n")
        out.write(f"│  dramc_conf2_val      : {_h(e.dramc_conf2_val)}\n")
        out.write(f"│  dramc_pd_ctrl_val    : {_h(e.dramc_pd_ctrl_val)}\n")
        out.write(f"│  dramc_padctl3_val    : {_h(e.dramc_padctl3_val)}\n")
        out.write(f"│  dramc_dqodly_val     : {_h(e.dramc_dqodly_val)}\n")
        out.write(f"│  dramc_addr_output_dly: {_h(e.dramc_addr_output_dly)}\n")
        out.write(f"│  dramc_clk_output_dly : {_h(e.dramc_clk_output_dly)}\n")
        out.write(f"│  dramc_actim1_val     : {_h(e.dramc_actim1_val)}\n")
        out.write(f"│  dramc_misctl0_val    : {_h(e.dramc_misctl0_val)}\n")
        out.write(f"│  dramc_actim05t_val   : {_h(e.dramc_actim05t_val)}\n")
        sizes = "  ".join(_h(v) for v in e.dram_rank_size)
        out.write(f"│  dram_rank_size       : {sizes}\n")
        out.write(f"│  DRAM type            : LPDDR3\n")
        out.write(f"│  lpddr3_mode_reg1     : {_h(e.lpddr3_mode_reg1)}\n")
        out.write(f"│  lpddr3_mode_reg2     : {_h(e.lpddr3_mode_reg2)}\n")
        out.write(f"│  lpddr3_mode_reg3     : {_h(e.lpddr3_mode_reg3)}\n")
        out.write(f"│  lpddr3_mode_reg5     : {_h(e.lpddr3_mode_reg5)}\n")
        out.write(f"│  lpddr3_mode_reg10    : {_h(e.lpddr3_mode_reg10)}\n")
        out.write(f"│  lpddr3_mode_reg63    : {_h(e.lpddr3_mode_reg63)}\n")
        out.write(f"└{dash}┘\n\n")


_TSV_HEADER = (
    "type\temmc_id\tfw_id\tNAND_Page_Size\t"
    "emi_cona_val\tdramc_drvctl0_val\tdramc_drvctl1_val\t"
    "dramc_actim_val\tdramc_gddr3ctl1_val\tdramc_conf1_val\t"
    "dramc_ddr2ctl_val\tdramc_test2_3_val\tdramc_conf2_val\t"
    "dramc_pd_ctrl_val\tdramc_padctl3_val\tdramc_dqodly_val\t"
    "dramc_addr_output_dly\tdramc_clk_output_dly\tdramc_actim1_val\t"
    "dramc_misctl0_val\tdramc_actim05t_val\t"
    "DRAM_type\t"
    "lpddr3_mode_reg1\tlpddr3_mode_reg2\tlpddr3_mode_reg3\t"
    "lpddr3_mode_reg5\tlpddr3_mode_reg10\tlpddr3_mode_reg63"
)


def print_excel(info: BloaderInfo, out: io.TextIOBase = sys.stdout) -> None:
    out.write(_TSV_HEADER + "\n")
    for e in info.elements:
        row = "\t".join([
            _h(e.type),
            e.emmc_id_hex,
            e.fw_id_hex,
            "",
            _h(e.emi_cona_val),
            _h(e.dramc_drvctl0_val),
            _h(e.dramc_drvctl1_val),
            _h(e.dramc_actim_val),
            _h(e.dramc_gddr3ctl1_val),
            _h(e.dramc_conf1_val),
            _h(e.dramc_ddr2ctl_val),
            _h(e.dramc_test2_3_val),
            _h(e.dramc_conf2_val),
            _h(e.dramc_pd_ctrl_val),
            _h(e.dramc_padctl3_val),
            _h(e.dramc_dqodly_val),
            _h(e.dramc_addr_output_dly),
            _h(e.dramc_clk_output_dly),
            _h(e.dramc_actim1_val),
            _h(e.dramc_misctl0_val),
            _h(e.dramc_actim05t_val),
            "LPDDR3",
            _h(e.lpddr3_mode_reg1),
            _h(e.lpddr3_mode_reg2),
            _h(e.lpddr3_mode_reg3),
            _h(e.lpddr3_mode_reg5),
            _h(e.lpddr3_mode_reg10),
            _h(e.lpddr3_mode_reg63),
        ])
        out.write(row + "\n")


def print_json(info: BloaderInfo, out: io.TextIOBase = sys.stdout) -> None:
    payload = {
        "offset": f"0x{info.offset:X}",
        "header": info.header,
        "pre_bin": info.pre_bin,
        "hex_1": f"0x{info.hex_1:X}",
        "hex_2": f"0x{info.hex_2:X}",
        "hex_3": f"0x{info.hex_3:X}",
        "mtk_bin": info.mtk_bin,
        "trailing_size": info.trailing_size,
        "elements": [e.to_dict() for e in info.elements],
    }
    json.dump(payload, out, indent=2)
    out.write("\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mtk_bloader_info_extractor",
        description="Extract and decode MTK_BLOADER_INFO from MediaTek preloader binaries.",
    )
    p.add_argument("filename", help="Path to the preloader binary")
    p.add_argument("-e", "--excel", action="store_true",
                   help="Output in tab-separated (Excel/spreadsheet) format")
    p.add_argument("-j", "--json", action="store_true",
                   help="Output as JSON")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print debug information to stderr")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    path = Path(args.filename)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1
    if not path.is_file():
        print(f"Error: not a regular file: {path}", file=sys.stderr)
        return 1

    print(f'Using preloader "{path}"', file=sys.stderr)

    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 1

    try:
        info = parse_preloader(data, verbose=args.verbose)
    except ValueError as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1

    print(
        f"Found MTK_BLOADER_INFO header at offset 0x{info.offset:X}  "
        f"({len(info.elements)} element(s))",
        file=sys.stderr,
    )

    out_file: io.TextIOBase
    if args.output:
        try:
            out_file = open(args.output, "w", encoding="utf-8", newline="")
        except OSError as exc:
            print(f"Error opening output file: {exc}", file=sys.stderr)
            return 1
    else:
        out_file = sys.stdout

    try:
        if args.json:
            print_json(info, out_file)
        elif args.excel:
            print_excel(info, out_file)
        else:
            print_verbose(info, out_file)
    finally:
        if args.output:
            out_file.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())