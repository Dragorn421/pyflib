# SPDX-FileCopyrightText: 2026 Dragorn421
# SPDX-License-Identifier: CC0-1.0

import dataclasses
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import Section, SymbolTableSection
import numpy as np


# https://refspecs.linuxfoundation.org/elf/mipsabi.pdf
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6


reloc_target_offsets_by_r_info_type = {
    R_MIPS_26: np.array([0, 1, 2, 3]),
    R_MIPS_HI16: np.array([2, 3]),
    R_MIPS_LO16: np.array([2, 3]),
}


@dataclasses.dataclass
class FunctionPattern:
    data: np.ndarray
    data_offsets: np.ndarray

    def check(self, rom_data: np.ndarray, offset: int):
        return np.all(rom_data[offset:][self.data_offsets] == self.data)

    def find(self, rom_data: np.ndarray):
        for offset in range(len(rom_data)):
            try:
                if self.check(rom_data, offset):
                    yield offset
            except IndexError:
                break


def elf_to_function_patterns(elf_p: Path, *, verbose=False):
    with elf_p.open("rb") as f:
        elf = ELFFile(f)

        text_section_index = elf.get_section_index(".text")
        if text_section_index is None:
            return {}
        text_section = elf.get_section(text_section_index)
        assert isinstance(text_section, Section)
        text_data = np.frombuffer(text_section.data(), dtype=np.uint8)
        if verbose:
            print(text_data.shape, text_data.dtype)

        text_reloc_section = elf.get_section_by_name(".rel.text")
        if text_reloc_section is None:
            text_relocs = []
        else:
            assert isinstance(text_reloc_section, RelocationSection)
            text_relocs = list(text_reloc_section.iter_relocations())
            if verbose:
                print(text_relocs)

        fps: dict[str, FunctionPattern] = {}

        symtab = elf.get_section_by_name(".symtab")
        assert isinstance(symtab, SymbolTableSection)
        for sym in symtab.iter_symbols():
            if (
                sym.entry["st_info"]["type"] == "STT_FUNC"
                and sym.entry["st_shndx"] == text_section_index
            ):
                if verbose:
                    print(sym.name, sym.entry)

                func_offset = sym.entry["st_value"]
                # TODO idk if we can trust st_size. I know IDO is funky with symbol sizes
                func_size = sym.entry["st_size"]
                func_data_whole = text_data[func_offset:][:func_size]

                data_offsets = np.arange(func_size)
                for reloc in text_relocs:
                    reloc_offset = reloc.entry["r_offset"]
                    if func_offset <= reloc_offset < func_offset + func_size:
                        if verbose:
                            print(reloc)
                        reloc_target_offsets = reloc_target_offsets_by_r_info_type[
                            reloc.entry["r_info_type"]
                        ]
                        for v in reloc_target_offsets + (reloc_offset - func_offset):
                            data_offsets = data_offsets[data_offsets != v]

                fp = FunctionPattern(func_data_whole[data_offsets], data_offsets)
                fps[sym.name] = fp
        return fps


def test_FunctionPattern():
    rom_data = np.array([0, 1, 2, 3, 4, 5, 6, 7])
    fp = FunctionPattern(
        np.array([1, 2, 4]),
        np.array([0, 1, 3]),
    )
    assert list(fp.find(rom_data)) == [1]


def test_elf_to_function_patterns():
    from pprint import pprint

    fps = elf_to_function_patterns(
        Path("test.o"),
        verbose=True,
    )
    pprint(fps)
    rom_data = np.frombuffer(Path("rom.bin").read_bytes(), dtype=np.uint8)
    for func_name, fp in fps.items():
        print(func_name, list(map(hex, fp.find(rom_data))))


def test():
    test_FunctionPattern()
    test_elf_to_function_patterns()


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true")
    parser.add_argument("rom", type=Path)
    parser.add_argument("objects", type=Path, nargs="+")
    args = parser.parse_args()

    if args.test:
        test()
        return

    rom_data = np.frombuffer(args.rom.read_bytes(), dtype=np.uint8)
    matches = []
    for i, object_p in enumerate(args.objects):
        print(i, "/", len(args.objects), str(object_p), flush=True)
        fps = elf_to_function_patterns(object_p)
        for func_name, fp in fps.items():
            offsets = list(fp.find(rom_data))
            if len(offsets) != 0:
                print(func_name, list(map(hex, offsets)), flush=True)
                matches.append((str(object_p), func_name, offsets))

    import json

    with open("matches.json", "w") as f:
        json.dump(matches, f)


if __name__ == "__main__":
    main()
