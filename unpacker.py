import gf
import os
from ctypes import cdll, c_char_p, create_string_buffer


class OodleDecompressor:
    """
    Oodle decompression implementation.
    Requires Windows and the external Oodle library.
    """

    def __init__(self, library_path: str) -> None:
        """
        Initialize instance and try to load the library.
        """
        if not os.path.exists(library_path):
            print(f'Looking in {library_path}')
            raise Exception("Could not open Oodle DLL, make sure it is configured correctly.")

        try:
            self.handle = cdll.LoadLibrary(library_path)
        except OSError as e:
            raise Exception(
                "Could not load Oodle DLL, requires Windows and 64bit python to run."
            ) from e

    def decompress(self, payload: bytes, output_size) -> bytes:
        """
        Decompress the payload using the given size.
        """
        output = create_string_buffer(output_size)
        try:
            self.handle.OodleLZ_Decompress(
                c_char_p(payload), len(payload), output, output_size,
                0, 0, 0, None, None, None, None, None, None, 3)
        except OSError:
            return False
        return output.raw




def extract_module(module):
    fb = open(f"{deploy_path}/{module}.module", "rb")
    file_size = fb.seek(0, 2)
    fb.seek(0)
    # Parsing header
    magic = gf.read_uint64(fb)
    assert magic == gf.get_uint64(b"mohd0\x00\x00\x00", 0), "Incorrect file given. Must be a module file."
    unk0x08 = gf.read_uint32(fb)
    unk0x0C = gf.read_uint32(fb)
    files_count = gf.read_uint32(fb)
    unk0x14 = gf.read_uint32(fb)
    # assert unk0x14 == gf.get_uint32(b"\xFF\xFF\xFF\xFF", 0), "Header has non-FFFFFFFF 0x14"
    unk0x18 = gf.read_uint32(fb)
    # assert unk0x18 == gf.get_uint32(b"\x00\x00\x00\x00", 0), "Header has non-0 0x18"
    unk0x1C = gf.read_uint32(fb)
    # assert unk0x1C == gf.get_uint32(b"\xFF\xFF\xFF\xFF", 0), "Header has non-FFFFFFFF 0x1C"
    table3_first_value = gf.read_uint32(fb)
    string_table_length = gf.read_uint32(fb)
    table3_count = gf.read_uint32(fb)
    blocks_count = gf.read_uint32(fb)
    unk0x30 = gf.read_uint32(fb)
    unk0x34 = gf.read_uint32(fb)
    unk0x38 = gf.read_uint32(fb)
    unk0x3C = gf.read_uint32(fb)
    unk0x40 = gf.read_uint32(fb)
    unk0x44 = gf.read_uint32(fb)
    hd1_delta = file_size
    tmp = None

    # Check if we need to use an hd1 file (no hd2 files just yet...)
    fb_hd1 = b""
    if os.path.isfile(f"{deploy_path}/{module}.module_hd1"):
        fb_hd1 = open(f"{deploy_path}/{module}.module_hd1", "rb")

    # Table1
    class FileEntry:
        def __init__(self):
            pass

    files = []
    for i in range(files_count):
        t1e = FileEntry()
        t1e.string_offset = gf.read_uint32(fb)            # 0x00
        t1e.parent_file_index = gf.read_int32(fb)         # 0x04
        t1e.resource_count = gf.read_uint16(fb)           # 0x08
        t1e.block_count = gf.read_uint16(fb)              # 0x0A
        t1e.first_resource_index = gf.read_uint32(fb)     # 0x0C
        t1e.first_block_index = gf.read_uint32(fb)        # 0x10
        t1e.tag = fb.read(4)                              # 0x14
        t1e.local_data_offset = gf.read_uint32(fb)        # 0x18
        t1e.unk0x1C = gf.read_uint32(fb)                  # 0x1C
        t1e.comp_size = gf.read_uint32(fb)                # 0x20
        t1e.decomp_size = gf.read_uint32(fb)              # 0x24
        t1e.unk0x28 = gf.read_uint32(fb)                  # 0x28
        t1e.unk0x2C = gf.read_uint32(fb)                  # 0x2C
        t1e.unk0x30 = gf.read_uint32(fb)                  # 0x30
        t1e.hash = fb.read(8).hex().upper()               # 0x34
        t1e.header_size = gf.read_uint32(fb)              # 0x3C
        t1e.tag_data_size = gf.read_uint32(fb)            # 0x40
        t1e.unk0x44 = gf.read_uint32(fb)                  # 0x44 zeros
        t1e.unk0x48 = gf.read_uint32(fb)                  # 0x48 mostly zeros, sometimes 16
        t1e.unk0x4C = gf.read_uint32(fb)                  # 0x4C two
        t1e.unk0x50 = gf.read_uint32(fb)                  # 0x50 uint32
        t1e.unk0x54 = gf.read_uint32(fb)                  # 0x54 zero
        if t1e.unk0x44 != 0:
            a = 0
        files.append(t1e)

    string_table_offset = fb.tell()
    for t1e in files:
        t1e.string = gf.offset_to_string(fb, string_table_offset+t1e.string_offset)

    # Table 3
    t3es = []
    for i in range(table3_count):
        t3es.append(gf.read_uint32(fb))

    # Table 4
    class BlockEntry:
      def __init__(self):
        pass

    blocks = []
    for i in range(blocks_count):
        t4e = BlockEntry()
        t4e.comp_offset = gf.read_uint32(fb)         # 0x00
        t4e.comp_size = gf.read_uint32(fb)           # 0x04
        t4e.decomp_offset = gf.read_uint32(fb)       # 0x08
        t4e.decomp_size = gf.read_uint32(fb)         # 0x0C
        t4e.b_compressed = gf.read_uint32(fb)        # 0x10
        blocks.append(t4e)

    # Get data

    # To skip zeros
    while fb.read(1) == b"\x00":
        continue
    data_offset = fb.seek(-1, 1)

    decompressor = OodleDecompressor('I:/oo2core_8_win64.dll')

    for i, t1e in enumerate(files):
        # Cleaning string to be savable


        if ":" in t1e.string:
            t1e.string = t1e.string.replace(" ", "_")
            t1e.string = t1e.string.replace(":", "_")

        t1e.save_path = f"{unpack_path}{t1e.string}"

        if "[5_bitmap_resource_handle.chunk5]" in t1e.string:
            continue


        os.makedirs('/'.join(t1e.save_path.split('/')[:-1]), exist_ok=True)

        in_file_offset = data_offset + t1e.local_data_offset

        if in_file_offset >= file_size:
            tmp = fb_hd1
            file_data_offset = in_file_offset - hd1_delta
        else:
            tmp = fb
            file_data_offset = in_file_offset
        decomp_save_data = b""
        if t1e.decomp_size == 0:
            with open(t1e.save_path, "wb"):
                continue
        if t1e.block_count:
            for block in blocks[t1e.first_block_index:t1e.first_block_index+t1e.block_count]:
                if block.b_compressed:
                    tmp.seek(file_data_offset + block.comp_offset)
                    data = tmp.read(block.comp_size)
                    decomp = decompressor.decompress(data, block.decomp_size)
                    if len(decomp_save_data) != block.decomp_offset:
                        raise Exception("Skipped data fix")
                    decomp_save_data += decomp
                else:
                    tmp.seek(file_data_offset + block.comp_offset)
                    decomp = tmp.read(block.comp_size)
                    if len(decomp_save_data) != block.decomp_offset:
                        raise Exception("Skipped data fix")
                    decomp_save_data += decomp
        else:
            if t1e.comp_size == t1e.decomp_size:
                decomp_save_data = tmp.read(t1e.comp_size)
            else:
                tmp.seek(file_data_offset)
                decomp_save_data = decompressor.decompress(tmp.read(t1e.comp_size), t1e.decomp_size)

        with open(t1e.save_path, "wb") as f:
            f.write(decomp_save_data)


def extract_all_modules():
    # Ignoring module hd files
    p = [os.path.join(dp, f)[len(deploy_path):].replace("\\", "/") for dp, dn, fn in os.walk(os.path.expanduser(deploy_path)) for f in fn if ".module" in f and ".module_" not in f]
    for file in p:
        print(file)
        extract_module(file.replace(".module", ""))


if __name__ == "__main__":
    unpack_path = "H:/HaloInfiniteUnpack/"
    deploy_path = "C:/Program Files (x86)/Steam/steamapps/common/MGS Test App 6/deploy/"
    module_name = "pc/globals/forge/forge_objects-rtx-new"
    # extract_module(module_name)
    extract_all_modules()

    ## pc/globals/forge/forge_objects-rtx-new.module is broken