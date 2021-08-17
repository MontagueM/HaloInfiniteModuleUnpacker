import os
import numpy as np
import struct


def fill_hex_with_zeros(s, desired_length):
    return ("0"*desired_length + s)[-desired_length:]


def get_hex_data(direc):
    t = open(direc, 'rb')
    r = t.read()
    return r


def get_flipped_hex(h, length):
    if length % 2 != 0:
        print("Flipped hex length is not even.")
        return None
    return "".join(reversed([h[:length][i:i + 2] for i in range(0, length, 2)]))


def get_file_from_hash(hsh):
    hsh = get_flipped_hex(hsh, 8)
    first_int = int(hsh, 16)
    one = first_int - 2155872256
    first_hex = hex(int(np.floor(one/8192)))
    second_hex = hex(first_int % 8192)
    return f'{fill_hex_with_zeros(first_hex[2:], 4)}-{fill_hex_with_zeros(second_hex[2:], 4)}'.upper()


def get_hash_from_file(file):
    pkg = file.replace(".bin", "").upper()

    firsthex_int = int(pkg[:4], 16)
    secondhex_int = int(pkg[5:], 16)

    one = firsthex_int*8192
    two = hex(one + secondhex_int + 2155872256)
    return get_flipped_hex(two[2:], 8).upper()



def get_uint64(fb, offset):
    return int.from_bytes(fb[offset:offset+8], byteorder='little')


def get_uint32(fb, offset):
    return int.from_bytes(fb[offset:offset+4], byteorder='little')


def get_uint32_big(fb, offset):
    return int.from_bytes(fb[offset:offset+4], byteorder='big')


def get_int32_big(fb, offset):
    return int.from_bytes(fb[offset:offset+4], byteorder='big', signed=True)


def get_uint16(fb, offset):
    return int.from_bytes(fb[offset:offset+2], byteorder='little')


def get_uint16_big(fb, offset):
    return int.from_bytes(fb[offset:offset+2], byteorder='big')


def get_int32(fb, offset):
    return int.from_bytes(fb[offset:offset+4], byteorder='little', signed=True)


def get_int16(fb, offset):
    return int.from_bytes(fb[offset:offset+2], byteorder='little', signed=True)


def get_int8(fb, offset):
    if fb[offset] > pow(2, 7) - 1:
        return fb[offset] - pow(2, 8)
    return fb[offset]


def get_float16(fb, offset, le=True, signed=True):
    if le:
        flt = int.from_bytes(fb[offset:offset+2], 'little', signed=signed)
    else:
        flt = int.from_bytes(fb[offset:offset + 2], 'big', signed=signed)
    # if not signed:
    #     flt /= 2
    if signed:
        flt = flt / (2 ** 15 - 1)
    else:
        flt = flt / (2 ** 16 - 1)
    return flt


def get_float32(fb, offset):
    return struct.unpack('f', fb[offset:offset+4])[0]


def get_relative_offset(fb, offset):
    return int.from_bytes(fb[offset:offset + 4], byteorder='little') + offset


def offset_to_string(fb, abs_offset):
    string = ''
    k = 0
    fb.seek(abs_offset)
    while True:
        char = read_uint8(fb)
        if char == 0:# and k != 0:
            break
        else:
            if char == 92:
                char = 47
            # if char == 0:
            #     string += "0"
            #     break
            # else:
            string += chr(char)
            k += 1
        if k > 1000:
            raise TypeError('Offset given is not string offset, infinite parse detected')
    return string


def offset_to_string_mem(fb, offset):
    string = ''
    k = 0
    while True:
        char = fb[offset + k]
        if char == 0:
            break
        else:
            string += chr(char)
            k += 1
        if k > 1000:
            raise TypeError('Offset given is not string offset, infinite parse detected')
    return string


def get_flipped_bin(h, length):
    if length % 2 != 0:
        print("Flipped bin length is not even.")
        return None
    return h[:length][::-1]


def read_uint8(fb):
    return int.from_bytes(fb.read(1), byteorder='little')


def read_int32(fb):
    return int.from_bytes(fb.read(4), byteorder='little', signed=True)


def read_uint32(fb):
    return int.from_bytes(fb.read(4), byteorder='little')


def read_uint16(fb):
    return int.from_bytes(fb.read(2), byteorder='little')


def read_uint64(fb):
    return int.from_bytes(fb.read(8), byteorder='little')