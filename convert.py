


def ascii_to_hex(ascii_str):
    try:
        hex_str = " ".join("{:02x}".format(ord(c)) for c in ascii_str)
        return hex_str
    except:
        return "null"
