def _validate_option_envelope(options: bytes, protocol: str, error_type: type[ValueError]) -> None:
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            if any(options[offset + 1:]):
                raise error_type(f"{protocol} option padding must be zero")
            return
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= len(options):
            raise error_type(f"{protocol} option length field exceeds option area")
        length = options[offset + 1]
        if length < 2:
            raise error_type(f"{protocol} option length must be at least 2 bytes")
        if offset + length > len(options):
            raise error_type(f"{protocol} option length exceeds option area")
        offset += length
