

# PKSC7 PADDING =====================================================
# 2018-01-18 PLAN is to replace this with pyca functionality


def pkcs7_padding(data, block_size):
    block_size = int(block_size)
    if block_size < 1:
        raise XLCryptoError("impossible block size")
    if not data:
        length = 0
    else:
        length = len(data)

    # we want from 1 to block_size bytes of padding
    n_blocks = int((length + block_size - 1) / block_size)
    rem = n_blocks * block_size - length
    if rem == 0:
        rem = block_size
    padding = bytearray(rem)    # that many null bytes
    for iii in range(rem):
        padding[iii] = rem      # padding bytes set to length of padding
    return padding


def add_pkcs7_padding(data, block_size):
    if block_size <= 1:
        raise XLCryptoError("impossible block size")
    else:
        padding = pkcs7_padding(data, block_size)
        if not data:
            out = padding
        else:
            out = data + padding
    return out


# The data passed is presumed to have PKCS7 padding.  If possible, return
# a copy of the data without the padding.  Return an error if the padding
# is incorrect.

def strip_pkcs7_padding(data, block_size):
    if block_size <= 1:
        raise XLCryptoError("impossible block size")
    elif not data:
        raise XLCryptoError("cannot strip padding from empty data")
    len_data = len(data)
    if len_data < block_size:
        raise XLCryptoError("data too short to have any padding")
    else:
        # examine the very last byte: it must be padding and must
        # contain the number of padding bytes added
        len_padding = data[len_data - 1]
        if len_padding < 1 or len_data < len_padding:
            raise XLCryptoError("incorrect PKCS7 padding")
        else:
            out = data[:len_data - len_padding]
    return out
