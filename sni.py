def get_var_len_int(byteString):
    firstByte = byteString[0:2]
    binary = bin(int(firstByte,16))[2:].zfill(8)
    
    MSB2 = binary[0:2]

    if MSB2 == '00':
        len = 1
    elif MSB2 == '01':
        len = 2
    elif MSB2 == '10':
        len = 4
    else:
        len = 8

    binary = bin(int(byteString[0:len*2],16))[2:].zfill(len*8)
    intVal = int(binary[2:], 2)

    return intVal, len*2

def ascii_hex_to_string(data):
    i = 0
    str = ""
    while(i<len(data)-1):
        byte = data[i:i+2]
        str += chr(int(byte,16))
        i += 2
    return str

def get_tls_from_crypto(cryptoData):
    initialByte = cryptoData[0:2]
    if initialByte != b'01':
        raise Exception("Not TLS Client Hello")
    
    i = 76 # skip header

    sessionIdLength = int(cryptoData[i:i+2], 16)
    i += 2 + sessionIdLength*2

    cipherSuiteLength = int(cryptoData[i:i+4], 16)
    i += 4 +cipherSuiteLength*2

    compressionMethodLength = int(cryptoData[i:i+2], 16)
    i += 2 + compressionMethodLength*2

    extensionsLength = int(cryptoData[i:i+4], 16)
    i += 4
    
    eof = i+extensionsLength*2
    while(i<eof):
        type = cryptoData[i:i+4]
        i += 4
        length = int(cryptoData[i:i+4], 16)
        i += 4

        if(type == b'0000'): # server_name
            j = i
            sn_lst_len = int(cryptoData[j:j+4], 16)
            j += 4
            sn_type = cryptoData[j:j+2]
            j += 2
            sn_len = int(cryptoData[j:j+4], 16)
            j += 4
            sn = cryptoData[j:j+sn_len*2]

            return ascii_hex_to_string(sn)
        i += length*2


def extract_sni(payload):
    i = 0
    cryptoList = []

    while(i<len(payload)-1):
        byteString = payload[i:i+2]
        if byteString == b'00': # Padding
            i = i + 2
            continue
        elif byteString == b'01': # Ping
            i = i + 2
            continue
        elif byteString == b'06': # crypto
            i=i+2
            cryptoOffset, off = get_var_len_int(payload[i:])
            i = i + off

            cryptoLength, off = get_var_len_int(payload[i:])
            i = i + off

            data = payload[i:i+cryptoLength*2]
            i = i+cryptoLength*2
            
            cryptoList.append((cryptoOffset, cryptoLength, data))

            continue
        else:
            # raise Exception("Unknown Frame Type", byteString)
            return 'NA' # Unknown Frame Type - either not a client Hello or not first Quic Initial Packet (decryption won't work)

    cryptoList.sort()
    cryptoData = b'' # Rearrangned Crypto Data
    for _, _ , data in cryptoList:
        cryptoData += data

    sni = get_tls_from_crypto(cryptoData)    
    
    return sni
