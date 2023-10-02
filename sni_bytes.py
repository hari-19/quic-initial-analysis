def get_var_len_int(payload):
    firstByte = payload[0]
    
    MSB2 = firstByte & 0xc0

    if MSB2 == 0x00:
        len = 1
    elif MSB2 == 0x40:
        len = 2
    elif MSB2 == 0x80:
        len = 4
    else:
        len = 8

    first_byte = (payload[0] & 0x3f).to_bytes(1, "big")
    binary = first_byte + payload[1:len]   
    intVal = int.from_bytes(binary, "big")

    return intVal, len

def ascii_bytes_to_string(data):
    i = 0
    str = ""
    while(i<len(data)):
        byte = data[i]
        str += chr(byte)
        i += 1
    return str

def get_tls_from_crypto(cryptoData):
    initialByte = cryptoData[0]
    if initialByte != 0x01:
        raise Exception("Not TLS Client Hello")
        
    i = 38 # skip header

    sessionIdLength = cryptoData[i]
    i += 1 + sessionIdLength

    cipherSuiteLength = int.from_bytes(cryptoData[i:i+2], "big")
    i += 2 +cipherSuiteLength

    compressionMethodLength = cryptoData[i]
    i += 1 + compressionMethodLength

    extensionsLength = int.from_bytes(cryptoData[i:i+2], "big")
    i += 2
    
    eof = i+extensionsLength
    while(i<eof):
        type = cryptoData[i:i+2]
        i += 2
        length = int.from_bytes(cryptoData[i:i+2], "big")
        i += 2
        type = int.from_bytes(type, "big")
        if(type == 0x0000): # server_name
            j = i
            sn_lst_len = int.from_bytes(cryptoData[j:j+2], "big")
            j += 2
            sn_type = cryptoData[j]
            j += 1
            sn_len = int.from_bytes(cryptoData[j:j+2], "big")
            j += 2
            sn = cryptoData[j:j+sn_len]

            return  ascii_bytes_to_string(sn)
        i += length


def extract_sni(payload):
    i = 0
    cryptoList = []

    while(i<len(payload)-1):
        byte = payload[i]
        if byte == 0x00: # Padding
            # print("Padding")
            i = i + 1
            continue
        elif byte == 0x01: # Ping
            # print("Ping")
            i = i + 1
            continue
        elif byte == 0x06: # crypto
            i=i+1
            cryptoOffset, off = get_var_len_int(payload[i:])
            i = i + off

            cryptoLength, off = get_var_len_int(payload[i:])
            i = i + off

            data = payload[i:i+cryptoLength]
            i = i+cryptoLength
            
            cryptoList.append((cryptoOffset, cryptoLength, data))
            continue
        else:
            raise Exception("Unknown Frame Type", byte)
            return 'NA' # Unknown Frame Type - either not a client Hello or not first Quic Initial Packet (decryption won't work)

    cryptoList.sort()
    cryptoData = b'' # Rearrangned Crypto Data
    for _, _ , data in cryptoList:
        cryptoData += data

    sni = get_tls_from_crypto(cryptoData)      
    return sni
