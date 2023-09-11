import hkdf
from binascii import unhexlify, hexlify
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_payload(dcid, payload_string,  packet_number):
    initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    dcid = dcid.replace(":","")
    payload_string = payload_string.replace(":","")
    # dcid = "8394c8f03e515708"
    
    client_in = "00200f746c73313320636c69656e7420696e00"
    quic_key = "00100e746c7331332071756963206b657900"
    quic_iv = "000c0d746c733133207175696320697600"
    quic_hp = "00100d746c733133207175696320687000"

    initial_secret = hkdf.hkdf_extract(unhexlify(initial_salt), unhexlify(dcid), hash=hashlib.sha256)
    client_initial_secret = hkdf.hkdf_expand(initial_secret, unhexlify(client_in), 32, hash=hashlib.sha256)
    
    key = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_key), 16, hash=hashlib.sha256)
    iv = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_iv), 12, hash=hashlib.sha256)
    hp = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_hp), 16, hash=hashlib.sha256)
    iv = hexlify(iv)
    nonce = packet_number ^ int(iv,16)
    nonce = hex(nonce)[2:].zfill(24)
    nonce = unhexlify(nonce)

    tag = unhexlify(payload_string[-32:])
    payload_string = payload_string[:-32]



    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=None)
    
    decryptor = cipher.decryptor()

    final = decryptor.update(unhexlify(payload_string)) # + decryptor.finalize()
    return hexlify(final)

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



def sni_quic_extract_custom(packet):
    if 'quic' not in packet:
        return 'NA'
    
    if packet['quic'].long.packet_type != '0': # 0 is for Initial Packet frame
        return 'NA'
    
    try:
        dcid = packet['quic'].dcid
    except:
        return 'NA'
    
    payload_string = packet['quic'].payload
    packet_number = packet['quic'].packet_number

    # if packet_number != '1':
    #     # Because we are only interested in the first packet
    #     # Also, decryption algo doesn't work for any other packet number, to be checked later
    #     return 'NA'
    # Commented above because we are not sure if the first packet is always the first packet number (pkt no 0 was observerd in some cases)
    
    payload = decrypt_payload(dcid, payload_string, int(packet_number))
    
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