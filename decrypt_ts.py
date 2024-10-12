from Crypto.Cipher import AES
from base64 import b64decode
import os
import re
import subprocess

def parsepmt(t: bytes, e: int, vpid, apid, mpid) -> (int, int, int):
    section_length = (0x0f & t[e + 1]) << 8 | t[e + 2]
    section_body = e + 0x03 + section_length - 0x04
    program_info_length = (0x0f & t[e + 10]) << 8 | t[e + 11]

    e += 12 + program_info_length
    while e < section_body:
        s = (0x1f & t[e + 1]) << 8 | t[e + 2]
        if t[e] == 0x1b and vpid == -1:
            vpid = s
        elif t[e] == 0x0f and apid == -1:
            apid = s
        elif t[e] == 0x1c and mpid == -1:
            mpid = s
        elif t[e] != 0x1b and t[e] != 0x0f and t[e] != 0x1c:
            print('ERROR @ {1}, UNKONWN STREAM TYPE: {2} STREAM_ID: {0}.'.format(s, e, t[e]))
        e += 5 + ((0x0f & t[e + 3]) << 8 | t[e + 4])
    return vpid, apid, mpid


def parsepes(datarray: bytearray, index: dict) -> bytes:
    r = bytes(datarray)
    if (r[0] << 16) + (r[1] << 8) + r[2] == 0x000001:
        if (r[4] << 8) + r[5] > len(r) - 6:
            return b''
        pes_header_data_length = r[8] + 9
        for key, value in index.items():
            index[key] += pes_header_data_length
            break
        return r[pes_header_data_length:]


def doset(decdata: bytes, index: dict, tsarray: bytearray) -> None:
    v = 0
    for j, start in index.items():
        end = min(j + 0xbc, start + len(decdata) - v)
        length = end - start
        tsarray[start:end] = decdata[v:v + length]
        v += length


def decrypt(datarray: bytearray, index: dict, tsarray: bytearray, key: bytes) -> None:
    data = parsepes(datarray, index)
    key = b64decode(key)
    encdata = data[0:len(data) - len(data) % 16]
    decdata = AES.new(key, AES.MODE_ECB).decrypt(encdata)
    doset(decdata, index, tsarray)


def dects(filename: str, key: bytes) -> None:
    tsfile = open(filename, 'rb')
    ts = bytearray(tsfile.read())
    tsfile.close()

    sdtid = 0x0011
    nulid = 0x1fff
    patid = 0x0000
    pmtid = vpid = apid = mpid = -1

    vdata = bytearray()
    adata = bytearray()
    mdata = bytearray()
    vindex = {}
    aindex = {}
    mindex = {}

    for i in range(0, len(ts), 0xbc):
        if ts[i] != 0x47:
            print('ERROR@ {0}, NOT START WITH 0x47.'.format(i))
            break

        payload = 0x40 & ts[i + 1]
        adap = (0x30 & ts[i + 3]) >> 4
        pid = ((0x1f & ts[i + 1]) << 8) + ts[i + 2]
        d = 0x00

        if adap == 0b00 or adap == 0b01:
            d = i + 0x04
        elif adap == 0b10:
            continue
        elif adap == 0b11:
            d = i + 0x04 + 0x01 + ts[i + 4]

        if pid == sdtid or pid == nulid:
            continue
        elif pid == patid:
            if payload:
                d += ts[d] + 1
            pmtid = (0x1f & ts[d + 10]) << 8 | ts[d + 11]
        elif pid == pmtid:
            if payload:
                d += ts[d] + 1
            vpid, apid, mpid = parsepmt(ts, d, vpid, apid, mpid)
        elif pid == vpid:
            if payload and vdata:
                decrypt(vdata, vindex, ts, key)
                vdata = bytearray()
                vindex = {}
            vdata += bytearray(ts[d:i + 0xbc])
            vindex[i] = d
        elif pid == apid:
            if payload and adata:
                decrypt(adata, aindex, ts, key)
                adata = bytearray()
                aindex = {}
            adata += bytearray(ts[d:i + 0xbc])
            aindex[i] = d
        elif pid == mpid:
            if payload and mdata:
                decrypt(mdata, mindex, ts, key)
                mdata = bytearray()
                mindex = {}
            mdata += bytearray(ts[d:i + 0xbc])
            mindex[i] = d
        else:
            print('ERROR @ {0}, {1} IS NOT A VALID PID.'.format(i, pid))

    if len(vdata) != 0:
        decrypt(vdata, vindex, ts, key)
    if len(adata) != 0:
        decrypt(adata, aindex, ts, key)
    if len(mdata) != 0:
        decrypt(mdata, mindex, ts, key)

    decfile = open(filename, 'wb')
    decfile.write(ts)
    decfile.close()

def get_largest_file_num(directory):
    largest_num = 0
    for filename in os.listdir(directory):
        match = re.search(r'\d+', filename)
        if match:
            num = int(match.group())
            if num > largest_num:
                largest_num = num
    return largest_num


def execute_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())

    rc = process.poll()
    return rc

if __name__ == '__main__':
    pass