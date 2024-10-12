import requests
import json
import random
import math
import hmac
import hashlib
import base64
import urllib.parse
import uuid
from base64 import b64decode, b64encode
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import os
import decrypt_ts
from config import headers, origin_url
import logging
import time
import subprocess

logging.basicConfig(level=logging.INFO #设置日志输出格式
                    ,format="%(asctime)s - %(name)s - %(levelname)-9s - %(filename)-8s : %(lineno)s line - %(message)s" #日志输出的格式
                    # -8表示占位符，让输出左对齐，输出长度都为8位
                    ,datefmt="%Y-%m-%d %H:%M:%S" #时间输出的格式
                    )

def get_play_info(playauth:str,origin_url:str):

    data = {}
    b64playauth = b64decode(playauth.encode('utf8'))
    playauth = json.loads(b64playauth.decode('utf8'))

    playauth["AuthInfo"] = json.loads(playauth["AuthInfo"])
    st = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz234567890'
    randstr = ''

    for ii in range(16):
        randstr += st[math.floor(random.random() * 50)]

    message = randstr.encode('utf8')
    key = RSA.import_key(open("rand.pem").read())
    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(message)
    rand = b64encode(ciphertext)
    rand = rand.decode('utf8')

    reqdict = {}
    reqdict["AccessKeyId"] = playauth["AccessKeyId"]
    reqdict["Action"] = "GetPlayInfo"
    playauth["AuthInfo"] = json.loads(b64playauth.decode('utf8'))["AuthInfo"]
    reqdict["AuthInfo"] = urllib.parse.quote_plus(playauth["AuthInfo"])
    reqdict["AuthTimeout"] = 7200
    reqdict["Channel"] = "HTML5"
    reqdict["Format"] = "JSON"
    reqdict["Formats"] = ""
    reqdict["PlayConfig"] = urllib.parse.quote_plus('{"PreviewTime":18000}')
    reqdict["PlayerVersion"] = "2.9.7"
    reqdict["Rand"] = urllib.parse.quote_plus(rand)
    reqdict["ReAuthInfo"] = urllib.parse.quote_plus('{}')
    reqdict["SecurityToken"] = urllib.parse.quote_plus(playauth["SecurityToken"])
    reqdict["SignatureMethod"] = "HMAC-SHA1"
    reqdict["SignatureNonce"] = uuid.uuid4()
    reqdict["SignatureVersion"] = 1.0
    reqdict["StreamType"] = "video"
    reqdict["Version"] = "2017-03-21"
    reqdict["VideoId"] = json.loads(playauth["AuthInfo"])["MediaId"]

    e = 'GET&%2F&' + urllib.parse.urlencode(reqdict).replace('=', '%3D').replace('&', '%26')

    key1 = bytes(playauth["AccessKeySecret"] + '&', 'UTF-8')
    message1 = bytes(e, 'utf8')
    digester = hmac.new(key1, message1, hashlib.sha1)
    signature1 = digester.digest()
    signature = str(base64.b64encode(signature1), 'utf8')
    reqdict["Signature"] = urllib.parse.quote_plus(signature)

    requrl = 'https://vod.' + playauth["Region"] + '.aliyuncs.com/?' + urllib.parse.urlencode(reqdict) .replace('%25', '%')
    aliheaders = headers

    aliheaders['Origin'] = aliheaders['Referer'] = origin_url
    req = requests.get(requrl, headers=aliheaders)
    if req.status_code!=200:
        raise Exception('Failed to get media info! Please check if playauth is expired.')

    aliresp = req.text
    aliresp = json.loads(aliresp)
    videoinfo = aliresp['PlayInfoList']['PlayInfo'][0]

    data["videoName"] = aliresp["VideoBase"]["Title"].encode('utf-8').decode('utf-8')
    data["CoverUrl"] = aliresp["VideoBase"]["CoverURL"]
    data['Videoinfo'] = videoinfo

    randkey = hashlib.md5()
    randkey.update(bytes(randstr, 'utf8'))
    iv = bytes(randkey.hexdigest()[8:24], 'utf8')

    if videoinfo['Encrypt'] == 1 and videoinfo['EncryptType'] == 'AliyunVoDEncryption':
        randnum = AES.new(iv, AES.MODE_CBC, iv=iv).decrypt(
            b64decode(bytes(videoinfo['Rand'], 'utf8'))).rstrip(b'\x0c').rstrip(b'\r')
        rand = bytes(randstr, 'utf8') + randnum
        m = hashlib.md5()
        m.update(rand)
        key = bytes(m.hexdigest()[8:24], 'utf8')
        finalkey = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(
            b64decode(bytes(videoinfo['Plaintext'], 'utf8'))).rstrip(b'\x08')
        #data['Key'] = b64encode(finalkey).decode('utf8')
        data['Key'] = finalkey

    return data



def download_m3u8_files(url:str, file_path:str,origin_url:str):
    aliheaders = headers
    aliheaders['Origin'] = aliheaders['Referer'] = origin_url
    r = requests.get(url,headers=headers)
    if r.status_code != 200:
        raise Exception('m3u8 download link is invaild! Consider retry.')

    m3u8_list = r.text.split('\n')
    m3u8_list = [i for i in m3u8_list if i and i[0] != '#']

    ts_list = []
    for ts_url in m3u8_list:
        ts_url = url.rsplit('/', 1)[0] + '/' + ts_url
        ts_list.append(ts_url)
    i=1
    for ts_url in ts_list:
        ret=download_ts(file_path,ts_url,i)
        j=0
        while ret is False and j < 3:
            ret=download_ts(file_path, ts_url, i)
            j+=1
            if j == 3:
                raise Exception('Failed to download ts file:' + ts_url)

        i += 1
    logging.info('m3u8 ts files downloaded.')
    return True

def download_ts(file_path,ts_url,i):
    with open(file_path + str(i) + '.ts', 'wb') as f:
        logging.info('Downloading:' + ts_url)

        r = requests.get(ts_url)
        if r.status_code == 200:
            if r.content != b'':
                f.write(r.content)
            else:
                logging.warning('ts file: ' + ts_url + ' is empty! Retrying')
                return False
        else:
            logging.error('Failed to download ts file, retrying:' + ts_url)
            return False


if __name__ == '__main__':
    try:
        logging.info('Starting...')
        time.sleep(0.01)
        os.makedirs('ts-tmp',exist_ok=True)
        os.makedirs('output/', exist_ok=True)
        playauth=input('please enter playauth:')
        if origin_url == '':
            origin_url=input('please enter origin url:')
        data=get_play_info(playauth,origin_url)
        logging.info('Key(base64) is:'+str(data['Key']))
        logging.info('m3u8 PlayURL is:'+data['Videoinfo']['PlayURL'])
        logging.info('Video name is:'+data['videoName'])
        video_basedir='ts-tmp/'+data['videoName']+'/'
        ts_basedir=video_basedir+'ts_file/'
        os.makedirs(video_basedir,exist_ok=True)
        os.makedirs(ts_basedir, exist_ok=True)
        download_m3u8_files(data['Videoinfo']['PlayURL'],ts_basedir,origin_url)
        largest_num = decrypt_ts.get_largest_file_num(ts_basedir)
        for i in range(1, largest_num):
            logging.info('decrypting ts file:'+str(i))
            decrypt_ts.dects(ts_basedir + str(i) + '.ts', data['Key'])

        if os.path.exists(video_basedir + 'tmp_m3u8inf.txt'):
            os.remove(video_basedir+'tmp_m3u8inf.txt')
        with open(video_basedir+'tmp_m3u8inf.txt', 'w') as f:
            for i in range(1, largest_num):
                f.write(("file ts_file/'" + str(i) + ".ts'\n"))
        ffcmd=r'ffmpeg -y -f concat -safe 0  -i '+video_basedir+'tmp_m3u8inf.txt -vcodec copy -acodec copy output\\' + data['videoName'] + '.mp4'
        logging.info('Executing ffmpeg...')
        ff_process = subprocess.Popen(ffcmd, stdout=subprocess.PIPE, universal_newlines=True)
        for line in ff_process.stdout:
            print(line.strip())

        ff_process.wait()
    except Exception as e:
        logging.error(str(e))
    input('Press any key to exit...')





