import hashlib
import argparse
import sys
import os

from getpass import getpass
from base64 import b64decode, b64encode
from rdflib import Graph, URIRef  # pip install rdflib
from Cryptodome.Cipher import AES  # pip install pycryptodomex
from Cryptodome.Util.Padding import unpad

separator = '#'
path_pred = 'path'
iv_pred = 'iv'
session_key_pred = 'sessionKey'
data_pred = 'encData'
server_path = '/opt/solid/server/'


def parse_ttl(fname):
    # Parse a .ttl file into a dictionary
    g = Graph()
    g.parse(fname)

    tripleMap = dict()
    for sub, pre, obj in g:
        s = sub.lower() if isinstance(sub, URIRef) else sub
        p = pre.split('#')[-1]
        o = obj.split('#')[-1]
        if s in tripleMap:
            d = tripleMap[s]
            if p in d:
                d[p].add(o)
            else:
                d[p] = [o]
        else:
            tripleMap[s] = {p: [o]}
    return tripleMap


def gen_master_key(security_key_str):
    # Generate master key from security key string as per `solidpod`
    return hashlib.sha256(security_key_str.encode('utf-8')).hexdigest()[:32].encode('utf-8')


def decrypt(data_ct, key, iv):
    # CTR mode is also known as segmented integer counter (SIC) mode, as per
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    # It seems the first half of `iv' should be used as `nonce', and the latter half for `initial_value'
    assert len(iv) == 16
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    return unpad(cipher.decrypt(data_ct), AES.block_size)


def main(master_key, session_key_ct_b64, session_key_iv_b64, data_ct_b64, data_iv_b64):
    session_key_ct = b64decode(session_key_ct_b64)
    session_key_iv = b64decode(session_key_iv_b64)
    data_ct = b64decode(data_ct_b64)
    data_iv = b64decode(data_iv_b64)

    # Decrypt the session key
    session_key_b64 = decrypt(session_key_ct, master_key, session_key_iv)
    session_key = b64decode(session_key_b64)

    # Decrypt data
    return decrypt(data_ct, session_key, data_iv)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process secret and path arguments')
    parser.add_argument('filepath', help='File path within data folder')
    args = parser.parse_args()

    # File path format: server_path/pod_name/app_name/data/data_file

    file_path = os.path.abspath(args.filepath)
    assert file_path.startswith(server_path)
    items = file_path.replace(server_path, '').split('/')
    assert len(items) >= 4
    pod_name = items[0]
    app_name = items[1]
    assert items[2] == 'data'
    app_path = f'{server_path}{pod_name}/{app_name}'

    security_key_str = getpass(prompt='Security Key: ')
    master_key = gen_master_key(security_key_str)

    # Parsing ind-keys.ttl file

    key_path = f'{app_path}/encryption/ind-keys.ttl'
    result = parse_ttl(key_path)
    key_map = {v[path_pred][0]: {iv_pred: v[iv_pred][0], session_key_pred: v[session_key_pred][0]} for k, v in result.items() if iv_pred in v}
    file_key = '/'.join(items[1:])
    session_key_ct_b64 = key_map[file_key][session_key_pred]
    session_key_iv_b64 = key_map[file_key][iv_pred]

    # Parse data .ttl file

    result = parse_ttl(file_path)
    data_key = list(result.keys())[0]
    data_map = {iv_pred: result[data_key][iv_pred][0], data_pred: result[data_key][data_pred][0]}
    data_ct_b64 = data_map[data_pred]
    data_iv_b64 = data_map[iv_pred]

    # Decrypt data

    data = main(master_key, session_key_ct_b64, session_key_iv_b64, data_ct_b64, data_iv_b64)
    print(data.decode('utf-8'))

