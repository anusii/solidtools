import hashlib
from base64 import (
    b64decode,
    b64encode,
)
from rdflib import (
    Graph,
    URIRef,
)
from urllib.parse import urlparse
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import (
    pad,
    unpad,
)


separator = '#'
path_pred = 'path'
iv_pred = 'iv'
session_key_pred = 'sessionKey'
data_pred = 'encData'
server_path = '/opt/solid/server/'
apps_terms = 'https://solidcommunity.au/predicates/terms#';

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


def encrypt(data_str, key, iv):
    # Encrypt the input string `data_str` using AES with
    # - key (bytes): encryption key
    # - iv (bytes): nonce and initial value
    # Returns the ciphertext (base64 encoded)
    
    # CTR mode is also known as segmented integer counter (SIC) mode, as per
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    # It seems the first half of `iv' should be used as `nonce', and the latter half for `initial_value'
    assert len(iv) == 16
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    return b64encode(cipher.encrypt(padded_data)).decode('ascii')


def decrypt(data_ct, key, iv):
    # CTR mode is also known as segmented integer counter (SIC) mode, as per
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    # It seems the first half of `iv' should be used as `nonce', and the latter half for `initial_value'
    assert len(iv) == 16
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    return unpad(cipher.decrypt(data_ct), AES.block_size).decode('utf-8')

