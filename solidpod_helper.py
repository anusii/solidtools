import sys
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
verify_key_pred = 'encKey'
private_key_pred = 'prvKey'
indi_key_pred = 'sessionKey'
enc_data_pred = 'encData'
inherit_key_pred = 'inheritKeyFrom'
server_path = '/opt/solid/server/'
apps_terms = 'https://solidcommunity.au/predicates/terms#';

def parse_ttl(fname=None, ttl_str=None):
    # Parse a .ttl file or its content (RDF data string) into a dictionary
    if fname is None and ttl_str is None:
        print(f'ERROR: either file name or RDF data should be provided')
        sys.exit(1)

    g = Graph()
    if fname is not None:
        g.parse(fname)
    elif ttl_str is not None:
        g.parse(data=ttl_str)
    else:
        pass

    tripleMap = dict()
    for sub, pre, obj in g:
        s = str(sub) if isinstance(sub, URIRef) else sub
        p = pre.split(separator)[-1]
        o = obj.split(separator)[-1]
        if s in tripleMap:
            d = tripleMap[s]
            if p in d:
                d[p] = d.add(o)
            else:
                d[p] = [o]
        else:
            tripleMap[s] = {p: [o]}
    # convert triple (s, p, o) to (s, p, o[0]) if o is a list with only one element
    return {s: {p: o[0] if len(o) == 1 else o for p, o in tripleMap[s].items()} for s in tripleMap.keys()}


def gen_master_key(security_key_str):
    # Generate master key from security key string as per `solidpod`
    return hashlib.sha256(security_key_str.encode('utf-8')).hexdigest()[:32].encode('utf-8')

def gen_verify_key(security_key_str):
    # Generate verification key from security key string as per `solidpod`
    return hashlib.sha224(security_key_str.encode('utf-8')).hexdigest()[:32].encode('utf-8')

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
    # Decrypt the input string `data_ct` using AES with
    # - key (bytes): encryption key
    # - iv (bytes): nonce and initial value
    # Returns the plaintext string

    # CTR mode is also known as segmented integer counter (SIC) mode, as per
    # https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
    # It seems the first half of `iv' should be used as `nonce', and the latter half for `initial_value'
    assert len(iv) == 16
    cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    return unpad(cipher.decrypt(data_ct), AES.block_size).decode('utf-8')

