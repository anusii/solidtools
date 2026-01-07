import os
import sys
import argparse

from getpass import getpass
from base64 import b64decode
from urllib.parse import urlparse

from solidpod_helper import (
    gen_master_key,
    gen_verify_key,
    decrypt,
    parse_ttl,
    path_pred,
    iv_pred,
    verify_key_pred,
    indi_key_pred,
    inherit_key_pred,
    enc_data_pred,
    server_path,
)

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
    relative_file_path = '/'.join(items[1:])

    security_key_str = getpass(prompt='Security Key: ')
    master_key = gen_master_key(security_key_str)
    verify_key = gen_verify_key(security_key_str)

    # Verify security key

    enc_key_map = parse_ttl(f'{app_path}/encryption/enc-keys.ttl')
    verify_key_stored = list(enc_key_map.items())[0][1][verify_key_pred]
    if verify_key.decode('utf-8') != verify_key_stored:
        print('ERROR: Verification failed, incorrect security key.')
        sys.exit(0)

    # Parse data .ttl file

    with open(file_path) as fd:
        file_content = fd.read()

    _map = parse_ttl(ttl_str=file_content)

    def exit():
        print(f'WARN: File "{args.filepath}" is not encrypted by solidpod, return raw content\n{"-"*20}')
        print(file_content)
        sys.exit(0)
    
    if len(_map) != 1:
        exit()

    file_url, data_map = list(_map.items())[0]

    if (path_pred not in data_map) or (data_map[path_pred] != relative_file_path):
        exit()

    if (iv_pred not in data_map) or (enc_data_pred not in data_map):
        exit()

    data_ct = b64decode(data_map[enc_data_pred])
    data_iv = b64decode(data_map[iv_pred])

    # Retrieve encryption key and IV

    key_map = parse_ttl(f'{app_path}/encryption/ind-keys.ttl')
    indi_key_ct = None
    indi_key_iv = None
    if file_url in key_map:
        indi_key_ct = b64decode(key_map[file_url][indi_key_pred])
        indi_key_iv = b64decode(key_map[file_url][iv_pred])
    elif inherit_key_pred in data_map:
        r = urlparse(file_url)
        server_url = f'{r.scheme}://{r.netloc}'
        inherit_key_url = '/'.join([server_url, pod_name, data_map[inherit_key_pred]])
        if inherit_key_url in key_map:
            indi_key_ct = b64decode(key_map[inherit_key_url][indi_key_pred])
            indi_key_iv = b64decode(key_map[inherit_key_url][iv_pred])
    else:
        pass

    if indi_key_ct is None or indi_key_iv is None:
        exit()

    # Decrypt individual key

    indi_key = b64decode(decrypt(indi_key_ct, master_key, indi_key_iv))

    # Decrypt data

    plain_text = decrypt(data_ct, indi_key, data_iv)

    print('-'*20)
    print(plain_text)

