import os
import argparse

from getpass import getpass
from base64 import b64decode

from pod_helper import (
    gen_master_key,
    decrypt,
    parse_ttl,
    path_pred,
    iv_pred,
    session_key_pred,
    data_pred,
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

    # Decrypt session key

    session_key_ct = b64decode(session_key_ct_b64)
    session_key_iv = b64decode(session_key_iv_b64)
    session_key_b64 = decrypt(session_key_ct, master_key, session_key_iv)
    session_key = b64decode(session_key_b64)

    # Decrypt data

    data_ct = b64decode(data_ct_b64)
    data_iv = b64decode(data_iv_b64)
    plain_text = decrypt(data_ct, session_key, data_iv)

    print(plain_text)

