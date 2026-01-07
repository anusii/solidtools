import os
import argparse

from getpass import getpass
from urllib.parse import urlparse
from Cryptodome.Random import get_random_bytes
from base64 import (
    b64decode,
    b64encode,
)
from rdflib import (
    Graph,
    URIRef,
)
from solidpod_helper import (
    gen_master_key,
    encrypt,
    apps_terms,
    path_pred,
    iv_pred,
    verify_key_pred,
    indi_key_pred,
    enc_data_pred,
    server_path,
)


def upload_file(file_content, file_path, server_url, master_key):
    # Encrypt file content

    print('Encrypt content ...')
    indi_key = get_random_bytes(32)
    data_iv = get_random_bytes(16)
    enc_data_b64 = encrypt(file_content, indi_key, data_iv)

    # Write encrypted content to file in POD

    print('Write encrypted content ...')
    g = Graph()
    file_url = '/'.join([server_url, file_path])
    data_iv_b64 = b64encode(data_iv).decode('ascii')
    query = f'INSERT DATA {{<{file_url}> <{apps_terms}{path_pred}> "{file_path}"; ' + \
            f'<{apps_terms}{iv_pred}> "{data_iv_b64}"; ' + \
            f'<{apps_terms}{enc_data_pred}> "{enc_data_b64}".}};'
    g.update(query)
    ttl_str = g.serialize(format='turtle')
    abs_path = f'{server_path}{file_path}'
    with open(abs_path, 'w') as f:
        f.write(ttl_str)

    # Add session key to ind-keys.ttl

    print('Add encrypted session key to ind-keys.ttl ...')
    add_indi_key(file_path, server_url, indi_key, master_key)

def add_indi_key(file_path, server_url, indi_key, master_key):
    # Add encrypted session key to ind-keys.ttl

    # Encrypt the session key
    indi_key_iv = get_random_bytes(16)
    indi_key_b64 = b64encode(indi_key).decode('ascii')
    enc_indi_key_b64 = encrypt(indi_key_b64, master_key, indi_key_iv)

    # Parse the ind-keys.ttl file
    items = file_path.split('/')
    assert len(items) >= 4
    pod_name = items[0]
    app_name = items[1]
    ind_key_path = f'{server_path}{pod_name}/{app_name}/encryption/ind-keys.ttl'
    g = Graph()
    g.parse(ind_key_path)

    # Replace file:///POD_DIR prefix with server URL
    file_url = '/'.join([server_url, file_path])
    for s, p, o in g:
        prefix = f'file://{server_path}'
        if str(s).startswith(prefix):
            new_s = str(s).replace(prefix, server_url)
            g.add((URIRef(new_s), p, o))
            g.remove((s, p, o))
        # Remove triple if the subject already exists
        if str(s) == file_url:
            g.remove((s, p, o))

    # Add encrypted session key to ind-keys.ttl 
    indi_key_iv_b64 = b64encode(indi_key_iv).decode('ascii')
    fpath = '/'.join(items[1:])
    query = f'INSERT DATA {{<{file_url}> <{apps_terms}{path_pred}> "{fpath}"; ' + \
            f'<{apps_terms}{iv_pred}> "{indi_key_iv_b64}"; ' + \
            f'<{apps_terms}{indi_key_pred}> "{enc_indi_key_b64}".}};'
    g.update(query)

    # Write back ind-keys.ttl
    ttl_str = g.serialize(format='turtle', base=server_url)
    with open(ind_key_path, 'w') as f:
        f.write(ttl_str)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process secret and path arguments')
    parser.add_argument('srcpath', help='Path of the file to be uploaded')
    parser.add_argument('destpath', help='Path of the destination file within data folder')
    args = parser.parse_args()

    # Destination file path format: server_path/pod_name/app_name/data/data_file

    dest_path = os.path.abspath(args.destpath)
    assert dest_path.startswith(server_path)
    items = dest_path.replace(server_path, '').split('/')
    assert len(items) >= 4
    pod_name = items[0]
    app_name = items[1]
    assert items[2] == 'data'
    app_path = f'{server_path}{pod_name}/{app_name}'

    # Generate master encryption key from the user-provided security key

    security_key_str = getpass(prompt='Security Key: ')
    master_key = gen_master_key(security_key_str)
    verify_key = gen_verify_key(security_key_str)

    # Verify security key

    _map = parse_ttl(f'{app_path}/encryption/enc-keys.ttl')
    enc_key_url, enc_key_map = list(_map.items())[0]
    verify_key_stored = enc_key_map[verify_key_pred]
    if verify_key.decode('utf-8') != verify_key_stored:
        print('ERROR: Incorrect security key (verification failed).')
        sys.exit(0)

    # Read content of source file

    src_path = args.srcpath
    assert os.path.exists(src_path)
    with open(src_path, 'r') as f:
        file_content = f.read()

    # Write encrypted content to POD

    file_path = '/'.join(items)  # pod_name/app_name/data/data_file
    r = urlparse(enc_key_url)
    server_url = f'{r.scheme}://{r.netloc}'
    upload_file(file_content, file_path, server_url, master_key)

