import os
import argparse

from Cryptodome.Random import get_random_bytes
from pod_helper import encrypt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process secret and path arguments')
    parser.add_argument('filepath', help='Path of the file to be uploaded')
    args = parser.parse_args()

    # Read content of source file

    file_path = args.filepath
    assert os.path.exists(file_path)
    with open(file_path, 'r') as f:
        file_content = f.read()

    # Encrypt content using random key and IV

    session_key = get_random_bytes(32)
    data_iv = get_random_bytes(16)
    enc_data_b64 = encrypt(file_content, session_key, data_iv)

    print(enc_data_b64)

