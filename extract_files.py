# MIT License

# Copyright (c) Microsoft Corporation.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE

import json
import base64
import sys
import argparse

def get_padded_str(str_content):
    rem = len(str_content) % 4
    str_content += "=" * (4 - rem)
    return str_content

def dump_files(key_attestation_file, cert_file, attest_data_file):
    with open(key_attestation_file, 'r') as file:
        data = json.loads(file.read())
        if 'attributes' not in data or 'attestation' not in data['attributes']:
            print('Invalid key attestation file')
            sys.exit(1)

        if 'certificates' not in data['attributes']['attestation']:
            print('No certificates found in key attestation file')
            sys.exit(1)

        if 'privateKeyAttestation' not in data['attributes']['attestation'] and 'publicKeyAttestation' not in data['attributes']['attestation']:
            print('key attestation file does not contain public or private key attestations')
            sys.exit(1)

        with open(cert_file, 'w') as file:
            file.write(base64.urlsafe_b64decode(get_padded_str(data['attributes']['attestation']['certificates'])).decode('utf-8'))
            print(f"Certificates bundle written to file: {cert_file}")
        
        if 'privateKeyAttestation' in data['attributes']['attestation']:
            with open(f'{attest_data_file}-pri', 'wb') as attest_file:
                attest_data = base64.urlsafe_b64decode(get_padded_str(data['attributes']['attestation']['privateKeyAttestation']))
                attest_file.write(attest_data)
                print(f"Private key attestation written to file: {attest_data_file}-pri")

        if 'publicKeyAttestation' in data['attributes']['attestation']:
            with open(f'{attest_data_file}-pub', 'wb') as attest_file:
                attest_data = base64.urlsafe_b64decode(get_padded_str(data['attributes']['attestation']['publicKeyAttestation']))
                attest_file.write(attest_data)
                print(f"Public key attestation written to file: {attest_data_file}-pub")

    print("Files extracted successfully!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-aj", "--attestation_json_file", help="(Input) Name of the file containing the json output of get attestation az rest call.", required=True)
    parser.add_argument("-cb", "--cert_bundle", help="(Output) Name of file to write the certificate bundle.", required=True)  
    parser.add_argument("-af", "--attestation_binary_file", help=" (Output) Name of file to write the attestation binary file to write to.", required=True)

    args = parser.parse_args()
    
    dump_files(args.attestation_json_file, args.cert_bundle, args.attestation_binary_file)
    sys.exit(0)