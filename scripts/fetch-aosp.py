#!/usr/bin/env python
# -*- coding: utf-8 -*-
import shutil
import subprocess
import os

TRUST_STORE_REPO_URL = 'https://android.googlesource.com/platform/system/ca-certificates'
TRUST_STORE_TAG = 'android-n-preview-2'
script_folder_path = os.path.dirname(os.path.abspath(__file__))
TRUST_STORE_LOCAL_PATH = os.path.join(script_folder_path, '..', 'data', 'aosp')
FINAL_LOCAL_FILE = os.path.join(script_folder_path, 'aosp.pem')


# Erase local path and file
try:
    os.remove(FINAL_LOCAL_FILE)
except OSError:
    pass

try:
    shutil.rmtree(TRUST_STORE_LOCAL_PATH)
except OSError:
    pass

try:
    os.makedirs(TRUST_STORE_LOCAL_PATH)
except OSError:
    pass

# Fetch the certificates
final_git_command = 'git clone --branch {tag} {repo_url} "{local_path}"'.format(tag=TRUST_STORE_TAG,
                                                                                repo_url=TRUST_STORE_REPO_URL,
                                                                                local_path=TRUST_STORE_LOCAL_PATH)
subprocess.call(final_git_command, shell=True)

# Merge them into one file
cert_files_path = os.path.join(TRUST_STORE_LOCAL_PATH, 'files')
for cert_file in os.listdir(cert_files_path):
    subprocess.call('cat {cert} >> {final_file}'.format(cert=os.path.join(cert_files_path, cert_file),
                                                        final_file=FINAL_LOCAL_FILE),
                    shell=True)
