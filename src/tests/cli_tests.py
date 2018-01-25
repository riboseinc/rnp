#!/usr/bin/env python2

import sys
import tempfile
import os
from os import path
import shutil
import re
import time
import unittest
import itertools
import logging

from cli_common import (
    find_utility,
    run_proc,
    pswd_pipe,
    rnp_file_path,
    random_text,
    file_text,
    raise_err
)
from gnupg import GnuPG as GnuPG
from rnp import Rnp as Rnp

WORKDIR = ''
RNP = ''
RNPK = ''
GPG = ''
RNPDIR = ''
PASSWORD = 'password'
RMWORKDIR = True
TESTS_SUCCEEDED = []
TESTS_FAILED = []
TEST_WORKFILES = []


# Key userids
KEY_ENCRYPT = 'encryption@rnp'
KEY_SIGN_RNP = 'signing@rnp'
KEY_SIGN_GPG = 'signing@gpg'

RE_RSA_KEY = r'(?s)^' \
r'# .*' \
r':public key packet:\s+' \
r'version 4, algo 1, created \d+, expires 0\s+' \
r'pkey\[0\]: \[(\d{4}) bits\]\s+' \
r'pkey\[1\]: \[17 bits\]\s+' \
r'keyid: ([0-9A-F]{16})\s+' \
r'# .*' \
r':user ID packet: "(.+)"\s+' \
r'# .*' \
r':signature packet: algo 1, keyid \2\s+' \
r'.*' \
r'# .*' \
r':public sub key packet:' \
r'.*' \
r':signature packet: algo 1, keyid \2\s+' \
r'.*$'

RE_RSA_KEY_LIST = r'^\s*' \
r'2 keys found\s+' \
r'pub\s+(\d{4})/RSA \(Encrypt or Sign\) ([0-9a-z]{16}) \d{4}-\d{2}-\d{2} \[.*\]\s+' \
r'([0-9a-z]{40})\s+' \
r'uid\s+(.+)\s+' \
r'sub.+\s+' \
r'[0-9a-z]{40}\s+$'

RE_MULTIPLE_KEY_LIST = r'(?s)^\s*(\d+) (?:key|keys) found.*$'
RE_MULTIPLE_KEY_5 = r'(?s)^\s*' \
r'10 keys found.*' \
r'.+uid\s+0@rnp-multiple' \
r'.+uid\s+1@rnp-multiple' \
r'.+uid\s+2@rnp-multiple' \
r'.+uid\s+3@rnp-multiple' \
r'.+uid\s+4@rnp-multiple.*$'

RE_GPG_SINGLE_RSA_KEY = r'(?s)^\s*' \
r'.+-+\s*' \
r'pub\s+rsa.+' \
r'\s+([0-9A-F]{40})\s*' \
r'uid\s+.+rsakey@gpg.*'

RE_GPG_GOOD_SIGNATURE = r'(?s)^\s*' \
r'gpg: Signature made .*' \
r'gpg: Good signature from "(.*)".*'

RE_RNP_GOOD_SIGNATURE = r'(?s)^.*' \
r'Good signature made .*' \
r'using .* key .*' \
r'signature .*' \
r'uid\s+(.*)\s*' \
r'Signature\(s\) verified successfully.*$'

def check_packets(fname, regexp):
    ret, output, err = run_proc(GPG, ['--list-packets', fname])
    if ret != 0:
        logging.error(err)
        return None
    else:
        result = re.match(regexp, output)
        if not result:
            logging.debug('Wrong packets:')
            logging.debug(output)
        return result


def clear_keyrings():
    shutil.rmtree(RNPDIR, ignore_errors=True)
    os.mkdir(RNPDIR, 0700)

    while os.path.isdir(GPGDIR):
        try:
            shutil.rmtree(GPGDIR)
        except:
            time.sleep(0.1)
    os.mkdir(GPGDIR, 0700)


def compare_files(src, dst, message):
    if file_text(src) != file_text(dst):
        raise_err(message)


def remove_files(*args):
    try:
        for fpath in args:
            os.remove(fpath)
    except:
        pass


def reg_workfiles(mainname, *exts):
    global TEST_WORKFILES
    res = []
    for ext in exts:
        fpath = path.join(WORKDIR, mainname + ext)
        if fpath in TEST_WORKFILES:
            logging.warn('Warning! Path {} is already in TEST_WORKFILES'.format(fpath))
        else:
            TEST_WORKFILES += [fpath]
        res += [fpath]
    return res


def clear_workfiles():
    global TEST_WORKFILES
    for fpath in TEST_WORKFILES:
        try:
            os.remove(fpath)
        except OSError:
            pass
    TEST_WORKFILES = []


def rnp_genkey_rsa(userid, bits=2048):
    pipe = pswd_pipe(PASSWORD)
    ret, _, err = run_proc(RNPK, ['--numbits', str(bits), '--homedir',
                                    RNPDIR, '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
    os.close(pipe)
    if ret != 0:
        raise_err('rsa key generation failed', err)

def rnp_encrypt_file(recipient, src, dst, zlevel=6, zalgo='zip', armor=False):
    params = ['--homedir', RNPDIR, '--userid', recipient, '-z',
              str(zlevel), '--' + zalgo, '--encrypt', src, '--output', dst]
    if armor:
        params += ['--armor']
    ret, _, err = run_proc(RNP, params)
    if ret != 0:
        raise_err('rnp encryption failed', err)


def rnp_symencrypt_file(src, dst, cipher, zlevel=6, zalgo='zip', armor=False):
    pipe = pswd_pipe(PASSWORD)
    params = ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--cipher', cipher, '-z', str(
        zlevel), '--' + zalgo, '-c', src, '--output', dst]
    if armor:
        params += ['--armor']
    ret, _, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp symmetric encryption failed', err)


def rnp_decrypt_file(src, dst):
    pipe = pswd_pipe(PASSWORD)
    ret, out, err = run_proc(
        RNP, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--decrypt', src, '--output', dst])
    os.close(pipe)
    if ret != 0:
        raise_err('rnp decryption failed', out + err)


def rnp_sign_file(src, dst, signer, armor=False):
    pipe = pswd_pipe(PASSWORD)
    params = ['--homedir', RNPDIR, '--pass-fd',
              str(pipe), '--userid', signer, '--sign', src, '--output', dst]
    if armor:
        params += ['--armor']
    ret, _, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp signing failed', err)


def rnp_sign_detached(src, signer, armor=False):
    pipe = pswd_pipe(PASSWORD)
    params = ['--homedir', RNPDIR, '--pass-fd',
              str(pipe), '--userid', signer, '--sign', '--detach', src]
    if armor:
        params += ['--armor']
    ret, _, err = run_proc(RNP, params)
    os.close(pipe)
    if ret != 0:
        raise_err('rnp detached signing failed', err)


def rnp_sign_cleartext(src, dst, signer):
    pipe = pswd_pipe(PASSWORD)
    ret, _, err = run_proc(RNP, ['--homedir', RNPDIR, '--pass-fd', str(
        pipe), '--userid', signer, '--output', dst, '--clearsign', src])
    os.close(pipe)
    if ret != 0:
        raise_err('rnp cleartext signing failed', err)


def rnp_verify_file(src, dst, signer=None):
    params = ['--homedir', RNPDIR, '--verify-cat', src, '--output', dst]
    ret, out, err = run_proc(RNP, params)
    if ret != 0:
        raise_err('rnp verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong rnp verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp verification failed, wrong signer')


def rnp_verify_detached(sig, signer=None):
    ret, out, err = run_proc(RNP, ['--homedir', RNPDIR, '--verify', sig])
    if ret != 0:
        raise_err('rnp detached verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong rnp detached verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp detached verification failed, wrong signer'.format())


def rnp_verify_cleartext(src, signer=None):
    params = ['--homedir', RNPDIR, '--verify', src]
    ret, out, err = run_proc(RNP, params)
    if ret != 0:
        raise_err('rnp verification failed', err + out)
    # Check RNP output
    match = re.match(RE_RNP_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong rnp verification output', err)
    if signer and (not match.group(1).strip() == signer.strip()):
        raise_err('rnp verification failed, wrong signer')


def gpg_import_pubring(kpath=None):
    if not kpath:
        kpath = path.join(RNPDIR, 'pubring.gpg')
    ret, _, err = run_proc(
        GPG, ['--batch', '--homedir', GPGDIR, '--import', kpath])
    if ret != 0:
        raise_err('gpg key import failed', err)


def gpg_import_secring(kpath=None):
    if not kpath:
        kpath = path.join(RNPDIR, 'secring.gpg')
    ret, _, err = run_proc(
        GPG, ['--batch', '--passphrase', PASSWORD, '--homedir', GPGDIR, '--import', kpath])
    if ret != 0:
        raise_err('gpg secret key import failed', err)


def gpg_encrypt_file(src, dst, cipher='AES', zlevel=6, zalgo=1, armor=False):
    params = ['--homedir', GPGDIR, '-e', '-z', str(zlevel), '--compress-algo', str(
        zalgo), '-r', KEY_ENCRYPT, '--batch', '--cipher-algo', cipher, '--trust-model', 'always', '--output', dst, src]
    if armor:
        params.insert(2, '--armor')
    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg encryption failed for cipher ' + cipher, err)


def gpg_symencrypt_file(src, dst, cipher='AES', zlevel=6, zalgo=1, armor=False):
    params = ['--homedir', GPGDIR, '-c', '-z', str(zlevel), '--s2k-count', '65536', '--compress-algo', str(
        zalgo), '--batch', '--passphrase', PASSWORD, '--cipher-algo', cipher, '--output', dst, src]
    if armor:
        params.insert(2, '--armor')
    ret, out, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg symmetric encryption failed for cipher ' + cipher, err)


def gpg_decrypt_file(src, dst, keypass):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch',
                                   '--yes', '--passphrase', keypass, '--trust-model', 'always', '-o', dst, '-d', src])
    if ret != 0:
        raise_err('gpg decryption failed', err)


def gpg_verify_file(src, dst, signer=None):
    ret, out, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch',
                                   '--yes', '--trust-model', 'always', '-o', dst, '--verify', src])
    if ret != 0:
        raise_err('gpg verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')


def gpg_verify_detached(src, sig, signer=None):
    ret, _, err = run_proc(GPG, ['--homedir', GPGDIR, '--batch',
                                   '--yes', '--trust-model', 'always', '--verify', sig, src])
    if ret != 0:
        raise_err('gpg detached verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg detached verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg detached verification failed, wrong signer')


def gpg_verify_cleartext(src, signer=None):
    ret, _, err = run_proc(
        GPG, ['--homedir', GPGDIR, '--batch', '--yes', '--trust-model', 'always', '--verify', src])
    if ret != 0:
        raise_err('gpg cleartext verification failed', err)
    # Check GPG output
    match = re.match(RE_GPG_GOOD_SIGNATURE, err)
    if not match:
        raise_err('wrong gpg verification output', err)
    if signer and (not match.group(1) == signer):
        raise_err('gpg verification failed, wrong signer')


def gpg_sign_file(src, dst, signer, zlevel=6, zalgo=1, armor=False):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '-z', str(zlevel), '--compress-algo', str(
        zalgo), '--batch', '--yes', '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '-s', src]
    if armor:
        params.insert(2, '--armor')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg signing failed', err)


def gpg_sign_detached(src, signer, armor=False):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes',
              '--passphrase', PASSWORD, '--trust-model', 'always', '-u', signer, '--detach-sign', src]
    if armor:
        params.insert(2, '--armor')
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg detached signing failed', err)


def gpg_sign_cleartext(src, dst, signer):
    params = ['--homedir', GPGDIR, '--pinentry-mode=loopback', '--batch', '--yes', '--passphrase',
              PASSWORD, '--trust-model', 'always', '-u', signer, '-o', dst, '--clearsign', src]
    ret, _, err = run_proc(GPG, params)
    if ret != 0:
        raise_err('gpg cleartext signing failed', err)


'''
    Things to try here later on:
    - different symmetric algorithms
    - different file sizes (block len/packet len tests)
    - different public key algorithms
    - different compression levels/algorithms
'''


def gpg_to_rnp_encryption(cipher, filesize, zlevel=6, zalgo=1):
    '''
    Encrypts with GPG and decrypts with RNP
    '''
    src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with GPG
        gpg_encrypt_file(src, dst, cipher, zlevel, zalgo, armor)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')
        remove_files(dst, dec)
    clear_workfiles()


def file_encryption_rnp_to_gpg(filesize, zlevel=6, zalgo='zip'):
    '''
    Encrypts with RNP and decrypts with GPG and RNP
    '''
    # TODO: Would be better to do "with reg_workfiles() as src,dst,enc ... and
    # do cleanup at the end"
    src, dst, enc = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with RNP
        rnp_encrypt_file(KEY_ENCRYPT, src, enc, zlevel, zalgo, armor)
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')
        remove_files(enc, dst)
    clear_workfiles()

'''
    Things to try later:
    - different public key algorithms
    - decryption with generated by GPG and imported keys
'''


def rnp_sym_encryption_gpg_to_rnp(cipher, filesize, zlevel=6, zalgo=1):
    src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with GPG
        gpg_symencrypt_file(src, dst, cipher, zlevel, zalgo, armor)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')
        remove_files(dst, dec)
    clear_workfiles()


def rnp_sym_encryption_rnp_to_gpg(cipher, filesize, zlevel=6, zalgo='zip'):
    src, dst, enc = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Encrypt cleartext file with RNP
        rnp_symencrypt_file(src, enc, cipher, zlevel, zalgo, armor)
        # Decrypt encrypted file with GPG
        gpg_decrypt_file(enc, dst, PASSWORD)
        compare_files(src, dst, 'gpg decrypted data differs')
        remove_files(dst)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(enc, dst)
        compare_files(src, dst, 'rnp decrypted data differs')
        remove_files(enc, dst)
    clear_workfiles()


def rnp_signing_rnp_to_gpg(filesize):
    src, sig, ver = reg_workfiles('cleartext', '.txt', '.sig', '.ver')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [False, True]:
        # Sign file with RNP
        rnp_sign_file(src, sig, KEY_SIGN_RNP, armor)
        # Verify signed file with RNP
        rnp_verify_file(sig, ver, KEY_SIGN_RNP)
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(ver)
        # Verify signed message with GPG
        gpg_verify_file(sig, ver, KEY_SIGN_RNP)
        compare_files(src, ver, 'gpg verified data differs')
        remove_files(sig, ver)
    clear_workfiles()


def rnp_detached_signing_rnp_to_gpg(filesize):
    src, sig, asc = reg_workfiles('cleartext', '.txt', '.txt.sig', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with RNP
        rnp_sign_detached(src, KEY_SIGN_RNP, armor)
        sigpath = asc if armor else sig
        # Verify signature with RNP
        rnp_verify_detached(sigpath, KEY_SIGN_RNP)
        # Verify signed message with GPG
        gpg_verify_detached(src, sigpath, KEY_SIGN_RNP)
        remove_files(sigpath)
    clear_workfiles()


def rnp_cleartext_signing_rnp_to_gpg(filesize):
    src, asc = reg_workfiles('cleartext', '.txt', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    # Sign file with RNP
    rnp_sign_cleartext(src, asc, KEY_SIGN_RNP)
    # Verify signature with RNP
    rnp_verify_cleartext(asc, KEY_SIGN_RNP)
    # Verify signed message with GPG
    gpg_verify_cleartext(asc, KEY_SIGN_RNP)
    clear_workfiles()


def rnp_signing_gpg_to_rnp(filesize, zlevel=6, zalgo=1):
    src, sig, ver = reg_workfiles('cleartext', '.txt', '.sig', '.ver')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with GPG
        gpg_sign_file(src, sig, KEY_SIGN_GPG, zlevel, zalgo, armor)
        # Verify file with RNP
        rnp_verify_file(sig, ver, KEY_SIGN_GPG)
        compare_files(src, ver, 'rnp verified data differs')
        remove_files(sig, ver)
    clear_workfiles()


def rnp_detached_signing_gpg_to_rnp(filesize):
    src, sig, asc = reg_workfiles('cleartext', '.txt', '.txt.sig', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    for armor in [True, False]:
        # Sign file with GPG
        gpg_sign_detached(src, KEY_SIGN_GPG, armor)
        sigpath = asc if armor else sig
        # Verify file with RNP
        rnp_verify_detached(sigpath, KEY_SIGN_GPG)
    clear_workfiles()


def rnp_cleartext_signing_gpg_to_rnp(filesize):
    src, asc = reg_workfiles('cleartext', '.txt', '.txt.asc')
    # Generate random file of required size
    random_text(src, filesize)
    # Sign file with GPG
    gpg_sign_cleartext(src, asc, KEY_SIGN_GPG)
    # Verify signature with RNP
    rnp_verify_cleartext(asc, KEY_SIGN_GPG)
    # Verify signed message with GPG
    gpg_verify_cleartext(asc, KEY_SIGN_GPG)
    clear_workfiles()


def setup(loglvl):
    # Setting up directories.
    global RMWORKDIR, WORKDIR, RNPDIR, RNP, RNPK, GPG, GPGDIR
    logging.basicConfig(stream=sys.stderr, format="%(message)s")
    logging.getLogger().setLevel(loglvl)
    WORKDIR = os.getcwd()
    if not '/tmp/' in WORKDIR:
        WORKDIR = tempfile.mkdtemp(prefix='rnpctmp')
        RMWORKDIR = True

    logging.info('Running in ' + WORKDIR)

    RNPDIR = path.join(WORKDIR, '.rnp')
    RNP = rnp_file_path('src/rnp/rnp')
    RNPK = rnp_file_path('src/rnpkeys/rnpkeys')
    os.mkdir(RNPDIR, 0700)

    GPGDIR = path.join(WORKDIR, '.gpg')
    GPG = os.getenv('RNPC_GPG_PATH') or find_utility('gpg')
    os.mkdir(GPGDIR, 0700)


'''
    Things to try here later on:
    - different public key algorithms
    - different key protection levels/algorithms
    - armored import/export
'''
class Keystore(unittest.TestCase):
    def tearDown(self):
        clear_workfiles()

    @staticmethod
    def _rnpkey_generate_rsa(bits= None):
        # Setup command line params
        if bits:
            params = ['--numbits', str(bits)]
        else:
            params = []
            bits = 2048

        userid = str(bits) + '@rnptest'
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        params = params + ['--homedir', RNPDIR, '--pass-fd',
                        str(pipe), '--userid', userid, '--generate-key']
        # Run key generation
        ret, out, err = run_proc(RNPK, params)
        os.close(pipe)
        if ret != 0:
            raise_err('key generation failed', err)
        # Check packets using the gpg
        match = check_packets(path.join(RNPDIR, 'pubring.gpg'), RE_RSA_KEY)
        if not match:
            raise_err('generated key check failed')
        keybits = int(match.group(1))
        if keybits > bits or keybits <= bits - 8:
            raise_err('wrong key bits')
        keyid = match.group(2)
        if not match.group(3) == userid:
            raise_err('wrong user id')
        # List keys using the rnpkeys
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        if ret != 0:
            raise_err('key list failed', err)
        match = re.match(RE_RSA_KEY_LIST, out)
        # Compare key ids
        if not match:
            raise_err('wrong key list output', out)
        if not match.group(3)[-16:] == match.group(2) or not match.group(2) == keyid.lower():
            raise_err('wrong key ids')
        if not match.group(1) == str(bits):
            raise_err('wrong key bits in list')
        # Import key to the gnupg
        ret, out, err = run_proc(GPG, ['--batch', '--passphrase', PASSWORD, '--homedir', GPGDIR,
                                    '--import', path.join(RNPDIR, 'pubring.gpg'), path.join(RNPDIR, 'secring.gpg')])
        if ret != 0:
            raise_err('gpg key import failed', err)
        # Cleanup and return
        clear_keyrings()

    @unittest.skip("Skipping until #550 is fixed")
    def test_generate_default_rsa_key(self):
        Keystore._rnpkey_generate_rsa()

    def test_generate_4096_rsa_key(self):
        Keystore._rnpkey_generate_rsa(4096)

    def test_generate_multiple_rsa_key__check_if_available(self):
        '''
        Generate multiple RSA keys and check if they are all available
        '''
        clear_keyrings()
        # Generate 5 keys with different user ids
        for i in range(0, 5):
            # generate the next key
            pipe = pswd_pipe(PASSWORD)
            userid = str(i) + '@rnp-multiple'
            ret, out, err = run_proc(RNPK, ['--numbits', '2048', '--homedir', RNPDIR,
                                            '--pass-fd', str(pipe), '--userid', userid, '--generate-key'])
            os.close(pipe)
            if ret != 0:
                raise_err('key generation failed', err)
            # list keys using the rnpkeys, checking whether it reports correct key
            # number
            ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
            if ret != 0:
                raise_err('key list failed', err)
            match = re.match(RE_MULTIPLE_KEY_LIST, out)
            if not match:
                raise_err('wrong key list output', out)
            if not match.group(1) == str((i + 1) * 2):
                raise_err('wrong key count', out)

        # Checking the 5 keys output
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--list-keys'])
        if ret != 0:
            raise_err('key list failed', err)
        match = re.match(RE_MULTIPLE_KEY_5, out)
        if not match:
            raise_err('wrong key list output', out)

        # Cleanup and return
        clear_keyrings()

    @unittest.skip("Skipping until #550 is fixed")
    def test_generate_key_with_gpg_import_to_rnp(self):
        '''
        Generate key with GnuPG and import it to rnp
        '''
        # Generate key in GnuPG
        ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR,
                                    '--passphrase', '', '--quick-generate-key', 'rsakey@gpg', 'rsa'])
        if ret != 0:
            raise_err('gpg key generation failed', err)
        # Getting fingerprint of the generated key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--list-keys'])
        match = re.match(RE_GPG_SINGLE_RSA_KEY, out)
        if not match:
            raise_err('wrong gpg key list output', out)
        keyfp = match.group(1)
        # Exporting generated public key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--armor', '--export', keyfp])
        if ret != 0:
            raise_err('gpg : public key export failed', err)
        pubpath = path.join(RNPDIR, keyfp + '-pub.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # Exporting generated secret key
        ret, out, err = run_proc(
            GPG, ['--batch', '--homedir', GPGDIR, '--armor', '--export-secret-key', keyfp])
        if ret != 0:
            raise_err('gpg : secret key export failed', err)
        secpath = path.join(RNPDIR, keyfp + '-sec.asc')
        with open(secpath, 'w+') as f:
            f.write(out)
        # Importing public key to rnp
        ret, out, err = run_proc(
            RNPK, ['--homedir', RNPDIR, '--import-key', pubpath])
        if ret != 0:
            raise_err('rnp : public key import failed', err)
        # Importing secret key to rnp
        ret, out, err = run_proc(
            RNPK, ['--homedir', RNPDIR, '--import-key', secpath])
        if ret != 0:
            raise_err('rnp : secret key import failed', err)
        # We do not check keyrings after the import - imported by RNP keys are not
        # saved yet

    def test_generate_with_rnp_import_to_gpg(self):
        '''
        Generate key with RNP and export it and then import to GnuPG
        '''
        # Open pipe for password
        pipe = pswd_pipe(PASSWORD)
        # Run key generation
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--pass-fd', str(pipe), '--userid', 'rsakey@rnp', '--generate-key'])
        os.close(pipe)
        if ret != 0: raise_err('key generation failed', err)
        # Export key
        ret, out, err = run_proc(RNPK, ['--homedir', RNPDIR, '--export-key', 'rsakey@rnp'])
        if ret != 0: raise_err('key export failed', err)
        pubpath = path.join(RNPDIR, 'rnpkey-pub.asc')
        with open(pubpath, 'w+') as f:
            f.write(out)
        # Import key with GPG
        ret, out, err = run_proc(GPG, ['--batch', '--homedir', GPGDIR, '--import', pubpath])
        if ret != 0: raise_err('gpg : public key import failed', err)


class Misc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    def tearDown(self):
        clear_workfiles()

    def test_encryption_no_mdc(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        # Generate random file of required size
        random_text(src, 64000)
        # Encrypt cleartext file with GPG
        params = ['--homedir', GPGDIR, '-c', '-z', '0', '--disable-mdc', '--s2k-count', '65536', '--batch', '--passphrase', PASSWORD, '--output', dst, src]
        ret, _, err = run_proc(GPG, params)
        if ret != 0:
            raise_err('gpg symmetric encryption failed', err)
        # Decrypt encrypted file with RNP
        rnp_decrypt_file(dst, dec)
        compare_files(src, dec, 'rnp decrypted data differs')

    def test_encryption_s2k(self):
        src, dst, dec = reg_workfiles('cleartext', '.txt', '.gpg', '.rnp')
        random_text(src, 64000)

        ciphers = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128',
                'CAMELLIA192', 'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
        hashes = ['SHA1', 'RIPEMD160', 'SHA256', 'SHA384', 'SHA512', 'SHA224']
        s2kmodes = [0, 1, 3]

        def rnp_encryption_s2k_gpg(cipher, hash_alg, s2k=None, iterations=None):
            params = ['--homedir', GPGDIR, '-c', '--s2k-cipher-algo', cipher, '--s2k-digest-algo',
                    hash_alg, '--batch', '--passphrase', PASSWORD, '--output', dst, src]

            if s2k is not None:
                params.insert(7, '--s2k-mode')
                params.insert(8, str(s2k))

                if iterations is not None:
                    params.insert(9, '--s2k-count')
                    params.insert(10, str(iterations))

            ret, _, err = run_proc(GPG, params)
            if ret != 0:
                raise_err('gpg symmetric encryption failed', err)
            rnp_decrypt_file(dst, dec)
            compare_files(src, dec, 'rnp decrypted data differs')
            remove_files(dst, dec)

        for i in range(0, 80):
            rnp_encryption_s2k_gpg(ciphers[i % len(ciphers)], hashes[
                                i % len(hashes)], s2kmodes[i % len(s2kmodes)])

    def test_armor(self):
        src_beg, dst_beg, dst_mid, dst_fin = reg_workfiles('beg','.src','.dst', '.mid.dst', '.fin.dst')

        for data_type in ['msg', 'pubkey', 'seckey', 'sign']:
            random_text(src_beg, 1000)

            run_proc(RNP, ['--enarmor', data_type, src_beg, '--output', dst_beg])
            run_proc(RNP, ['--dearmor', dst_beg, '--output', dst_mid])
            run_proc(RNP, ['--enarmor', data_type, dst_mid, '--output', dst_fin])

            compare_files(dst_beg, dst_fin, "RNP armor/dearmor test failed")
            compare_files(src_beg, dst_mid, "RNP armor/dearmor test failed")
            remove_files(dst_beg, dst_mid, dst_fin)

class Encryption(unittest.TestCase):
    '''
        Things to try later:
        - different public key algorithms
        - different hash algorithms where applicable
        - cleartext signing/verification
        - detached signing/verification

        TODO:
        Tests in this test case should be splitted into many algorithm-specific tests (potentially auto generated)
        Reason being - if you have a problem with BLOWFISH size 1000000, you don't want to wait until everything else gets
        tested before your failing BLOWFISH
    '''
    RNP_CIPHERS = ['AES', 'AES192', 'AES256', 'TWOFISH', 'CAMELLIA128', 'CAMELLIA192', 'CAMELLIA256', 'IDEA', '3DES', 'CAST5', 'BLOWFISH']
    GPG_CIPHERS = ['cast5', 'idea', 'blowfish', 'twofish', 'aes128', 'aes192', 'aes256', 'camellia128', 'camellia192', 'camellia256', 'tripledes']
    SIZES = [20, 1000, 5000, 20000, 150000, 1000000]

    @classmethod
    def setUpClass(cls):
        # Generate keypair in RNP
        rnp_genkey_rsa(KEY_ENCRYPT)
        # Add some other keys to the keyring
        rnp_genkey_rsa('dummy1@rnp', 1024)
        rnp_genkey_rsa('dummy2@rnp', 1024)
        gpg_import_pubring()
        gpg_import_secring()

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    def tearDown(self):
        clear_workfiles()

    def test_file_encryption__gpg_to_rnp(self):
        for cipher,size in itertools.product(Encryption.RNP_CIPHERS, Encryption.SIZES):
            gpg_to_rnp_encryption(cipher,size)
        # Encrypt cleartext file with GPG and decrypt it with RNP, using different ciphers and file sizes

    def test_file_encryption__rnp_to_gpg(self):
        for size in Encryption.SIZES:
            file_encryption_rnp_to_gpg(size)

    def test_sym_encryption__gpg_to_rnp(self):
        # Encrypt cleartext with GPG and decrypt with RNP
        for cipher, size in itertools.product(Encryption.RNP_CIPHERS, Encryption.SIZES):
            rnp_sym_encryption_gpg_to_rnp(cipher, size, 0, 1)
            rnp_sym_encryption_gpg_to_rnp(cipher, size, 6, 1)
            rnp_sym_encryption_gpg_to_rnp(cipher, size, 6, 2)
            rnp_sym_encryption_gpg_to_rnp(cipher, size, 6, 3)

    def test_sym_encryption__rnp_to_gpg(self):
        # Encrypt cleartext with RNP and decrypt with GPG
        for cipher, size in itertools.product(Encryption.GPG_CIPHERS, Encryption.SIZES):
            rnp_sym_encryption_rnp_to_gpg(cipher, size, 0)
            rnp_sym_encryption_rnp_to_gpg(cipher, size, 6, 'zip')
            rnp_sym_encryption_rnp_to_gpg(cipher, size, 6, 'zlib')
            rnp_sym_encryption_rnp_to_gpg(cipher, size, 6, 'bzip2')

class Compression(unittest.TestCase):

    def setUp(self):
        # Compression is currently implemented only for encrypted messages
        rnp_genkey_rsa(KEY_ENCRYPT)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    def tearDown(self):
        clear_keyrings()

    def test_rnp_compression(self):
        levels = [0, 2, 4, 6, 9]
        algosrnp = ['zip', 'zlib', 'bzip2']
        algosgpg = [1, 2, 3]
        sizes = [20, 1000, 5000, 20000, 150000, 1000000]

        for size in sizes:
            for algo in [0, 1, 2]:
                for level in levels:
                    gpg_to_rnp_encryption(
                        'AES', size, level, algosgpg[algo])
                    file_encryption_rnp_to_gpg(size, level, algosrnp[algo])
                    rnp_signing_gpg_to_rnp(size, level, algosgpg[algo])


class Sign(unittest.TestCase):
    # Message sizes to be tested
    SIZES = [20, 1000, 5000, 20000, 150000, 1000000]

class SignDefault(Sign):
    '''
        Things to try later:
        - different public key algorithms
        - different hash algorithms where applicable
        - cleartext signing/verification
        - detached signing/verification
    '''
    # Message sizes to be tested
    SIZES = [20, 1000, 5000, 20000, 150000, 1000000]

    @classmethod
    def setUpClass(cls):
        # Generate keypair in RNP
        rnp_genkey_rsa(KEY_SIGN_RNP)
        rnp_genkey_rsa(KEY_SIGN_GPG)
        gpg_import_pubring()
        gpg_import_secring()

    @classmethod
    def tearDownClass(cls):
        clear_keyrings()

    # TODO: This script should generate one test case per message size.
    #       Not sure how to do it yet
    def test_rnp_to_gpg_default_key(self):
        for size in Sign.SIZES:
            rnp_signing_rnp_to_gpg(size)
            rnp_detached_signing_rnp_to_gpg(size)
            rnp_cleartext_signing_rnp_to_gpg(size)

    def test_gpg_to_rnp_default_key(self):
        for size in Sign.SIZES:
            rnp_signing_gpg_to_rnp(size)
            rnp_detached_signing_gpg_to_rnp(size)
            rnp_cleartext_signing_gpg_to_rnp(size)


class SignECDSA(Sign):
    # {0} must be replaced by ID of the curve 3,4 or 5 (NIST-256,384,521)
    #CURVES = ["NIST P-256", "NIST P-384", "NIST P-521"]
    GPG_GENERATE_ECDSA_PATERN = """
        Key-Type: ecdsa
        Key-Curve: {0}
        Key-Usage: sign auth
        Name-Real: Test Testovich
        Expire-Date: 1y
        Preferences: twofish sha512 zlib
        Name-Email: {1}"""

    # {0} must be replaced by ID of the curve 1,2 or 3 (NIST-256,384,521)
    RNP_GENERATE_ECDSA_PATTERN = "19\n{0}\n"

    def _rnp_sign_verify(self, e1, e2, key_id, keygen_cmd):
        '''
        Helper function for ECDSA verification
        1. e1 creates ECDSA key
        2. e1 exports key
        3. e2 imports key
        2. e1 signs message
        3. e2 verifies message

        eX == entityX
        '''
        keyfile, input, output = reg_workfiles('ecdsa'+str(key_id), '.gpg', '.in', '.out')
        random_text(input, 0x1337)
        self.assertTrue(e1.generte_key_batch(keygen_cmd))
        self.assertTrue(e1.export_key(keyfile, False))
        self.assertTrue(e2.import_key(keyfile))
        self.assertTrue(e1.sign(output, input))
        self.assertTrue(e2.verify(output))
        clear_workfiles()

    def setUp(self):
        self.rnp = Rnp(RNPDIR, RNP, RNPK)
        self.gpg = GnuPG(GPGDIR, GPG)
        self.rnp.password = self.gpg.password = PASSWORD
        self.rnp.userid = self.gpg.userid = 'ecdsatest@secure.gov'

    def test_sign_P256(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(1)
        self._rnp_sign_verify(self.rnp, self.gpg, 1, cmd)

    def test_sign_P384(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(2)
        self._rnp_sign_verify(self.rnp, self.gpg, 2, cmd)

    def test_sign_P521(self):
        cmd = SignECDSA.RNP_GENERATE_ECDSA_PATTERN.format(3)
        self._rnp_sign_verify(self.rnp, self.gpg, 3, cmd)

    def test_verify_P256(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATERN.format(
            "nistp256", self.rnp.userid)
        self._rnp_sign_verify(self.gpg, self.rnp, 3, cmd)

    def test_verify_P384(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATERN.format("nistp384", self.rnp.userid)
        self._rnp_sign_verify(self.gpg, self.rnp, 4, cmd)

    def test_verify_P521(self):
        cmd = SignECDSA.GPG_GENERATE_ECDSA_PATERN.format("nistp521", self.rnp.userid)
        self._rnp_sign_verify(self.gpg, self.rnp, 5, cmd)

if __name__ == '__main__':
    main = unittest.main
    main.USAGE +=   ''.join([
                    "\nRNP test client specific flags:\n",
                    "  -w,\t\t Don't remove working directory\n",
                    "  -d,\t\t Enable debug messages\n"])

    CLEANUP = ("-w" in sys.argv)
    if CLEANUP:
        # -w must be removed as unittest doesn't expect it
        sys.argv.remove('-w')

    LVL = logging.INFO
    if "-d" in sys.argv:
        sys.argv.remove('-d')
        LVL = logging.DEBUG

    setup(LVL)
    main()

    if CLEANUP:
        try:
            if RMWORKDIR:
                shutil.rmtree(WORKDIR)
            else:
                shutil.rmtree(RNPDIR)
                shutil.rmtree(GPGDIR)
        except:
            pass
