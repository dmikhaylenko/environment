#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import argparse
from contextlib import contextmanager
import sys
import M2Crypto
import utils

__version__ = '1.0'


class DsaKey(object):
    def __init__(self, prime_length):
        """
        :type prime_length: int
        :param prime_length: the length of the prime to be generated in bits
        """
        self._dsa = M2Crypto.DSA.gen_params(prime_length,
                                            callback=M2Crypto.util.quiet_genparam_callback)
        self._dsa.gen_key()

    def get_private_key(self, cipher=None, pass_phrase=None):
        """
        :type cipher: unicode | None
        :param cipher: name of symmetric key algorithm and mode to encrypt the private key
        :type pass_phrase: unicode | None
        :param pass_phrase: password used to protect the private key when using `cipher`
        :rtype: unicode
        """
        pass_phrase_callback = M2Crypto.util.passphrase_callback
        if pass_phrase:
            pass_phrase_callback = lambda *_: pass_phrase.encode('utf-8')

        with self._open_memory_bio() as bio:
            self._dsa.save_key_bio(bio, cipher=cipher and cipher.encode('utf-8'),
                                   callback=pass_phrase_callback)
            return bio.read().decode('utf-8')

    def get_public_key(self):
        """
        :rtype: unicode
        """
        with self._open_memory_bio() as bio:
            self._dsa.save_pub_key_bio(bio)
            return bio.read().decode('utf-8')

    @staticmethod
    @contextmanager
    def _open_memory_bio():
        bio = M2Crypto.BIO.MemoryBuffer()
        try:
            yield bio
        finally:
            bio.close()


def main():
    utils.unicodefy_std_io()

    parser = argparse.ArgumentParser(description='Generates a pair of DSA keys')
    parser.add_argument('--version', action='version', version='DSA Key Generator {}'.format(__version__))
    parser.add_argument('-o', '--output', default=utils.STD_IO_MARK,
                        help='where to save the generated keys pair, default "%(default)s" means print keys to stdout')
    parser.add_argument('-b', '--bits', type=int, default=1024,
                        help='the length of the prime to be generated in bits (default: %(default)s)')
    parser.add_argument('--cipher',
                        help='name of symmetric key algorithm and mode to encrypt the private key, such as aes_128_cbc')
    parser.add_argument('--passphrase',
                        help='a password used to protect the private key when using `cipher`. If not given, '
                             'you might be asked to enter password during generation process.')

    unicode_args = map(lambda s: unicode(s, sys.getfilesystemencoding()), sys.argv)
    args = parser.parse_args(unicode_args[1:])

    dsa_key = DsaKey(args.bits)
    with utils.smart_open(args.output, mode='wb') as f:
        f.write(dsa_key.get_private_key(cipher=args.cipher, pass_phrase=args.passphrase))
        f.write(dsa_key.get_public_key())


if __name__ == '__main__':
    main()
