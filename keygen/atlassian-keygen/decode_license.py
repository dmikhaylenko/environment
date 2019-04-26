#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import argparse
import base64
import hashlib
import struct
import sys
import zlib
import M2Crypto
import utils

__version__ = '1.0'


class LicenseDecodeError(Exception):
    pass


class AtlassianLicenseDecoder(object):
    VALID_VERSION_NUMBERS = {1, 2}
    VERSION_LENGTH = 3
    ENCODED_LICENSE_LENGTH_BASE = 31
    LICENSE_PREFIX = (13, 14, 12, 10, 15)
    SEPARATOR = 'X'

    def __init__(self, public_key_path):
        """
        :type public_key_path: unicode
        :param public_key_path: the public key file used to verify license
        """
        self.public_key_path = public_key_path

    def decode(self, atlassian_license, need_verify=True):
        """
        :type atlassian_license: unicode
        :param atlassian_license: an atlassian license for any of its product
        :type need_verify: bool
        :raise: LicenseDecodeError
        :rtype: (unicode, bool | None)
        :return: a tuple of two values:
                    1. decoded license text;
                    2. True or False indicates verification succeed or failed, None indicates unknown.
        """
        if not atlassian_license:
            raise ValueError('atlassian_license cannot be None or empty string')

        atlassian_license = self._remove_whitespaces(atlassian_license)
        license_content = self._get_license_content(atlassian_license)
        compressed_license, license_signature = self._split_license_content(license_content)

        verified = None
        if need_verify and self.public_key_path:
            verified = self._verify_license(compressed_license, license_signature)

        decompressed_content = self._decompress(compressed_license)
        return decompressed_content, verified

    @staticmethod
    def _remove_whitespaces(text):
        """
        :type text: unicode
        :rtype: unicode
        """
        return ''.join(c for c in text if not c.isspace())

    @classmethod
    def _get_license_content(cls, atlassian_license):
        """
        :type atlassian_license: unicode
        :raise: LicenseDecodeError
        :rtype: unicode
        :return: major content of license
        """
        if not atlassian_license:
            raise LicenseDecodeError('license has no content')

        pos = atlassian_license.rfind(cls.SEPARATOR)
        if pos < 0:
            raise LicenseDecodeError('cannot find separator "{}"'.format(cls.SEPARATOR))
        if pos + cls.VERSION_LENGTH >= len(atlassian_license):
            raise LicenseDecodeError('incomplete license - no enough data after separator')

        try:
            version = int(atlassian_license[pos + 1:pos + cls.VERSION_LENGTH])
        except ValueError as e:
            raise LicenseDecodeError('non-integer version number', e)

        if version not in cls.VALID_VERSION_NUMBERS:
            raise LicenseDecodeError('unsupported license version {}'.format(version))

        try:
            license_length = int(atlassian_license[pos + cls.VERSION_LENGTH:], cls.ENCODED_LICENSE_LENGTH_BASE)
        except ValueError as e:
            raise LicenseDecodeError('non-{}-based-integer license length'.format(cls.ENCODED_LICENSE_LENGTH_BASE), e)

        if pos != license_length:
            raise LicenseDecodeError('incorrect checksum {} (should be {})'.format(license_length, pos))

        return atlassian_license[:license_length]

    @classmethod
    def _split_license_content(cls, license_content):
        """
        :type license_content: unicode
        :param license_content: major content of license
        :raise: LicenseDecodeError
        :rtype: (bytes, bytes)
        :return: a tuple containing (compressed) license text and signature
        """
        try:
            decoded_bytes = base64.b64decode(license_content.encode('utf-8'))
        except TypeError as e:
            raise LicenseDecodeError('base64-decoding failed', e)

        # Length value is a 4-bytes big-endian unsigned integer
        text_length = struct.unpack('>L', decoded_bytes[:4])[0]
        compressed_license, license_signature = decoded_bytes[4:4 + text_length], decoded_bytes[4 + text_length:]
        return compressed_license, license_signature

    @classmethod
    def _decompress(cls, compressed_text):
        """
        :type compressed_text: bytes
        :rtype: unicode
        """
        try:
            return zlib.decompress(compressed_text[len(cls.LICENSE_PREFIX):]).decode('utf-8')
        except zlib.error as e:
            raise LicenseDecodeError('cannot decompress', e)

    def _verify_license(self, compressed_license, license_signature):
        """
        :type compressed_license: bytes
        :type license_signature: bytes
        :rtype: bool
        """
        digest = hashlib.sha1(compressed_license).digest()
        dsa = M2Crypto.DSA.load_pub_key(self.public_key_path.encode('utf-8'))
        return bool(dsa.verify_asn1(digest, license_signature))


def main():
    utils.unicodefy_std_io()

    parser = argparse.ArgumentParser(description='Decodes (and verifies) an atlassian license')
    parser.add_argument('--version', action='version', version='Atlassian License Decoder {}'.format(__version__))
    parser.add_argument('-k', '--key', '--public-key', default='atlassian.pem',
                        help='a key file (contains at least a public DSA key) used to verify license (default: '
                             '%(default)s)')
    parser.add_argument('-V', '--no-verify', dest='verify', action='store_false',
                        help='skip license verification step')
    parser.add_argument('-i', '--input', default=utils.STD_IO_MARK,
                        help='from where to read license, default "%(default)s" means stdin')
    parser.add_argument('-o', '--output', default=utils.STD_IO_MARK,
                        help='where to save the decoded license, default "%(default)s" means stdout')

    unicode_args = map(lambda s: unicode(s, sys.getfilesystemencoding()), sys.argv)
    args = parser.parse_args(unicode_args[1:])

    with utils.smart_open(args.input, mode='rb') as f:
        atlassian_license = f.read()

    decoder = AtlassianLicenseDecoder(args.key)
    decompressed_content, verified = decoder.decode(atlassian_license, need_verify=args.verify)

    with utils.smart_open(args.output, mode='wb') as f:
        f.write(decompressed_content)

    if verified is not None and not verified:
        print('\nWARNING: the license can NOT be verified by the given public key', file=sys.stderr)


if __name__ == '__main__':
    main()
