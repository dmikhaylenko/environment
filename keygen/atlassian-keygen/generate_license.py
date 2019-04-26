#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import argparse
import base64
import codecs
import datetime
import hashlib
import string
import struct
import sys
import textwrap
import zlib

import M2Crypto
import yaml

import utils

__version__ = '1.1'


class LicenseGenerationError(Exception):
    pass


class LicenseEncodeError(Exception):
    pass


class AtlanssianLicenseGenerator(object):
    KNOWN_LICENSE_EDITIONS = {
        # Based on altassian-extras-api-3.2.api:com.atlassian.extras.api.LicenseEdition
        'BASIC', 'STANDARD', 'PROFESSIONAL', 'ENTERPRISE', 'UNLIMITED',
    }
    KNOWN_LICENSE_TYPES = {
        # Based on altassian-extras-api-3.2.api:com.atlassian.extras.api.LicenseType
        'ACADEMIC', 'COMMERCIAL', 'COMMUNITY', 'DEMONSTRATION', 'DEVELOPER',
        'NON_PROFIT', 'OPEN_SOURCE', 'PERSONAL', 'STARTER', 'HOSTED',
        'TESTING'
    }

    LICENSE_EDITION = 'ENTERPRISE'
    LICENSE_TYPE = 'COMMERCIAL'
    NUMBER_OF_USERS = -1
    EXPIRY_DATE = '2099-12-31'
    SEN = 'SEN-L0000000'

    EVALUATION = 'false'
    ACTIVE = 'true'
    LICENSE_VERSION = 2
    NUMBER_OF_CLUSTER_NODES = 0
    ENTERPRISE = 'true'
    STARTER = 'false'

    CONTACT_EMAIL = 'noreply@foobar.com'

    @classmethod
    def generate_default_variables(cls):
        now = datetime.datetime.now()
        variables = {
            'license_edition': cls.LICENSE_EDITION,
            'license_type': cls.LICENSE_TYPE,
            'number_of_users': cls.NUMBER_OF_USERS,
            'purchase_date': now.strftime('%Y-%m-%d'),
            'creation_date': now.strftime('%Y-%m-%d'),
            'maintenance_expiry_date': cls.EXPIRY_DATE,
            'license_expiry_date': cls.EXPIRY_DATE,
            'sen': cls.SEN,

            'evaluation': cls.EVALUATION,
            'active': cls.ACTIVE,
            'license_version': cls.LICENSE_VERSION,
            'number_of_cluster_nodes': cls.NUMBER_OF_CLUSTER_NODES,
            'enterprise': cls.ENTERPRISE,
            'starter': cls.STARTER,

            'contact_email': cls.CONTACT_EMAIL,

            'created_at': now.ctime(),
        }
        return variables

    def __init__(self, template_file_path):
        """
        :type template_file_path: unicode
        :param template_file_path: a yaml file contains license template
        """
        with codecs.open(template_file_path, 'r', 'utf-8') as f:
            self._product_info = yaml.load(f)
            self._template = self._product_info['template']

    def generate(self, organisation, server_id=None, custom_variables=None):
        """
        :type organisation: unicode
        :param organisation: company name used to register the product
        :type server_id: unicode | None
        :param server_id: server id, usually in format of `ABCD-1234-EFGH-5678`
        :type custom_variables: dict[unicode, unicode | object]
        :rtype: unicode
        :return: not-encoded atlassian license
        """
        template_variables = self.generate_default_variables()
        template_variables.update(self._product_info)
        if organisation:
            template_variables['organisation'] = organisation
        if server_id:
            template_variables['server_id'] = server_id
        template_variables.update(custom_variables or {})

        try:
            atlassian_license = self._template.format(**template_variables)
        except KeyError as e:
            raise LicenseGenerationError('missing required template variable', e)

        return atlassian_license


class AtlassianLicenseEncoder(object):
    VERSION_NUMBER = 2
    VERSION_LENGTH = 3
    ENCODED_LICENSE_LENGTH_BASE = 31
    ENCODED_LICENSE_LENGTH_ALPHABET = ''.join((string.digits, string.ascii_lowercase))
    LICENSE_PREFIX = (13, 14, 12, 10, 15)
    SEPARATOR = 'X'
    ENCODED_LICENSE_LINE_LENGTH = 76
    LICENSE_COMPRESS_LEVEL = 9

    def __init__(self, private_key_path, pass_phrase=None):
        """
        :type private_key_path: unicode
        :param private_key_path: the private key file used to sign license
        :type pass_phrase: unicode | None
        :param pass_phrase: password used by the private key
        """
        pass_phrase_callback = M2Crypto.util.passphrase_callback
        if pass_phrase:
            pass_phrase_callback = lambda *_: pass_phrase.encode('utf-8')

        self._dsa = M2Crypto.DSA.load_key(private_key_path.encode('utf-8'),
                                          callback=pass_phrase_callback)

    def encode(self, license_text):
        """
        :type license_text: unicode
        :param license_text: an atlassian license in plain text
        :rtype: unicode
        """
        compressed_data = zlib.compress(license_text.encode('utf-8'), self.LICENSE_COMPRESS_LEVEL)
        license_prefix = ''.join(map(chr, self.LICENSE_PREFIX)).encode('utf-8')
        license_bytes = license_prefix + compressed_data

        license_digest = hashlib.sha1(license_bytes).digest()
        signature_bytes = self._dsa.sign_asn1(license_digest)

        license_length = len(license_bytes)
        length_bytes = struct.pack('>L', license_length)

        license_base64 = base64.b64encode(
            length_bytes + license_bytes + signature_bytes).decode('utf-8')
        encoded_length = utils.int2str(len(license_base64),
                                       self.ENCODED_LICENSE_LENGTH_BASE,
                                       self.ENCODED_LICENSE_LENGTH_ALPHABET)

        version_text = '{:0{}}'.format(self.VERSION_NUMBER, self.VERSION_LENGTH - 1)

        encoded_license = ''.join([license_base64, self.SEPARATOR, version_text, encoded_length])
        wrapped_license = '\n'.join(textwrap.wrap(
            encoded_license, self.ENCODED_LICENSE_LINE_LENGTH)) + '\n'

        return wrapped_license


def main():
    utils.unicodefy_std_io()

    parser = argparse.ArgumentParser(description='Generates an atlassian license')
    parser.add_argument('--version', action='version',
                        version='Atlassian License Generator {}'.format(__version__))

    parser.add_argument('template',
                        help='path to a license template yaml file, such as `templates/jira.yml`')
    parser.add_argument('organisation',
                        help='your company name used to register the product')
    parser.add_argument('server_id', nargs='?',
                        help='server id, usually in format of `ABCD-1234-EFGH-5678`')

    parser.add_argument('-o', '--output', default=utils.STD_IO_MARK,
                        help='where to save the generated license, default "%(default)s" means '
                             'stdout')
    parser.add_argument('--show-raw', action='store_true',
                        help='also prints raw (not encoded) license content to stderr')
    parser.add_argument('-k', '--key', '--private-key', default='calfzhou.pem',
                        help='a key file (contains at least a private DSA key) used to sign the '
                             'license (default: %(default)s)')
    parser.add_argument('--passphrase',
                        help='password used by the private key. If not given, you might be asked '
                             'to enter it when needed.')

    def parse_variable_definition(text):
        parts = text.split('=', 1)
        if len(parts) < 2:
            raise argparse.ArgumentTypeError('unrecognized variable definition "{}"'.format(text))
        return tuple(parts)

    group = parser.add_argument_group('customizing license arguments',
                                      'use these arguments to over-write default license template '
                                      'or variables')

    group.add_argument('-v', '--var', action='append', type=parse_variable_definition,
                       help='custom variable used by template, e.g. -v number_of_users=200')

    unicode_args = map(lambda s: unicode(s, sys.getfilesystemencoding()), sys.argv)
    args = parser.parse_args(unicode_args[1:])

    custom_variables = None
    if args.var:
        custom_variables = {key: value for key, value in args.var}

    generator = AtlanssianLicenseGenerator(args.template)
    atlassian_license = generator.generate(args.organisation, args.server_id, custom_variables)

    if args.show_raw:
        print(atlassian_license, file=sys.stderr)

    encoder = AtlassianLicenseEncoder(args.key, args.passphrase)
    encoded_license = encoder.encode(atlassian_license)

    with utils.smart_open(args.output, mode='wb') as f:
        f.write(encoded_license)


if __name__ == '__main__':
    main()
