#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import argparse
import base64
import sys
import textwrap
import utils

__version__ = '1.0'


class LicenseGenerationError(Exception):
    pass


class GliffyLicenseGenerator(object):
    KNOWN_PRODUCTS = {
        'jira': 'Gliffy JIRA Plugin',
        'confluence': 'Gliffy Confluence Plugin',
    }
    # Based on gliffy-license-1.0.1:com.gliffy.core.license.License.Type
    KNOWN_LICENSE_TYPES = {
        'ACADEMIC', 'NON_PROFIT', 'COMMERCIAL', 'COMMERCIAL_ENTERPRISE', 'STARTER',
        'COMMUNITY', 'HOSTED', 'OPEN_SOURCE', 'PERSONAL', 'DEVELOPER',
        'DEMONSTRATION', 'TESTING', 'TRIAL',
        'false',  # LEGACY_COMMERCIAL
        'true',  # LEGACY_TRIAL
    }

    LICENSE_TEMPLATE = (
        '{{"licenseVersion":{license_version},"licenseKey":"{license_key}","licensedSystem":"{name}",'
        '"licensedTo":"{organisation}","licenseType":"{license_type}","quantityUsers":{quantity_users},'
        '"quantityNodes":{quantity_nodes},"expirationDate":"{expiration_date}"}}'
    )
    LICENSE_TYPE = 'COMMERCIAL_ENTERPRISE'
    LICENSE_VERSION = 2
    QUANTITY_USERS = -1
    QUANTITY_NODES = -1

    # Note: The date can NOT be later than Dec 31, 2032, otherwise the year will be cast to 19xx.
    EXPIRATION_DATE = '12/31/32'  # 2032-12-31 in mm/dd/YY format

    ENCODED_LICENSE_LINE_LENGTH = 76

    def __init__(self):
        self._template = self.LICENSE_TEMPLATE

    def generate(self, product, organisation, custom_variables=None, custom_template=None):
        """
        :type product: unicode
        :param product: gliffy product
        :type organisation: unicode
        :param organisation: company name used to register the product
        :type custom_variables: dict[unicode, unicode | object]
        :type custom_template: unicode | None
        :rtype: unicode
        :return: not-encoded gliffy license
        """
        template = self._template or custom_template or ''
        template = template.strip()
        if not template:
            raise LicenseGenerationError('no license template defined')

        template_variables = self.generate_default_variables()
        product_name = self.KNOWN_PRODUCTS.get(product, None)
        if product_name:
            template_variables['name'] = product_name
        if organisation:
            template_variables['organisation'] = organisation
        template_variables.update(custom_variables or {})

        try:
            license_key = self._calculate_license_key(template_variables)
        except KeyError as e:
            raise LicenseGenerationError('missing required template variable to generate license key', e)

        template_variables['license_key'] = license_key

        try:
            gliffy_license = template.format(**template_variables)
        except KeyError as e:
            raise LicenseGenerationError('missing required template variable to generate license content', e)

        return gliffy_license

    def encode(self, license_text):
        """
        :type license_text: unicode
        :param license_text: a gliffy license in plain text
        :rtype: unicode
        """
        license_base64 = base64.b64encode(license_text.encode('utf-8')).decode('utf-8')
        wrapped_license = '\n'.join(textwrap.wrap(license_base64, self.ENCODED_LICENSE_LINE_LENGTH)) + '\n'
        return wrapped_license

    @classmethod
    def generate_default_variables(cls):
        variables = {
            'license_version': cls.LICENSE_VERSION,
            'license_type': cls.LICENSE_TYPE,
            'quantity_users': cls.QUANTITY_USERS,
            'quantity_nodes': cls.QUANTITY_NODES,
            'expiration_date': cls.EXPIRATION_DATE,
        }
        return variables

    @classmethod
    def _calculate_license_key(cls, variables):
        """
        :type variables: dict[unicode, unicode | object]
        :return: unicode
        """
        key_templates = [
            '{quantity_users}{license_type}{name}{organisation}{expiration_date}{node_part}',
            '{organisation}{quantity_users}{node_part}{license_type}{expiration_date}{name}',
            '{node_part}{organisation}{name}{quantity_users}{license_type}{expiration_date}',
            '{name}{expiration_date}{node_part}{organisation}{license_type}{quantity_users}',
        ]

        nodes_count = variables.get('quantity_nodes', 0)
        node_part = '{}'.format(nodes_count) if (nodes_count > 1) else ''

        return '-'.join(cls.rs_hash(t.format(node_part=node_part, **variables)) for t in key_templates)

    @staticmethod
    def rs_hash(text):
        """
        :type text: unicode
        :rtype: unicode
        """
        a = 63689
        b = 378551
        h = 0
        uint32_mask = (1 << 32) - 1
        uint64_mask = (1 << 64) - 1
        int32_mask = (1 << 31) - 1

        for c in text:
            h = h * a + ord(c)
            h &= uint64_mask
            a *= b
            a &= uint32_mask

        result = h & int32_mask
        return '{}'.format(result)


def main():
    utils.unicodefy_std_io()

    parser = argparse.ArgumentParser(description='Generates a gliffy license')
    parser.add_argument('--version', action='version', version='Gliffy License Generator {}'.format(__version__))

    parser.add_argument('product',
                        help='gliffy product, usually one of {}; use `custom` to generate license of a custom product, '
                             'but in this case, custom `template` must be provided'.format(
                             ', '.join(GliffyLicenseGenerator.KNOWN_PRODUCTS.iterkeys())))
    parser.add_argument('organisation',
                        help='your company name used to register the product')

    parser.add_argument('-o', '--output', default=utils.STD_IO_MARK,
                        help='where to save the generated license, default "%(default)s" means stdout')
    parser.add_argument('--show-raw', action='store_true',
                        help='also prints raw (not encoded) license content to stderr')

    def parse_variable_definition(text):
        parts = text.split('=', 1)
        if len(parts) < 2:
            raise argparse.ArgumentTypeError('unrecognized variable definition "{}"'.format(text))
        return tuple(parts)

    group = parser.add_argument_group('customizing license arguments',
                                      'use these arguments to over-write default license template or variables')

    group.add_argument('-v', '--var', action='append', type=parse_variable_definition,
                       help='custom variable used by template, e.g. -v number_of_users=200')
    group.add_argument('-t', '--template', nargs='?', const=utils.STD_IO_MARK,
                       help='a file containing custom license template (if no file name given, read from stdin)')

    unicode_args = map(lambda s: unicode(s, sys.getfilesystemencoding()), sys.argv)
    args = parser.parse_args(unicode_args[1:])

    custom_variables = None
    custom_template = None

    if args.var:
        custom_variables = {key: value for key, value in args.var}

    if args.template:
        with utils.smart_open(args.template, mode='rb') as f:
            custom_template = f.read()

    generator = GliffyLicenseGenerator()
    gliffy_license = generator.generate(args.product, args.organisation, custom_variables, custom_template)

    if args.show_raw:
        print(gliffy_license, file=sys.stderr)
        print(file=sys.stderr)

    encoded_license = generator.encode(gliffy_license)

    with utils.smart_open(args.output, mode='wb') as f:
        f.write(encoded_license)


if __name__ == '__main__':
    main()
