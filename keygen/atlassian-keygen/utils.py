# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import codecs
from contextlib import contextmanager
import string
import sys

STD_IO_MARK = '-'


def unicodefy_std_io():
    sys.stdin = codecs.getreader(sys.stdin.encoding or sys.getfilesystemencoding())(sys.stdin)
    sys.stdout = codecs.getwriter(sys.stdout.encoding or sys.getfilesystemencoding())(sys.stdout)
    sys.stderr = codecs.getwriter(sys.stdout.encoding or sys.getfilesystemencoding())(sys.stderr)


@contextmanager
def smart_open(file_path, mode='rb', encoding='utf-8', std_io=None):
    """
    :type file_path: unicode
    :type mode: unicode
    :type encoding: unicode
    :type std_io: file
    :rtype: collections.Iterable[StreamReaderWriter]
    """
    if file_path == STD_IO_MARK:
        if std_io is not None:
            yield std_io
        elif 'r' in mode:
            yield sys.stdin
        else:
            yield sys.stdout
    else:
        with codecs.open(file_path, mode=mode, encoding=encoding) as f:
            yield f


def _iter_digits(number, base, alphabet):
    if number == 0:
        yield alphabet[0]
        return

    is_positive = True
    if number < 0:
        is_positive = False
        number = -number

    while number > 0:
        number, remainder = divmod(number, base)
        yield alphabet[remainder]

    if not is_positive:
        yield '-'


def int2str(number, base=10, alphabet=''.join((string.digits, string.ascii_lowercase))):
    """
    :type number: int
    :type base: int
    :type alphabet: unicode
    :rtype: unicode
    """
    return ''.join(_iter_digits(number, base, alphabet))[::-1]
