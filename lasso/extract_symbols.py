#! /usr/bin/env python

import io
import glob
import re
import sys
import six

if len(sys.argv) == 2:
    srcdir = sys.argv[1]
else:
    srcdir = '.'

regex = re.compile('LASSO_EXPORT[^;(]*(lasso_[a-zA-Z0-9_]+)', re.MULTILINE)

symbols = []
for header_file in glob.glob('%s/*/*.h' % srcdir) + glob.glob('%s/*.h' % srcdir) + \
        glob.glob('%s/*/*/*.h' % srcdir):
    assert not ('/id-wsf/' in header_file or '/id-wsf-2.0' in header_file)
    symbols.extend(regex.findall(io.open(header_file, encoding='utf-8').read().replace('\\\n', '')))

for s in symbols:
    six.print_(s)

