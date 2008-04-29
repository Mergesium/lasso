#! /usr/bin/env python

import os
import re

constants = []

def parse(header_file):
    in_comment = False

    content = file(header_file).read().replace('\\\n', ' ')
    for line in content.splitlines():
        if in_comment:
            if '*/' in line:
                in_comment = False
            continue

        if '/*' in line and not '*/' in line:
            continue

        if line.startswith('#define'):
            m = re.match(r'#define\s+([a-zA-Z0-9_]+)\s+[-\w"]', line)
            if not m:
                continue
            constant = m.group(1)
            if constant[0] == '_':
                # ignore private constants
                continue
            constants.append(constant)


for base, dirnames, filenames in os.walk('../lasso/'):
    if base.endswith('/.svn'):
        # ignore svn directories
        continue
    if not 'Makefile.am' in filenames:
        # not a source dir
        continue
    makefile_am = open(os.path.join(base, 'Makefile.am')).read()
    filenames = [x for x in filenames if x.endswith('.h') if x in makefile_am]
    for filename in filenames:
        if filename == 'lasso_config.h':
            continue
        parse(os.path.join(base, filename))


import pprint
pprint.pprint(constants)

