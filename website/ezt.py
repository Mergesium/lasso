"""ezt.py -- easy templating

ezt templates are simply text files in whatever format you so desire
(such as XML, HTML, etc.) which contain directives sprinkled
throughout.  With these directives it is possible to generate the
dynamic content from the ezt templates.

These directives are enclosed in square brackets.  If you are a
C-programmer, you might be familar with the #ifdef directives of the C
preprocessor 'cpp'.  ezt provides a similar concept.  Additionally EZT
has a 'for' directive, which allows it to iterate (repeat) certain
subsections of the template according to sequence of data items
provided by the application.

The final rendering is performed by the method generate() of the Template
class.  Building template instances can either be done using external
EZT files (convention: use the suffix .ezt for such files):

    >>> template = Template("../templates/log.ezt")

or by calling the parse() method of a template instance directly with
a EZT template string:

    >>> template = Template()
    >>> template.parse('''<html><head>
    ... <title>[title_string]</title></head>
    ... <body><h1>[title_string]</h1>
    ...    [for a_sequence] <p>[a_sequence]</p>
    ...    [end] <hr>
    ...    The [person] is [if-any state]in[else]out[end].
    ... </body>
    ... </html>
    ... ''')

The application should build a dictionary 'data' and pass it together
with the output fileobject to the templates generate method:

    >>> data = {'title_string' : "A Dummy Page",
    ...         'a_sequence' : ['list item 1', 'list item 2', 'another element'],
    ...         'person': "doctor",
    ...         'state' : None }
    >>> import sys
    >>> template.generate(sys.stdout, data)
    <html><head>
    <title>A Dummy Page</title></head>
    <body><h1>A Dummy Page</h1>
     <p>list item 1</p>
     <p>list item 2</p>
     <p>another element</p>
     <hr>
    The doctor is out.
    </body>
    </html>

Template syntax error reporting should be improved.  Currently it is
very sparse (template line numbers would be nice):

    >>> Template().parse("[if-any where] foo [else] bar [end unexpected args]")
    Traceback (innermost last):
      File "<stdin>", line 1, in ?
      File "ezt.py", line 220, in parse
        self.program = self._parse(text)
      File "ezt.py", line 275, in _parse
        raise ArgCountSyntaxError(str(args[1:]))
    ArgCountSyntaxError: ['unexpected', 'args']
    >>> Template().parse("[if unmatched_end]foo[end]")
    Traceback (innermost last):
      File "<stdin>", line 1, in ?
      File "ezt.py", line 206, in parse
        self.program = self._parse(text)
      File "ezt.py", line 266, in _parse
        raise UnmatchedEndError()
    UnmatchedEndError


Directives
==========

 Several directives allow the use of dotted qualified names refering to objects
 or attributes of objects contained in the data dictionary given to the
 .generate() method.

 Qualified names
 ---------------

   Qualified names have two basic forms: a variable reference, or a string
   constant. References are a name from the data dictionary with optional
   dotted attributes (where each intermediary is an object with attributes,
   of course).

   Examples:

     [varname]

     [ob.attr]

     ["string"]

 Simple directives
 -----------------

   [QUAL_NAME]

   This directive is simply replaced by the value of the qualified name.
   If the value is a number it's converted to a string before being
   outputted. If it is None, nothing is outputted. If it is a python file
   object (i.e. any object with a "read" method), it's contents are
   outputted. If it is a callback function (any callable python object
   is assumed to be a callback function), it is invoked and passed an EZT
   printer function as an argument.

   [QUAL_NAME QUAL_NAME ...]

   If the first value is a callback function, it is invoked with the
   output file pointer as a first argument, and the rest of the values as
   additional arguments.

   Otherwise, the first value defines a substitution format, specifying
   constant text and indices of the additional arguments. The arguments
   are substituted and the result is inserted into the output stream.

   Example:
     ["abc %0 def %1 ghi %0" foo bar.baz]

   Note that the first value can be any type of qualified name -- a string
   constant or a variable reference. Use %% to substitute a percent sign.
   Argument indices are 0-based.

   [include "filename"]  or [include QUAL_NAME]

   This directive is replaced by content of the named include file. Note
   that a string constant is more efficient -- the target file is compiled
   inline. In the variable form, the target file is compiled and executed
   at runtime.

 Block directives
 ----------------

   [for QUAL_NAME] ... [end]

   The text within the [for ...] directive and the corresponding [end]
   is repeated for each element in the sequence referred to by the
   qualified name in the for directive.  Within the for block this
   identifiers now refers to the actual item indexed by this loop
   iteration.

   [if-any QUAL_NAME [QUAL_NAME2 ...]] ... [else] ... [end]

   Test if any QUAL_NAME value is not None or an empty string or list.
   The [else] clause is optional.  CAUTION: Numeric values are
   converted to string, so if QUAL_NAME refers to a numeric value 0,
   the then-clause is substituted!

   [if-index INDEX_FROM_FOR odd] ... [else] ... [end]
   [if-index INDEX_FROM_FOR even] ... [else] ... [end]
   [if-index INDEX_FROM_FOR first] ... [else] ... [end]
   [if-index INDEX_FROM_FOR last] ... [else] ... [end]
   [if-index INDEX_FROM_FOR NUMBER] ... [else] ... [end]

   These five directives work similar to [if-any], but are only useful
   within a [for ...]-block (see above).  The odd/even directives are
   for example useful to choose different background colors for
   adjacent rows in a table.  Similar the first/last directives might
   be used to remove certain parts (for example "Diff to previous"
   doesn't make sense, if there is no previous).

   [is QUAL_NAME STRING] ... [else] ... [end]
   [is QUAL_NAME QUAL_NAME] ... [else] ... [end]

   The [is ...] directive is similar to the other conditional
   directives above.  But it allows to compare two value references or
   a value reference with some constant string.

   [define VARIABLE] ... [end]

   The [define ...] directive allows you to create and modify template
   variables from within the template itself.  Essentially, any data
   between inside the [define ...] and its matching [end] will be
   expanded using the other template parsing and output generation
   rules, and then stored as a string value assigned to the variable
   VARIABLE.  The new (or changed) variable is then available for use
   with other mechanisms such as [is ...] or [if-any ...], as long as
   they appear later in the template.

   [format STRING] ... [end]

   The format directive controls how the values substituted into
   templates are escaped before they are put into the output stream. It
   has no effect on the literal text of the templates, only the output
   from [QUAL_NAME ...] directives. STRING can be one of "raw" "html"
   or "xml". The "raw" mode leaves the output unaltered. The "html" and
   "xml" modes escape special characters using entity escapes (like
   &quot; and &gt;)
"""
#
# Copyright (C) 2001-2005 Greg Stein. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#
# This software is maintained by Greg and is available at:
#    http://svn.webdav.org/repos/projects/ezt/trunk/
#

import datetime
import html
import io
import os
import re

#
# Formatting types
#
FORMAT_RAW = 'raw'
FORMAT_HTML = 'html'
FORMAT_XML = 'xml'
FORMAT_RTF = 'rtf'

#
# This regular expression matches three alternatives:
#   expr: DIRECTIVE | BRACKET | COMMENT
#   DIRECTIVE: '[' ITEM (whitespace ITEM)* ']
#   ITEM: STRING | NAME
#   STRING: '"' (not-slash-or-dquote | '\' anychar)* '"'
#   NAME: (alphanum | '_' | '-' | '.')+
#   BRACKET: '[[]'
#   COMMENT: '[#' not-rbracket* ']'
#
# When used with the split() method, the return value will be composed of
# non-matching text and the two paren groups (DIRECTIVE and BRACKET). Since
# the COMMENT matches are not placed into a group, they are considered a
# "splitting" value and simply dropped.
#
_item = r'(?:"(?:[^\\"]|\\.)*"|[-\w.]+)'
_re_parse = re.compile(r'\[(%s(?: +%s)*)\]|(\[\[\])|\[#[^\]]*\]' % (_item, _item))

_re_args = re.compile(r'"(?:[^\\"]|\\.)*"|[-\w.]+')

# block commands and their argument counts
_block_cmd_specs = {'if-index': 2, 'for': 1, 'is': 2, 'define': 1, 'format': 1}
_block_cmds = _block_cmd_specs.keys()

# two regular expresssions for compressing whitespace. the first is used to
# compress any whitespace including a newline into a single newline. the
# second regex is used to compress runs of whitespace into a single space.
_re_newline = re.compile('[ \t\r\f\v]*\n\\s*')
_re_whitespace = re.compile(r'\s\s+')

# this regex is used to substitute arguments into a value. we split the value,
# replace the relevant pieces, and then put it all back together. splitting
# will produce a list of: TEXT ( splitter TEXT )*. splitter will be '%' or
# an integer.
_re_subst = re.compile('%(%|[0-9]+)')


class Template:
    _printers = {
        FORMAT_RAW: '_cmd_print',
        FORMAT_HTML: '_cmd_print_html',
        FORMAT_XML: '_cmd_print_xml',
        FORMAT_RTF: '_cmd_print_rtf',
    }

    def __init__(self, fname=None, compress_whitespace=1, base_format=FORMAT_RAW):
        self.compress_whitespace = compress_whitespace
        if fname:
            self.parse_file(fname, base_format)

    def parse_file(self, fname, base_format=FORMAT_RAW):
        "fname -> a string object with pathname of file containg an EZT template."

        self.parse(_FileReader(fname), base_format)

    def parse(self, text_or_reader, base_format=FORMAT_RAW):
        """Parse the template specified by text_or_reader.

        The argument should be a string containing the template, or it should
        specify a subclass of ezt.Reader which can read templates. The base
        format for printing values is given by base_format.
        """
        if not isinstance(text_or_reader, Reader):
            # assume the argument is a plain text string
            text_or_reader = _TextReader(text_or_reader)

        printer = getattr(self, self._printers[base_format])
        self.program = self._parse(text_or_reader, base_printer=printer)

    def generate(self, fp, data):
        if hasattr(data, '__getitem__') or callable(getattr(data, 'keys', None)):
            # a dictionary-like object was passed. convert it to an
            # attribute-based object.
            class _data_ob:
                def __init__(self, d):
                    self.data = d

                def __getattr__(self, k):
                    try:
                        return self.data[k]
                    except KeyError:
                        raise AttributeError(k)

            data = _data_ob(data)

        ctx = _context()
        ctx.data = data
        ctx.for_index = {}
        ctx.defines = {}
        self._execute(self.program, fp, ctx)

    def _parse(self, reader, for_names=None, file_args=(), base_printer=None):
        """text -> string object containing the template.

        This is a private helper function doing the real work for method parse.
        It returns the parsed template as a 'program'.  This program is a sequence
        made out of strings or (function, argument) 2-tuples.

        Note: comment directives [# ...] are automatically dropped by _re_parse.
        """

        # parse the template program into: (TEXT DIRECTIVE BRACKET)* TEXT
        parts = _re_parse.split(reader.text)

        program = []
        stack = []
        if not for_names:
            for_names = []

        if base_printer:
            printers = [base_printer]
        else:
            printers = [self._cmd_print]

        column = 0
        line = 0

        for i in range(len(parts)):
            piece = parts[i]
            which = i % 3  # discriminate between: TEXT DIRECTIVE BRACKET
            if which == 0:
                # TEXT. append if non-empty.
                line += piece.count('\n')
                last_newline = piece.rfind('\n')
                if last_newline != -1:
                    column = 0
                column += len(piece) - last_newline - 1
                if piece:
                    if self.compress_whitespace:
                        piece = _re_whitespace.sub(' ', _re_newline.sub('\n', piece))
                    program.append(piece)
            elif which == 2:
                # BRACKET directive. append '[' if present.
                if piece:
                    program.append('[')
            elif piece:
                # DIRECTIVE is present.
                args = _re_args.findall(piece)
                cmd = args[0]
                if cmd == 'else':
                    if len(args) > 1:
                        raise ArgCountSyntaxError(str(args[1:]), line, column)
                    # check: don't allow for 'for' cmd
                    try:
                        idx = stack[-1][1]
                    except IndexError:
                        raise UnmatchedElseError('', line, column)
                    true_section = program[idx:]
                    del program[idx:]
                    stack[-1][3] = true_section
                elif cmd == 'end':
                    if len(args) > 1:
                        raise ArgCountSyntaxError(str(args[1:]), line, column)
                    # note: true-section may be None
                    try:
                        cmd, idx, args, true_section = stack.pop()
                    except IndexError:
                        raise UnmatchedEndError('', line, column)
                    else_section = program[idx:]
                    if cmd == 'format':
                        printers.pop()
                    else:
                        func = getattr(self, '_cmd_' + re.sub('-', '_', cmd))
                        program[idx:] = [(func, (args, true_section, else_section))]
                        if cmd == 'for':
                            for_names.pop()
                elif cmd in _block_cmds:
                    if len(args) > _block_cmd_specs[cmd] + 1:
                        raise ArgCountSyntaxError(str(args[1:]), line, column)
                    # this assumes arg1 is always a ref unless cmd is 'define'
                    if cmd != 'define':
                        if len(args) < 2:
                            raise ArgCountSyntaxError(str(args), line, column)
                        args[1] = _prepare_ref(args[1], for_names, file_args)

                    # handle arg2 for the 'is' command
                    if cmd == 'is':
                        if len(args) != 3:
                            raise ArgCountSyntaxError(str(args[1:]), line, column)
                        args[2] = _prepare_ref(args[2], for_names, file_args)
                    elif cmd == 'for':
                        for_names.append(args[1][0])  # append the refname
                    elif cmd == 'format':
                        if args[1][0]:
                            raise BadFormatConstantError(str(args[1:]), line, column)
                        funcname = self._printers.get(args[1][1])
                        if not funcname:
                            raise UnknownFormatConstantError(str(args[1:]), line, column)
                        printers.append(getattr(self, funcname))

                    # remember the cmd, current pos, args, and a section placeholder
                    stack.append([cmd, len(program), args[1:], None])
                elif cmd == 'include':
                    if args[1][0] == '"':
                        include_filename = args[1][1:-1]
                        f_args = []
                        for arg in args[2:]:
                            f_args.append(_prepare_ref(arg, for_names, file_args))
                        program.extend(
                            self._parse(reader.read_other(include_filename), for_names, f_args, printers[-1])
                        )
                    else:
                        if len(args) != 2:
                            raise ArgCountSyntaxError(str(args), line, column)
                        program.append(
                            (self._cmd_include, (_prepare_ref(args[1], for_names, file_args), reader))
                        )
                elif cmd == 'if-any':
                    f_args = []
                    for arg in args[1:]:
                        f_args.append(_prepare_ref(arg, for_names, file_args))
                    stack.append(['if-any', len(program), f_args, None])
                else:
                    # implied PRINT command
                    f_args = []
                    for arg in args:
                        f_args.append(_prepare_ref(arg, for_names, file_args))
                    program.append((printers[-1], f_args))
                column += 2 + len(piece)

        if stack:
            # would be nice to say which blocks...
            raise UnclosedBlocksError('', line, column)
        return program

    def _execute(self, program, fp, ctx):
        """This private helper function takes a 'program' sequence as created
        by the method '_parse' and executes it step by step.  strings are written
        to the file object 'fp' and functions are called.
        """
        for step in program:
            if isinstance(step, str):
                fp.write(step)
            else:
                step[0](step[1], fp, ctx)

    def _cmd_print(self, valref, fp, ctx):
        _write_value(valref, fp, ctx)

    def _cmd_print_html(self, valref, fp, ctx):
        _write_value(valref, fp, ctx, html.escape)

    def _cmd_print_rtf(self, valref, fp, ctx):
        def char2rtf(c):
            if ord(c) < 128:
                return c
            else:
                return '\\u%d?' % ord(c)

        def rtf_escape(s):
            s = ''.join([char2rtf(c) for c in s])
            return '{\\uc1{%s}}' % s

        _write_value(valref, fp, ctx, rtf_escape)

    def _cmd_print_xml(self, valref, fp, ctx):
        # use the same quoting as HTML for now
        self._cmd_print_html(valref, fp, ctx)

    def _cmd_include(self, include_ref, fp, ctx):
        (valref, reader) = include_ref
        fname = _get_value(valref, ctx)
        # note: we don't have the set of for_names to pass into this parse.
        # I don't think there is anything to do but document it. we also
        # don't have a current format (since that is a compile-time concept).
        self._execute(self._parse(reader.read_other(fname)), fp, ctx)

    def _cmd_if_any(self, args, fp, ctx):
        "If any value is a non-empty string or non-empty list, then T else F."
        (valrefs, t_section, f_section) = args
        value = 0
        for valref in valrefs:
            try:
                if _get_value(valref, ctx):
                    value = 1
                    break
            except UnknownReference:
                pass
        self._do_if(value, t_section, f_section, fp, ctx)

    def _cmd_if_index(self, args, fp, ctx):
        ((valref, value), t_section, f_section) = args
        list, idx = ctx.for_index[valref[0]]
        if value == 'even':
            value = idx % 2 == 0
        elif value == 'odd':
            value = idx % 2 == 1
        elif value == 'first':
            value = idx == 0
        elif value == 'last':
            value = idx == len(list) - 1
        else:
            value = idx == int(value)
        self._do_if(value, t_section, f_section, fp, ctx)

    def _cmd_is(self, args, fp, ctx):
        ((left_ref, right_ref), t_section, f_section) = args
        try:
            value = _get_value(right_ref, ctx)
            value = str(_get_value(left_ref, ctx)).lower() == str(value).lower()
        except UnknownReference:
            value = False
        self._do_if(value, t_section, f_section, fp, ctx)

    def _do_if(self, value, t_section, f_section, fp, ctx):
        if t_section is None:
            t_section = f_section
            f_section = None
        if value:
            section = t_section
        else:
            section = f_section
        if section is not None:
            self._execute(section, fp, ctx)

    def _cmd_for(self, args, fp, ctx):
        ((valref,), dummy, section) = args
        try:
            list = _get_value(valref, ctx)
        except UnknownReference:
            return
        if isinstance(list, str):
            raise NeedSequenceError()
        refname = valref[0]
        ctx.for_index[refname] = idx = [list, 0]
        for dummy in list:
            self._execute(section, fp, ctx)
            idx[1] = idx[1] + 1
        del ctx.for_index[refname]

    def _cmd_define(self, args, fp, ctx):
        ((name,), dummy, section) = args
        valfp = io.StringIO()
        if section is not None:
            self._execute(section, valfp, ctx)
        ctx.defines[name] = valfp.getvalue()


def boolean(value):
    "Return a value suitable for [if-any bool_var] usage in a template."
    if value:
        return 'yes'
    return None


def _prepare_ref(refname, for_names, file_args):
    """refname -> a string containing a dotted identifier. example:"foo.bar.bang"
    for_names -> a list of active for sequences.

    Returns a `value reference', a 3-tuple made out of (refname, start, rest),
    for fast access later.
    """
    # is the reference a string constant?
    if refname[0] == '"':
        return None, refname[1:-1], None

    parts = refname.split('.')
    start = parts[0]
    rest = parts[1:]

    # if this is an include-argument, then just return the prepared ref
    if start[:3] == 'arg':
        try:
            idx = int(start[3:])
        except ValueError:
            pass
        else:
            if idx < len(file_args):
                dummy, start, more_rest = file_args[idx]
                if more_rest is None:
                    # the include-argument was a string constant
                    return None, start, None

                # prepend the argument's "rest" for our further processing
                rest[:0] = more_rest

                # rewrite the refname to ensure that any potential 'for' processing
                # has the correct name
                # this can make it hard for debugging include files since we lose
                # the 'argNNN' names
                if not rest:
                    return start, start, []
                refname = start + '.' + '.'.join(rest)

    if for_names:
        # From last to first part, check if this reference is part of a for loop
        for i in range(len(parts), 0, -1):
            name = '.'.join(parts[:i])
            if name in for_names:
                return refname, name, parts[i:]

    return refname, start, rest


def _get_value(value_ref, ctx):
    """(refname, start, rest) -> a prepared `value reference' (see above).
    ctx -> an execution context instance.

    Does a name space lookup within the template name space.  Active
    for blocks take precedence over data dictionary members with the
    same name.
    """
    (refname, start, rest) = value_ref
    if rest is None:
        # it was a string constant
        return start

    # get the starting object
    if start in ctx.for_index:
        list, idx = ctx.for_index[start]
        ob = list[idx]
    elif start in ctx.defines:
        ob = ctx.defines[start]
    elif hasattr(ctx.data, start):
        ob = getattr(ctx.data, start)
    elif refname in ('True', 'False'):
        return bool(refname == 'True')
    else:
        raise UnknownReference(refname)

    # walk the rest of the dotted reference
    for attr in rest:
        try:
            ob = getattr(ob, attr)
        except AttributeError:
            try:
                ob = ob[attr]
            except (TypeError, KeyError):
                try:
                    ob = ob[int(attr)]
                except (ValueError, TypeError):
                    raise UnknownReference(refname)

    # make sure we return a string instead of some various Python types
    if isinstance(ob, (int, float)):
        return str(ob)
    if ob is None:
        return ''

    # string or a sequence
    return ob


def _get_value_fallback(value_ref, ctx):
    try:
        return _get_value(value_ref, ctx)
    except UnknownReference:
        refname = value_ref[0]
        return '[' + refname + ']'


def _write_value(valrefs, fp, ctx, format=lambda s: s):
    try:
        value = _get_value(valrefs[0], ctx)
    except UnknownReference:
        value = '[' + ' '.join([v[0] for v in valrefs]) + ']'
        fp.write(format(value))
        return
    args = list(map(lambda valref, ctx=ctx: _get_value_fallback(valref, ctx), valrefs[1:]))

    # if the value has a 'read' attribute, then it is a stream: copy it
    if hasattr(value, 'read'):
        while True:
            chunk = value.read(16384)
            if not chunk:
                break
            fp.write(format(chunk))

    # value is a callback function
    elif callable(value):
        if getattr(value, 'ezt_call_mode', None) == 'simple':
            # simple call mode, call with args and write the result
            fp.write(value(*args))
        else:
            # default, call with file pointer and extra args
            value(*[fp] + args)

    # value is a substitution pattern
    elif args:
        parts = _re_subst.split(value)
        for i in range(len(parts)):
            piece = parts[i]
            if i % 2 == 1 and piece != '%':
                idx = int(piece)
                if idx < len(args):
                    piece = args[idx]
                else:
                    piece = '<undef>'
            if format:
                fp.write(format(piece))

    elif isinstance(value, datetime.datetime):
        from .misc import localstrftime

        fp.write(localstrftime(value))
    elif isinstance(value, datetime.date):
        from .misc import date_format, strftime

        fp.write(strftime(date_format(), value))
    # plain old value, write to output
    else:
        fp.write(format(str(value)))


class _context:
    """A container for the execution context"""


class Reader:
    "Abstract class which allows EZT to detect Reader objects."


class _FileReader(Reader):
    """Reads templates from the filesystem."""

    def __init__(self, fname):
        with open(fname, 'rb') as fd:
            self.text = fd.read()
        self._dir = os.path.dirname(fname)

    def read_other(self, relative):
        return _FileReader(os.path.join(self._dir, relative))


class _TextReader(Reader):
    """'Reads' a template from provided text."""

    def __init__(self, text):
        self.text = text

    def read_other(self, relative):
        raise BaseUnavailableError()


class EZTException(Exception):
    """Parent class of all EZT exceptions."""

    def __init__(self, msg=None, line=None, column=None):
        self.msg = msg
        self.line = line
        self.column = column

    def __str__(self):
        s = self.__class__.__name__
        if self.msg:
            s += ' "%s"' % self.msg
        if self.line:
            s += ' at line %d column %d' % (self.line + 1, self.column + 1)
        return s


class ArgCountSyntaxError(EZTException):
    """A bracket directive got the wrong number of arguments."""


class UnknownReference(EZTException):
    """The template references an object not contained in the data dictionary."""


class NeedSequenceError(EZTException):
    """The object dereferenced by the template is no sequence (tuple or list)."""


class UnclosedBlocksError(EZTException):
    """This error may be simply a missing [end]."""


class UnmatchedEndError(EZTException):
    """This error may be caused by a misspelled if directive."""


class UnmatchedElseError(EZTException):
    """This error may be caused by a misspelled if directive."""


class BaseUnavailableError(EZTException):
    """Base location is unavailable, which disables includes."""


class BadFormatConstantError(EZTException):
    """Format specifiers must be string constants."""


class UnknownFormatConstantError(EZTException):
    """The format specifier is an unknown value."""
