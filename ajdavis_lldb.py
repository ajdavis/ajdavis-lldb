import json
import lldb
import optparse
import shlex
import struct
import sys
from collections import OrderedDict

try:
    import bson
except ImportError:
    bson = None


FLAGS = OrderedDict([
    ('INLINE', 1 << 0),
    ('STATIC', 1 << 1),
    ('RDONLY', 1 << 2),
    ('CHILD', 1 << 3),
    ('IN_CHILD', 1 << 4),
    ('NO_FREE', 1 << 5),
])


ALL_FLAGS = (1 << 6) - 1


def flags_str(flags):
    if flags == 0:
        return 'flags=0'

    return 'flags=' + '|'.join(
        name for name, value in FLAGS.items() if flags & value)


_UNPACK_INT = struct.Struct("<i").unpack


if sys.version_info[0] == 3:
    string_types = (bytes, str)
else:
    string_types = (str, unicode)


class Key(str):
    def __repr__(self):
        return "Key(%s)" % super(Key, self).__repr__()

    def __hash__(self):
        return id(self)


class DuplicateKeyDict(OrderedDict):
    """Allows duplicate keys in dicts."""

    def __setitem__(self, key, value):
        if isinstance(key, string_types):
            key = Key(key)

        super(DuplicateKeyDict, self).__setitem__(key, value)


def check(error):
    if not error.success:
        raise Exception(str(error))


def get_inline_bytes(data):
    error = lldb.SBError()
    len = data.GetData().GetSignedInt32(error, 0)
    check(error)
    return b''.join(chr(b) for b in data.GetData().uint8[:len])


def get_allocated_bytes(buf, offset, debugger):
    # I don't know why this must be so different from get_inline_bytes.
    error = lldb.SBError()
    check(error)
    buf_addr = buf.Dereference().GetAddress().offset + offset
    process = debugger.GetSelectedTarget().process
    len_bytes = process.ReadMemory(buf_addr, 4, error)
    check(error)
    len = _UNPACK_INT(len_bytes)[0]
    return process.ReadMemory(buf_addr, len, error)


def bson_as_json(value, debugger, verbose=False, oneline=False, raw=False):
    try:
        target = debugger.GetSelectedTarget()
        inline_t = target.FindFirstType('bson_impl_inline_t')
        alloc_t = target.FindFirstType('bson_impl_alloc_t')

        if not inline_t.GetDisplayTypeName():
            return """error: libbson not compiled with debug symbols
Download latest mongo-c-driver.tar.gz from mongoc.org and do:
./configure --enable-debug
make
sudo make install
"""

        if value.TypeIsPointerType():
            value = value.Dereference()

        len = value.GetChildMemberWithName('len').GetValueAsUnsigned()
        flags = value.GetChildMemberWithName('flags').GetValueAsUnsigned()

        if flags & ~ALL_FLAGS or len < 5 or len > 16 * 1024 * 1024:
            return 'uninitialized'

        if flags & FLAGS['INLINE']:
            if len > 120:
                return 'uninitialized'

            inline = value.Cast(inline_t)
            data = inline.GetChildMemberWithName('data')
            raw_bson = get_inline_bytes(data)
        else:
            alloc = value.Cast(alloc_t)
            offset = alloc.GetChildMemberWithName('offset').GetValueAsUnsigned()
            buf = alloc.GetChildMemberWithName('buf').Dereference()
            raw_bson = get_allocated_bytes(buf, offset, debugger)

        if raw:
            return repr(raw_bson)

        ret = ''
        if verbose:
            ret += 'len=%s\n' % len
            ret += flags_str(flags) + '\n'

        if oneline:
            indent = None
        else:
            indent = 2

        codec_options = bson.CodecOptions(document_class=DuplicateKeyDict)
        ret += json.dumps(bson.BSON(raw_bson).decode(codec_options),
                          indent=indent)
        return ret
    except Exception as exc:
        return str(exc)


if not bson:
    def bson_as_json(value, internal_dict):
        return "No PyMongo, do `python -m pip install pymongo`"


class OptionParserNoExit(optparse.OptionParser):
    def exit(self, status=0, msg=None):
        raise Exception(msg)


def bson_as_json_options():
    usage = "usage: %prog [options] VARIABLE"
    description = '''Prints a libbson bson_t struct as JSON'''
    parser = OptionParserNoExit(description=description, prog='bson',
                                usage=usage,
                                add_help_option=False)
    parser.add_option('-v', '--verbose', action='store_true',
                      help='Print length and flags of bson_t.')
    parser.add_option('-1', '--one-line', action='store_true',
                      dest='oneline', help="Don't indent JSON")
    parser.add_option('-r', '--raw', action='store_true',
                      help='Print byte string, not JSON')
    parser.add_option('-h', '--help', action='store_true',
                      help='Print help and exit')

    return parser


def bson_as_json_command(debugger, command, result, internal_dict):
    command_args = shlex.split(command)
    parser = bson_as_json_options()

    try:
        options, args = parser.parse_args(command_args)
    except Exception as exc:
        result.AppendMessage(str(exc))
        return

    if options.help or not args:
        result.AppendMessage(parser.format_help())
        return

    process = debugger.GetSelectedTarget().GetProcess()
    frame = process.GetSelectedThread().GetFrameAtIndex(0)

    for arg in args:
        value = frame.FindVariable(arg)
        result.AppendMessage(
            bson_as_json(value,
                         debugger,
                         verbose=options.verbose,
                         oneline=options.oneline,
                         raw=options.raw))


def bson_type_summary(value, internal_dict):
    return bson_as_json(value, lldb.debugger)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'type summary add -F ajdavis_lldb.bson_type_summary bson_t')

    debugger.HandleCommand(
        'command script add --help \"%s\"'
        ' -f ajdavis_lldb.bson_as_json_command bson' %
        bson_as_json_options().format_help().replace('"', "'"))

    sys.stderr.write('"bson" command installed by ajdavis_lldb\n')
