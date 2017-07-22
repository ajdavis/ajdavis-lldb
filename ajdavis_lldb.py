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


def bson_as_json(value, debugger, verbose=False, oneline=False):
    try:
        if value.TypeIsPointerType():
            value = value.Dereference()

        codec_options = bson.CodecOptions(document_class=OrderedDict)

        target = debugger.GetSelectedTarget()
        len = value.GetChildMemberWithName('len').GetValueAsUnsigned()
        flags = value.GetChildMemberWithName('flags').GetValueAsUnsigned()

        if flags & ~ALL_FLAGS or len < 5 or len > 16 * 1024 * 1024:
            return 'uninitialized'

        if flags & FLAGS['INLINE']:
            if len > 120:
                return 'uninitialized'

            inline_t = target.FindFirstType('bson_impl_inline_t')
            inline = value.Cast(inline_t)
            data = inline.GetChildMemberWithName('data')
            raw = bson.BSON(get_inline_bytes(data))
        else:
            alloc_t = target.FindFirstType('bson_impl_alloc_t')
            alloc = value.Cast(alloc_t)
            offset = alloc.GetChildMemberWithName('offset').GetValueAsUnsigned()
            buf = alloc.GetChildMemberWithName('buf').Dereference()
            raw = bson.BSON(get_allocated_bytes(buf, offset, debugger))

        ret = ''
        if verbose:
            ret += 'len=%s\n' % len
            ret += flags_str(flags) + '\n'

        if oneline:
            indent = None
        else:
            indent = 2

        ret += json.dumps(raw.decode(codec_options), indent=indent)
        return ret
    except Exception as exc:
        return str(exc)


if not bson:
    def bson_as_json(value, internal_dict):
        return "No PyMongo, do `python -m pip install pymongo`"


def bson_as_json_options():
    usage = "usage: %prog [options]"
    description = '''Prints a libbson bson_t struct as JSON'''
    parser = optparse.OptionParser(description=description, prog='json',
                                   usage=usage)
    parser.add_option('-v', '--verbose', action='store_true',
                      help='Print length and flags of bson_t.')
    parser.add_option('-1', '--oneline', action='store_true',
                      help="Don't indent JSON")

    return parser


def bson_as_json_command(debugger, command, result, internal_dict):
    command_args = shlex.split(command)
    parser = bson_as_json_options()
    options, args = parser.parse_args(command_args)

    process = debugger.GetSelectedTarget().GetProcess()
    frame = process.GetSelectedThread().GetFrameAtIndex(0)

    for arg in args:
        value = frame.FindVariable(arg)
        result.AppendMessage(
            bson_as_json(value,
                         debugger,
                         verbose=options.verbose,
                         oneline=options.oneline))


def bson_type_summary(value, internal_dict):
    return bson_as_json(value, lldb.debugger)


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'type summary add -F ajdavis_lldb.bson_type_summary bson_t')

    debugger.HandleCommand(
        'command script add -f ajdavis_lldb.bson_as_json_command json')

    sys.stderr.write('json command installed by ajdavis_lldb\n')
