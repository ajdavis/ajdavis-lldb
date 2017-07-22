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
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetFrameAtIndex(0)
    for arg in args:
        value = frame.FindVariable(arg)
        result.AppendMessage(bson_as_json(value, debugger))


INLINE = 1
_UNPACK_INT = struct.Struct("<i").unpack


def check(error):
    if not error.success:
        raise Exception(str(error))


def inline_as_bytes(data):
    error = lldb.SBError()
    len = data.GetData().GetSignedInt32(error, 0)
    check(error)
    return b''.join(chr(b) for b in data.GetData().uint8[:len])


def alloc_as_bytes(buf, offset, debugger):
    # I don't know why this must be so different from inline_as_bytes.
    error = lldb.SBError()
    check(error)
    buf_addr = buf.Dereference().GetAddress().offset + offset
    process = debugger.GetSelectedTarget().process
    len_bytes = process.ReadMemory(buf_addr, 4, error)
    check(error)
    len = _UNPACK_INT(len_bytes)[0]
    return process.ReadMemory(buf_addr, len, error)


def bson_as_json(value, debugger):
    try:
        codec_options = bson.CodecOptions(document_class=OrderedDict)

        target = debugger.GetSelectedTarget()
        flags = value.GetChildMemberWithName('flags').GetValueAsUnsigned()
        if flags & INLINE:
            inline_t = target.FindFirstType('bson_impl_inline_t')
            inline = value.Cast(inline_t)
            data = inline.GetChildMemberWithName('data')
            raw = bson.BSON(inline_as_bytes(data))
        else:
            alloc_t = target.FindFirstType('bson_impl_alloc_t')
            alloc = value.Cast(alloc_t)
            offset = alloc.GetChildMemberWithName('offset').GetValueAsUnsigned()
            buf = alloc.GetChildMemberWithName('buf').Dereference()
            raw = bson.BSON(alloc_as_bytes(buf, offset, debugger))

        return json.dumps(raw.decode(codec_options))
    except Exception as exc:
        return str(exc)


def bson_summary(value, internal_dict):
    return bson_as_json(value, lldb.debugger)


if not bson:
    def bson_as_json(value, internal_dict):
        return "No PyMongo, do `python -m pip install pymongo`"


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'type summary add -F ajdavis_lldb.bson_summary bson_t')

    debugger.HandleCommand(
        'command script add -f ajdavis_lldb.bson_as_json_command json')

    sys.stderr.write('json command installed by ajdavis_lldb\n')
