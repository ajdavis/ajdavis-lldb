import json
import logging
import struct
from collections import OrderedDict

logging.basicConfig(filename="/tmp/lldb.log", level=logging.DEBUG)
logging.info("hello world")

try:
    import lldb
    logging.info("imported lldb")
except ImportError:
    logging.exception("importing")



try:
    import bson
    logging.info("imported bson")
except ImportError:
    logging.exception("importing")
    bson = None


def bsonCommand(debugger, command, result, internal_dict):
    result.AppendMessage("foo")
    logging.info("bson")


INLINE = 1
_UNPACK_INT = struct.Struct("<i").unpack


def inline_as_bytes(data, offset):
    error = lldb.SBError()
    len = data.GetData().GetSignedInt32(error, 0)
    return b''.join(chr(b) for b in data.GetData().uint8[offset:len + offset])


def alloc_as_bytes(buf, offset):
    # I don't know why this must be so different from inline_as_bytes.
    error = lldb.SBError()
    buf_addr = buf.Dereference().GetAddress().offset
    process = lldb.debugger.GetSelectedTarget().process
    len_bytes = process.ReadMemory(buf_addr, 4, error)
    len = _UNPACK_INT(len_bytes)[0]
    return process.ReadMemory(buf_addr, len, error)


def bson_summary(value, internal_dict):
    try:
        codec_options = bson.CodecOptions(document_class=OrderedDict)

        target = lldb.debugger.GetSelectedTarget()
        flags = value.GetChildMemberWithName('flags').GetValueAsUnsigned()
        if flags & INLINE:
            inline_t = target.FindFirstType('bson_impl_inline_t')
            inline = value.Cast(inline_t)
            offset = 0
            data = inline.GetChildMemberWithName('data')
            raw = bson.BSON(inline_as_bytes(data, offset))
        else:
            alloc_t = target.FindFirstType('bson_impl_alloc_t')
            alloc = value.Cast(alloc_t)
            offset = alloc.GetChildMemberWithName('offset').GetValueAsUnsigned()
            buf = alloc.GetChildMemberWithName('buf').Dereference()
            raw = bson.BSON(alloc_as_bytes(buf, offset))

        return json.dumps(raw.decode(codec_options))
    except Exception as exc:
        return str(exc)

if not bson:
    def bson_summary(value, internal_dict):
        return "No PyMongo, do `python -m pip install pymongo`"

