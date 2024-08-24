'''

The MIT License (MIT)

Copyright (c) 2015 Mikhail Gorodetsky

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

MY_STRUCT="""typedef struct __attribute__ ((__packed__)){
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    int8_t i8;
    int16_t i16;
    int32_t i32;
    int64_t i64;
    long long int lli;
    float flt;
    double dbl;
    char string[12];
    uint64_t array[5];
} debugInfo;"""



import re
import struct
from collections import OrderedDict
from collections import namedtuple

TYPE_REGEX=re.compile("\\s*([a-zA-Z0-9_]+)\\s+(\\w+)(?:\\[(\\d*)\\])?;")
#\s* -- all spaces on left from type name
#([a-zA-Z0-9_ ]+) -- type name
#\s+ -- spaces between type and name
#(\w+) -- variable name
#(?:\[(\d*)\\])? -- elements in array, optional

TYPES_DICT={"uint64_t":"Q","uint32_t":"I","uint16_t":"H","uint8_t":"B",
                 "int64_t":"q","int32_t":"i","int16_t":"h","int8_t":"b",
                 "char":"c","bool":"?","float":"f","double":"d",
                 "long long int":"q","unsigned long long int":"Q"};



def structInfo(cStruct, alignment="="):
    pack_format=alignment
    varlist=[];
    for line in cStruct.splitlines():
        try:
            vartype, varname, arrayLength=TYPE_REGEX.findall(line)[0]
            vartype=TYPES_DICT[vartype];
            if arrayLength:
                arrayLength=int(arrayLength);
            else:
                arrayLength=1;

            pack_format+=vartype*arrayLength
            varlist.append([varname,arrayLength])
        except IndexError:
            pass
    return varlist, pack_format


def depack_bytearray_to_dict(bindata, cStruct, alignment="="):
    result=OrderedDict()
    varlist,pack_format=structInfo(cStruct,alignment)
    unpacked=struct.unpack(pack_format,bindata);

    if pack_format[0] in '@=<>!':
        pack_format=pack_format[1:]

    ind=0;
    for varname,arrlen in varlist:
        if arrlen>1:
            result[varname]=unpacked[ind:ind+arrlen]
            ind+=arrlen
        else:
            result[varname]=unpacked[ind]
            ind+=1
    return result

def depack_bytearray_to_str(bindata, cStruct, alignment="="):
    out_str=u''
    for key,value in depack_bytearray_to_dict(bindata,cStruct, alignment).items():
        out_str+=key+':'+unicode(value)+'\n'
    return out_str

def depack_bytearray_to_namedtuple(bindata, cStruct, alignment="="):
    d=depack_bytearray_to_dict(bindata,cStruct, alignment)
    return namedtuple('CStruct',d.keys())(*d.values())

def structSize(cStruct, alignment="="):
    varlist,pack_format=structInfo(cStruct, alignment)
    return struct.calcsize(pack_format)

if __name__ == '__main__':
    UNPACKED_STRUCT=[1,256,65536,2**32,-1,-256,-65536,-(2**32),42,2.1,3.01,'t','e','s','t','S','t','r','i','n','g','\0','\0',1,2,3,4,5]
    PACKED_STRUCT='\x01\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\xff\x00\xff\x00\x00\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff*\x00\x00\x00\x00\x00\x00\x00ff\x06@\x14\xaeG\xe1z\x14\x08@testString\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00'

    # print "C struct definition:"
    # print MY_STRUCT
    # print ""

    # print "Test data:"
    # print UNPACKED_STRUCT;
    # print ""

    # varlist,pack_format=structInfo(MY_STRUCT,'<')
    # #packed_struct=struct.pack(pack_format,*MY_STRUCT_UNPACKED)
    # packed_struct=PACKED_STRUCT
    # print repr(packed_struct)

    # print "Result:"

    # print depack_bytearray_to_str(packed_struct,MY_STRUCT,'<' )

    # print "Bytes in Stuct:"+str(structSize(MY_STRUCT))

    # nt=depack_bytearray_to_namedtuple(packed_struct,MY_STRUCT,'<' )
    # print "named tuple nt:"
    # print nt
    # print "nt.string="+nt.string

