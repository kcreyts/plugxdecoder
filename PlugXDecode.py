import sys
import optparse
try:
    import dpkt
except:
    print "please install dpkt to analyze pcaps"
from struct import *
from ctypes    import *

try:
    nt = windll.ntdll
except:
    print "you must be running windows to use windows ntdll..."

def decrypt(key, src, size):
    
    key0 = key
    key1 = key
    key2 = key
    key3 = key
    dst = b''
    i = 0
    if size > 0:
        while i < size:
            key0 = (key0 + (((key0 >> 3)&0xFFFFFFFF) - 0x11111111)&0xFFFFFFFF)&0xFFFFFFFF
            key1 = (key1 + (((key1 >> 5)&0xFFFFFFFF) - 0x22222222)&0xFFFFFFFF)&0xFFFFFFFF
            key2 = (key2 + (0x44444444 - ((key2 << 9)&0xFFFFFFFF))&0xFFFFFFFF)&0xFFFFFFFF
            key3 = (key3 + (0x33333333 - ((key3 << 7)&0xFFFFFFFF))&0xFFFFFFFF)&0xFFFFFFFF
            new_key = (((key2&0xFF) + (key3&0xFF) + (key1&0xFF) + (key0&0xFF))&0xFF)
            res = unpack("<B", src[i:i+1])[0] ^ new_key
            dst += pack("<B", res)
            i = i + 1
    
    return dst


def read_file_to_decrypt(i_fname):
    
    with open(i_fname, "rb") as input:
        src = input.read()
        
        return decrypt_packed_string(src)


def decrypt_packed_string(src):

    key = unpack("<I", src[0:4])[0]
    size = 16
    print "decrypting with key:", key, hex(key)
    
    stage1 = decrypt(key, src, size)
    
    flags = unpack("<I", stage1[4:8])[0]
    print decode_cc(flags)
    
    #not entirely sure handled correctly when this flag set, works when it isn't
    if flags & 0x2000000:      #do not decrypt payload separately
        stage1 = decrypt(key, src, len(src))
    else:
        stage1 = stage1 + decrypt(key, src[16:], len(src[16:]))
    
    if flags & 0x1000000:      #do not decompress payload
        return stage1, flags
    else:
        compressed = create_string_buffer(stage1[16:])
        uncompressed = create_string_buffer(0xFFFF)
        final_size = c_ulong(0)
        comp_size = unpack("<H", stage1[8:10])[0]
        uncomp_size = unpack("<H", stage1[10:12])[0]
        
        nt.RtlDecompressBuffer(
                     2,                # COMPRESSION_FORMAT_LZNT1
                     uncompressed,     # UncompressedBuffer
                     uncomp_size,      # UncompressedBufferSize
                     compressed,       # CompressedBuffer
                     comp_size,        # CompressedBufferSize
                     byref(final_size) # FinalUncompressedSize
                     )
        
        return stage1[0:16] + uncompressed[0:final_size.value], flags


def decode_cc(flags):
    #TODO these probably need work
    GET_MACHINE_INFO_FLAG = 0x1 #returns machine name and identifier
    START_PLUGIN_MGR_FLAG = 0x3 #select and enable plugins
    INSTALL_NEW_COPY_FLAG = 0x5 #install itself again
    SEND_NEW_SETTINGS_FLAG = 0x6 #send bot new settings
    SAVE_SETTINGS_TO_FILE_FLAG = 0x7 #save current settings to file
    SEND_PLUGINS_INFO_FLAG = 0x8 #send C&C info about plugins
    #FLAG_NAME_HERE_FLAG = 0xFLAG
    if flags == GET_MACHINE_INFO_FLAG:
        return "%s (GetMachineInfo)" % (hex(flags))
    elif flags == START_PLUGIN_MGR_FLAG:
        return "%s (StartPluginManager)" % (hex(flags))
    elif flags == INSTALL_NEW_COPY_FLAG:
        return "%s (InstallNewCopy)" % (hex(flags))
    elif flags == SEND_NEW_SETTINGS_FLAG:
        return "%s (SendNewSettings)" % (hex(flags))
    elif flags == SAVE_SETTINGS_TO_FILE_FLAG:
        return "%s (SaveSettingsToFile)" % (hex(flags))
    elif flags == SEND_PLUGINS_INFO_FLAG:
        return "%s (SendPluginsInfo)" % (hex(flags))
    #elif flags == FLAG_NAME_HERE:
    #    return "%s (flag_name_here)" % (hex(flags)) 
    else:
        return hex(flags)


def pcap_read_and_extract(i_fname):
    
    pcap = dpkt.pcap.Reader(open(i_fname,"rb"))
    output_tcpdata= []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        #we only care about IP packets for now
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        #example implements TCP data reading only
        if ip.p != 6:
            continue
        tcp = ip.data
        
        try:
            #we only care about SYNs
            if (tcp.flags & 0x18):
                data = tcp.data
                output_tcpdata.append([
                                       decrypt_packed_string(data),
                                       ip.src,
                                       tcp.sport,
                                       ip.dst,
                                       tcp.dport])
            else:
                continue
        except:
            continue
    for each in output_tcpdata:
        [(extracted, flags),
         s_ip,
         s_port,
         d_ip,
         d_port] = each
        print "\nsource: %s:%s, destination: %s:%s" % (
                           ".".join(map(lambda n: str(unpack("<I", s_ip)[0]>>n & 0xFF), [24,16,8,0])),
                           s_port,
                           ".".join(map(lambda n: str(unpack("<I", d_ip)[0]>>n & 0xFF), [24,16,8,0])),
                           d_port)
        output_results(extracted, flags)


def decrypt_data_to_new_file(i_fname = None, o_fname = None):

    extracted, flags = read_file_to_decrypt(i_fname)
    output_results(extracted, flags, o_fname)


def output_results(extracted, flags, o_fname = None):
    payload = extracted[16:]
    ##not sure if this is handled right when this flag is set
    if flags & 0x2000000:
        payload = extracted
        str1 = "flags: %s\npayload:%s" % (decode_cc(flags),
                                          repr(payload))
    if flags & 0x1000000:
        str1 = "flags: %s\npayload:%s" % (decode_cc(flags),
                                          repr(payload))
    else:
        comp_size = unpack("<H", extracted[8:10])[0]
        uncomp_size = unpack("<H", extracted[10:12])[0]
        str1 = "flags: %s\ncompressed size: %d\nuncompressed size: %d\npayload:%s" % (
                                                                                      decode_cc(flags),
                                                                                      comp_size,
                                                                                      uncomp_size,
                                                                                      repr(payload))
    
    print str1
    
    if o_fname != None:
        with open(o_fname, "ab") as output:
            output.write(extracted)

parser = optparse.OptionParser()
parser.add_option(
    '-f',
    '--file',
    metavar = 'FILE',
    dest = 'in_file',
    help = 'read from a data file (extracted tcp data stream, or other artifact such as file stored on disk)')
parser.add_option(
    '-p',
    '--pcap',
    metavar = 'FILE',
    dest = 'pcap_file',
    help = 'read from a pcap file')
parser.add_option(
    '-o',
    '--output-file',
    default = None,
    metavar = 'FILE',
    dest = 'out_file',
    help = 'write out to a file (usually most useful for decrypting artifacts or extracted tcp data streams) otherwise, writes to stdout')

(opts, args) = parser.parse_args()
if opts.pcap_file and opts.in_file:
    parser.error("options -p and -f are mutually exclusive")

if opts.pcap_file:
    pcap_read_and_extract(opts.pcap_file)
elif opts.in_file:
    decrypt_data_to_new_file(i_fname = opts.in_file, o_fname = opts.out_file)
else:
    parser.error("you must specify a file with -p or -f")
