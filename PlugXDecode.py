import sys
import optparse
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s')

from struct import *
from ctypes import *

try:
    import dpkt
except:
    logging.error("please install dpkt to analyze pcaps")
    sys.exit()

try:
    nt = windll.ntdll
except:
    logging.error("you must be running windows to use windows ntdll...")
    sys.exit()



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
    logging.info("decrypting with key %s:%s" % (key, hex(key)))
    
    stage1 = decrypt(key, src, size)
    
    flags = unpack("<I", stage1[4:8])[0]
    print decode_cc(flags) #XXX - use logging? 
    
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
        comp_size = unpack("!H", stage1[8:10])[0]
        if comp_size != (len(stage1)-16):
            return stage1, flags
        uncomp_size = unpack("!H", stage1[10:12])[0]
        
        if nt.RtlDecompressBuffer(
                     2,                # COMPRESSION_FORMAT_LZNT1
                     uncompressed,     # UncompressedBuffer
                     uncomp_size,      # UncompressedBufferSize
                     compressed,       # CompressedBuffer
                     comp_size,        # CompressedBufferSize
                     byref(final_size) # FinalUncompressedSize
                     ):
            return stage1[0:16] + uncompressed[0:final_size.value], flags
        else:
            logging.warn("This payload could not be decompressed")
            return stage1,flags


def decode_cc(flags):
    #TODO these probably need work
    the_flags = {
        0x1    : "GET_MACHINE_INFO_FLAG",           #returns machine name and identifier
        0x3    : "START_PLUGIN_MGR_FLAG",           #select and enable plugins
        0x5    : "INSTALL_NEW_COPY_FLAG",           #install itself again
        0x6    : "SEND_NEW_SETTINGS_FLAG",          #send bot new settings
        0x7    : "SAVE_SETTINGS_TO_FILE_FLAG",      #save current settings to file
        0x8    : "SEND_PLUGINS_INFO_FLAG",          #send C&C info about plugins
        0x2000 : "LOCK_WORKSTATION_FLAG",
        0x2001 : "LOGOFF_FLAG",
        0x2002 : "SYSTEM_REBOOT_FLAG",
        0x2003 : "SYSTEM_SHUTDOWN_FLAG",
        0x2005 : "MESSAGE_BOX_FLAG",
        0x3000 : "GET_ATTACHED_DISKS_FLAG",
        0x3001 : "SEARCH_DIR_FOR_FILES_FLAG",
        0x3002 : "SEARCH_DIR_RECURSING_FLAG",
        0x3004 : "READ_FILE_FLAG",
        0x3007 : "WRITE_FILE_FLAG",
        0x300A : "CREATE_DIRECTORY_FLAG",
        0x300C : "CREATE_DESKTOP_EXEC_FILE_FLAG",
        0x300D : "DO_FILE_OPERATION_FLAG",
        0x300E : "GET_ENV_STRINGS_FLAG",
        0x4000 : "SCREEN_START_CAP_THREAD_FLAG",
        0x4100 : "SCREEN_CAPTURE_FLAG",
        0x4101 : "SCREEN_CAPTURE_FRAME_FLAG",
        0x5000 : "ENUM_RUNNING_PROCS_FLAG",
        0x5001 : "ENUM_RUNNING_PROC_MODULES_FLAG",
        0x5002 : "KILL_PROCESS_FLAG",
        0x6000 : "ENUM_SERVICES_FLAG",
        0x7002 : "START_SHELL_FLAG",
        0x7003 : "SHELL_INTERACT_FLAG",
        0x7100 : "START_TELNET_FLAG",
        0x7104 : "TELNET_INTERACT_FLAG",
        0x9000 : "REG_ENUM_KEY_FLAG",
        0x9001 : "REG_OPEN_KEY_FLAG",
        0x9002 : "REG_DEL_KEY_FLAG",
        0x9003 : "REG_CREATE_KEY_FLAG",
        0x9004 : "REG_ENUM_KEY_VALUE_FLAG",
        0x9005 : "REG_CREATE_KEY_WITH_VALUE_FLAG",
        0x9006 : "REG_DEL_VALUE_FLAG",
        0x9007 : "REG_GET_OR_CREATE_VALUE_FLAG",
        0xA000 : "NETHOOD_FLAG",
        0xB000 : "UNKNOWN_FLAG",
        0xC000 : "SQL_FLAG",
        0xD000 : "TCPSTATE_FLAG",
        0xD001 : "UDPSTATE_FLAG",
        0xD002 : "ADD_TCPSTATE_FLAG",
        0xE000 : "KEYLOGGER_FLAG",
    }

    #FLAG_NAME_HERE_FLAG = 0xFLAG
    if flags in the_flags.keys():
        return "%s %s" % (hex(flags), the_flags[flags])    
    #elif flags == FLAG_NAME_HERE:
    #    return "%s (flag_name_here)" % (hex(flags)) 
    else:
        return "%s %s" % (hex(flags), "UNKNOWN_FLAG")

def pcap_read_and_extract(i_fname):
    pcap = dpkt.pcap.Reader(open(i_fname,"rb"))
    output_data = []
    header_stripper = []
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        #we only care about IP packets for now
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        #example implements TCP data reading only
        if ip.p == 6:

            tcp = ip.data
            
            try:
                #we only care about SYNs
                if (tcp.flags & 0x18):
                    data = tcp.data
                    output_data.append([
                                           decrypt_packed_string(data),
                                           ip.src,
                                           tcp.sport,
                                           ip.dst,
                                           tcp.dport])
                else:
                    continue
            except:
                continue
#        elif ip.p = 17:
#            udp = ip.data
#            data = udp.data
#            cc_op = data[0:2]
#            uk1 = data[2:4]
#            uk2 = data[4:6]
#            uk3 = data[6:8]
#            uk4 = data[8:12]
#            try: 
#                key = data[12:14]
#                plugin = data[14:16]
#                print bin(key)
#                print bin(plugin)
#            except:
#                print data[12:14]
#                print data[13]
#                print len(data)-13 
#
#            output_data.append([
#                            decrypt_packed_string(data),
#                            ip.src,
#                            udp.sport,
#                            ip.dst,
#                            udp.dport])
#
        else:
            continue
    for each in output_data:
        [(extracted, flags),
         s_ip,
         s_port,
         d_ip,
         d_port] = each
        ##If the addresses you see are wrong, this is why.
        print "\nsource: %s:%s, destination: %s:%s" % (
                           ".".join(map(lambda n: str(unpack("<I", s_ip)[0]>>n & 0xFF), [0,8,16,24])),
                           s_port,
                           ".".join(map(lambda n: str(unpack("<I", d_ip)[0]>>n & 0xFF), [0,8,16,24])),
                           d_port)
        output_results(extracted, flags)

def decrypt_data_to_new_file(i_fname = None, o_fname = None):
    extracted, flags = read_file_to_decrypt(i_fname)
    output_results(extracted, flags, o_fname)

def output_results(extracted, flags, o_fname = None):
    payload = extracted[16:]
    ##not sure if this is handled right when this flag is set
    #XXX: Use logging factory? 
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

if __name__ == '__main__':
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
