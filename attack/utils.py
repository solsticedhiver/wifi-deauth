import os
import struct

from scapy.all import RadioTap

from sniffer import WiFiSniffer


class ChannelFinder(object):
    
    '''Find channel used by an access point whose MAC address is given.'''
    
    DEFAULT_TIMEOUT = 60
    
    TIMESTAMP_FLAG = 0x1
    FLAGS_FLAG = 0x2
    RATE_FLAG = 0x3
    CHANNEL_FLAG = 0x8
    
    TIMESTAMP_BYTES = 8
    FLAGS_BYTES = 1
    RATE_BYTES = 1
    
    CHANNEL_1_FREQ = 2412
    
    def __init__(self, interface, bssid):
        self.interface = interface
        self.bssid = bssid
        
    def find(self):
        sniffer = WiFiSniffer(self.interface)
        packets = sniffer.sniff(timeout=self.DEFAULT_TIMEOUT,
                                lfilter=lambda pkt: pkt.haslayer(RadioTap) and\
                                                    pkt.addr3 == self.bssid)
        # Find a packet containing channel information.
        for packet in packets:
            if self._packet_has_channel_info(packet[RadioTap]):
                sniffer.stop()
                
        # Extract channel from radiotap header.
        return self._extract_channel_from(packet[RadioTap])
    
    def _packet_has_channel_info(self, radiotap_header):
        return radiotap_header.present & self.CHANNEL_FLAG != 0
    
    def _extract_channel_from(self, radiotap_header):
        offset = 0
        if radiotap_header.present & self.TIMESTAMP_FLAG != 0:
            offset += self.TIMESTAMP_BYTES
        if radiotap_header.present & self.FLAGS_FLAG != 0:
            offset += self.FLAGS_BYTES
        if radiotap_header.present & self.RATE_FLAG != 0:
            offset += self.RATE_BYTES
        
        # Decode frequency and then map it to the channel number.    
        freq_bytes = radiotap_header.notdecoded[offset:offset+2]    
        freq = struct.unpack('h', freq_bytes)[0]
        
        if freq == 2484:
            channel = 14
        else:
            channel = 1 + (freq - self.CHANNEL_1_FREQ) / 5
            
        return channel
    
    
class WiFiInterface(object):
    
    def __init__(self, interface_name):
        self.interface_name = interface_name
        
    def get_name(self):
        return self.interface_name
        
    def set_channel(self, channel):
        command = 'iw %s set channel %d > /dev/null 2>&1'\
                   % (self.interface_name, channel)
        exit_code = os.system(command)
        if exit_code != 0:
            raise Exception('Failed to set channel %d on interface %s!' %\
                            (channel, self.interface_name))