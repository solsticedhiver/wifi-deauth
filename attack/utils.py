import os
import struct

from scapy.all import Dot11Elt

from exceptions import AttackException
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
                                lfilter=lambda pkt: pkt.haslayer(Dot11Elt) and\
                                                    pkt.addr3 == self.bssid)
        dot11elt = None

        # Find a packet containing channel information.
        for packet in packets:
            if self._packet_has_channel_info(packet.getlayer(Dot11Elt)):
                dot11elt = packet.getlayer(Dot11Elt)
                break
            
        sniffer.stop()

        if dot11elt is None:
            raise AttackException('Failed to find AP channel!')

        return self._extract_channel_from(dot11elt)

    def _packet_has_channel_info(self, dot11elt):
        found = False
        while dot11elt and not found:
            if dot11elt.ID == 3:
                found = True
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        return found

    def _extract_channel_from(self, dot11elt):
        found = False
        while not found:
            if dot11elt.ID == 3:
                channel = struct.unpack('B', dot11elt.info)[0]
                found = True
            dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        return channel
    
    
class WiFiInterface(object):
    
    def __init__(self, interface):
        if isinstance(interface, self.__class__):
            self.interface_name = interface.get_name()
        else:
            self.interface_name = interface
        
    def get_name(self):
        return self.interface_name
        
    def set_channel(self, channel):
        command = 'iw %s set channel %d > /dev/null 2>&1'\
                   % (self.interface_name, channel)
        exit_code = os.system(command)
        if exit_code != 0:
            msg = 'Failed to set channel %d on interface %s!' %\
                   (channel, self.interface_name)
            raise AttackException(msg)