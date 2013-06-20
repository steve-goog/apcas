#!/usr/bin/python
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Perform analysis on the pcap data to look for simlarities."""

import argparse
import os
import pdb
import socket
import struct
import sys
import traceback

import dpkt
import pcap
import scapy

AP_FLAGS = argparse.ArgumentParser(description='File Analysis')
AP_FLAGS.add_argument('--output_pcap', help='Output unknown pcap',
                      default='')
AP_FLAGS.add_argument('--output_stats_dir', help='Output stats to dir',
                      default='/sdb2/stats')
AP_FLAGS.add_argument('--detail', help='Export detail',
                      default=False, action='store_true')
AP_FLAGS.add_argument('--overwrite', help='Overwrite stats files',
                      default=False, action='store_true')
AP_FLAGS.add_argument('input_files', help='Input files to parse', nargs='+')

FLAGS = None


class Stats(object):
  def __init__(self, name):
    self.name = name
    self.stats = {}
    self.totals = [0, 0]

  def add(self, val, pktlen):
    if val not in self.stats:
      self.stats[val] = [0, 0]
    self.stats[val][0] += 1  # packets
    self.stats[val][1] += pktlen  # packet length
    self.totals[0] += 1
    self.totals[1] += pktlen

  def PrintTotals(self):
    print '%5d %6dkB' % (self.totals[0], self.totals[1]/1000)

  def PrintStats(self):
    val_list = list(self.stats)
    # sort on # of packets
    val_list.sort(key=lambda x: self.stats[x][0], reverse=True)
    print '%s %s %s' % ('=' * 10, self.name, '=' * 10)
    for i in xrange(min(10, len(val_list))):
      print '%5d %6dkB %s' % (
          self.stats[val_list[i]][0], self.stats[val_list[i]][1]/1000,
          val_list[i])


class StatsGroup(object):
  def __init__(self, *args):
    self.groups = args
    for element in args:
      self.__dict__[element] = Stats(element)


class Classification(object):
  def __init__(self, pkt):
    self.pkt = pkt
    self.name = self.Classify(pkt)

  def PktType(self, pkt, protocol, general_class,
              specific_class=''):
    return '%s:%s:%s:%s|%d' % (
        protocol, general_class, specific_class, pkt['dst_ip'],
        pkt.get('dport', 0))

  def Classify(self, pkt):
    # Syntax:
    # protocol:general class name:specific class name:dstip|port
    # ex:
    #  UDP:flood:0xffff:1.1.1.1|80
    if pkt['proto'] == 17 and len(pkt.raw) > 70:
      if (pkt.raw[52:56] == pkt.raw[56:60] and
          pkt.raw[52:54] == pkt.raw[54:56]):
        return self.PktType(
            pkt, 'UDP', 'flood', specific_class='0x%02x%02x' %
            (ord(pkt.raw[52]), ord(pkt.raw[53])))
      if (struct.unpack('H', pkt.raw[50:52])[0]+0x101 ==
          struct.unpack('H', pkt.raw[66:68])[0] and
          struct.unpack('H', pkt.raw[52:54])[0]+0x101 ==
          struct.unpack('H', pkt.raw[68:70])[0]):
        return self.PktType(
            pkt, 'UDP', 'flood', specific_class='0x101-offset')
    if (pkt['proto'] == 17 and pkt.get('dport', None) == 37 and
        pkt.pktlen == 60):
      # <Ether  dst=00:15:17:ed:a2:e0 src=00:1f:12:8e:00:00 type=0x800 |
      #  <IP  version=4L ihl=5L tos=0x0 len=28 id=18019 flags=DF frag=0L
      #   ttl=44 proto=udp chksum=0xd37c src=86.130.220.109 dst=1.1.1.1
      #   options=[] |<UDP  sport=16046 dport=time len=8 chksum=0x8c19 |
      #  <Padding  load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
      #   \x00\x00\x00\x00\x00\x00\x00' |>>>>
      # randomly checking some of the source IPs, it's all
      # host109-156-40-233.range109-156.btcentralplus.com. domains.
      if pkt['src_ip'][:3] in ('86.', '81.', '109', '217'):
        return self.PktType(pkt, 'UDP', 'flood',
                            specific_class='btcentral-time')
    if pkt['proto'] == 17 and pkt.get('dport') == 53:
      if pkt['sport'] == 53:
        return self.PktType(pkt, 'UDP', 'DNS', specific_class='DNSAnswer')
      return self.PktType(pkt, 'UDP', 'DNS', specific_class='DNSReq')
    if pkt['proto'] == 17 and pkt.get('dport', 0) == 5060:
      if 'REGISTER' in pkt.raw:
        return self.PktType(pkt, 'UDP', 'SIP', specific_class='REGISTER')
      if 'OPTIONS' in pkt.raw:
        return self.PktType(pkt, 'UDP', 'SIP', specific_class='OPTIONS')
      return self.PktType(pkt, 'UDP', 'SIP')
    if pkt['proto'] == 17 and pkt.get('dport') == 2727:
      if 'RSIP' in pkt.raw:
        return self.PktType(pkt, 'UDP', 'MGCP', specific_class='RestartIP')
      return self.PktType(pkt, 'UDP', 'MGCP')
    if pkt['proto'] == 6:
      if pkt.get('dport', 0) == 8888 and pkt['dst_ip'] == '1.2.3.4':
        return self.PktType(pkt, 'TCP', 'HotelNet')
    # Below? It's unclassfied, essentially...
    # elements matching a single ip:port are grouped together, so only things
    # that are more unique than that (eg, packet contents, sources, etc)
    # need to be called out above.
    if pkt['proto'] == 6:
      if pkt.get('flags', 0)&0x2 > 0:  # SYN
        return self.PktType(pkt, 'TCP', 'SYN')
      if pkt.get('flags', 0) & 0x5 > 0:  # FIN or RST
        return self.PktType(pkt, 'TCP', 'Close')
      return self.PktType(pkt, 'TCP', 'ACK')
    if pkt['proto'] == 17:
      return self.PktType(pkt, 'UDP', '')
    if pkt['proto'] == 6:  # In case anything slipped through above
      return self.PktType(pkt, 'TCP', '')
    if pkt['proto'] == 1:
      pkt.fields['dport'] = pkt.get('code', 0)
      return self.PktType(pkt, 'ICMP', 'type-%d' % pkt.get('type', 0))
    if pkt['proto'] == 47:
      return self.PktType(pkt, 'GRE', '')
    return self.PktType(pkt, 'MiscProto', 'Proto-%d' % pkt['proto'])


class Packet(object):
  def __init__(self, pkt, pktlen):
    self.fields = self.Decode(pkt)
    self.pktlen = pktlen
    self.raw = pkt

  def get(self, s, default=None):
    if s in self.fields:
      return self.fields[s]
    return default

  def __getitem__(self, s):
    return self.fields[s]

  def Decode(self, s):
    d = {}
    ofs = 14
    d['header_len'] = ord(s[ofs+0]) & 0x0f
    d['frag_offset'] = socket.ntohs(
        struct.unpack('H', s[ofs+6:ofs+8])[0] & 0x1f)
    d['proto'] = ord(s[ofs+9])
    d['src_ip'] = pcap.ntoa(struct.unpack('i', s[ofs+12:ofs+16])[0])
    d['dst_ip'] = pcap.ntoa(struct.unpack('i', s[ofs+16:ofs+20])[0])
    if d['frag_offset'] == 0:
      offset = d['header_len']<<2
      if d['proto'] in (6, 17) and len(s) >= offset+4:
        d['sport'] = socket.ntohs(
            struct.unpack('H', s[ofs+offset:ofs+offset+2])[0])
        d['dport'] = socket.ntohs(
            struct.unpack('H', s[ofs+offset+2:ofs+offset+4])[0])
        if len(s) >= offset+14 and d['proto'] == 6:
          d['flags'] = ord(s[ofs+offset+13])
      elif d['proto'] == 1 and len(s) >= offset+4:
        d['type'] = ord(s[ofs+offset])
        d['code'] = ord(s[ofs+offset+1])
    return d


class PacketProcessing(object):

  def __init__(self):
    # classified objects
    self.stats = {}
    if FLAGS.output_pcap:
      print 'Writing unknown packets to %s' % FLAGS.output_pcap
      self.pcap_writer = dpkt.pcap.Writer(open(FLAGS.output_pcap, 'w+'))
    else:
      self.pcap_writer = None

  def ProcessPacket(self, pktlen, raw_pkt, timestamp):
    pkt = Packet(raw_pkt, pktlen)
    cls = Classification(pkt)
    if cls.name not in self.stats:
      self.stats[cls.name] = StatsGroup(
          'sport', 'dport', 'dst_ip', 'src_ip', 'proto_dport', 'proto')
    if not cls.name and self.pcap_writer:
      self.pcap_writer.writepkt(raw_pkt, ts=timestamp)
    stats = self.stats[cls.name]
    stats.proto.add(pkt['proto'], pktlen)
    stats.dst_ip.add(pkt['dst_ip'], pktlen)
    stats.src_ip.add(pkt['src_ip'], pktlen)
    if 'dport' in pkt.fields:
      stats.dport.add(pkt['dport'], pktlen)
      stats.proto_dport.add((pkt['proto'], pkt['dport']), pktlen)
    if 'sport' in pkt.fields:
      stats.sport.add(pkt['sport'], pktlen)

  def ClearStats(self):
    self.stats = {}

  def GetStatsFname(self, orig_fname):
    prefix = os.path.basename(orig_fname)
    fname_split = prefix.split('-')
    if len(fname_split) != 3:
      print prefix, fname_split
      print 'Unable to understand filename %s' % orig_fname
      return None
    unused_fname_group, fname_date, unused_fname_time = fname_split
    stats_dir = os.path.join(FLAGS.output_stats_dir, fname_date)
    if not os.path.exists(stats_dir):
      os.mkdir(stats_dir)
    stats_fname = os.path.join(stats_dir, prefix + '.stats')
    return stats_fname

  def SaveStats(self, orig_fname, stats_fname):
    if not stats_fname:
      return
    prefix = os.path.basename(orig_fname)
    fname_split = prefix.split('-')
    unused_fname_group, fname_date, unused_fname_time = fname_split
    stats_fh = open(stats_fname, 'w+')
    if 'sample' in orig_fname:
      if prefix.startswith('1'):
        sample_size = 32.0
      else:
        sample_size = 128.0   # large packets
    else:
      sample_size = 1.0
    skip_file = '/sdb2/stats.pcap/%s/%s' % (fname_date, prefix)
    if os.path.exists(skip_file):
      result = open(skip_file).read()
      if result:
        rate = result.strip().split(' ')
        sample_size *= (float(rate[2])+float(rate[1]))/float(rate[1])
    print 'Writing stats to %s (sample rate: %.2f)' % (stats_fname, sample_size)
    other = {}
    for cls_name in self.stats:
      if cls_name is None:
        print_name = 'Unclassified'
      else:
        print_name = cls_name
      pkts, bytes = (self.stats[cls_name].proto.totals[0],
                     self.stats[cls_name].proto.totals[1])
      if pkts <= 2 and ':' in print_name:
        # go ahead and combine things that saw <=2 packets during this interval
        other_name = ':'.join(print_name.split(':')[:-1])
        while other_name and other_name.endswith(':'):
          other_name = other_name[:-1]
        if other_name not in other:
          other[other_name] = [0, 0]
        other[other_name][0] += pkts
        other[other_name][1] += bytes
        continue
      pkts *= sample_size
      bytes *= sample_size
      print >>stats_fh, '%s\t%d\t%d' % (print_name, pkts, bytes)
    for other_name in other:
      pkts, bytes = other[other_name]
      pkts *= sample_size
      bytes *= sample_size
      print >>stats_fh, '%s\t%d\t%d' % (other_name, pkts, bytes)

    stats_fh.close()

  def PrintStats(self):
    for cls_name in self.stats:
      print
      print '*' * 30, cls_name, '*' * 30
      if cls_name is None:
        for statgroup in self.stats[cls_name].groups:
          self.stats[cls_name].__getattribute__(statgroup).PrintStats()
      else:
        self.stats[cls_name].proto.PrintTotals()


def main(unused_argv):
  global FLAGS
  FLAGS = AP_FLAGS.parse_args()
  pkt = PacketProcessing()
  scapy.all.UDP.payload_guess = []
  scapy.all.TCP.payload_guess = []
  for fname in FLAGS.input_files:
    print 'reading %s' % fname
    stats_fname = pkt.GetStatsFname(fname)
    if not stats_fname:
      continue
    if os.path.exists(stats_fname) and not FLAGS.overwrite:
      continue
    p = pcap.pcapObject()
    p.open_dead(1, 1600)
    try:
      p.open_offline(fname)
    except Exception, e:
      print e
      continue
    p.loop(-1, pkt.ProcessPacket)
    if FLAGS.detail:
      pkt.PrintStats()
    pkt.SaveStats(fname, stats_fname)
    pkt.ClearStats()
  if pkt.pcap_writer:
    pkt.pcap_writer.close()


def ExceptionInfo(ex_type, value, tb):
  if hasattr(sys, 'ps1') or not sys.stderr.isatty():
    sys.__excepthook__(ex_type, value, tb)
  else:
    traceback.print_exception(ex_type, value, tb)
    print
    pdb.pm()


sys.excepthook = ExceptionInfo
try:
  main(sys.argv)
except KeyboardInterrupt:
  pass
