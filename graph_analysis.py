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

"""Analyze and graph the sniffer data."""

import argparse
import collections
import datetime
import hashlib
import os
import re
import subprocess
import sys
import time

import blist

AP_FLAGS = argparse.ArgumentParser(description='Graph Analysis')
AP_FLAGS.add_argument('--output_dir', help='Output dir',
                      default='/var/www/graphs/graph-data/')
AP_FLAGS.add_argument('input_dir', help='Input dir to watch')
AP_FLAGS.add_argument('--tmp_dir', help='tmp dir', default='/var/ramdisk')
AP_FLAGS.add_argument('--scan_all_dates',
                      help='Nothing is too old, scan all dates',
                      default=False, action='store_true')
AP_FLAGS.add_argument('--hourly', help='Run hourly',
                      default=False, action='store_true')
AP_FLAGS.add_argument('--daily', help='Run daily',
                      default=False, action='store_true')
AP_FLAGS.add_argument('--weekly', help='Run weekly',
                      default=False, action='store_true')
AP_FLAGS.add_argument('--monthly', help='Run monthly',
                      default=False, action='store_true')

FLAGS = None
TOPN = 33
# The % of the total at which an element is too big to combine with
# another element
KEEP_PCT = 0.04

DATE_RE = re.compile(r'-(20.*?)-(\d\d\d\d)\.')

PLOT_COMMON = """
set timefmt "%Y%m%d-%H%M"
set xdata time
set terminal pngcairo size 1250,700 font ",6"
set format y "%.1s%c"
set format x "%a %m/%d %H:%M"
set grid xtics ytics
"""

LOG_PLOT_COMMON = """
set logscale y 2
set yrange [0.001:]
set key below maxrows 10
"""

STACKED_PLOT_COMMON = """
set yrange [0:]
set key below maxrows 10
"""


class StatsProc(object):
  def __init__(self, title, png_filename):
    self.total_bytes = {}
    self.total_pkts = {}
    self.file_stats = {}
    self.title = title
    self.needs_render = False
    self.png_filename = png_filename

  def AddStats(self, fname):
    self.needs_render = True
    date_match = DATE_RE.search(fname)
    if not date_match:
      print 'cannot parse date from filename %s' % fname
      return
    datestamp = (date_match.group(1), date_match.group(2))  # (yyyymmdd,hhmm)
    try:
      fh = open(fname)
    except IOError, e:
      print 'Cannot open file: %s' % e
      return
    if datestamp not in self.file_stats:
      self.file_stats[datestamp] = {}
    for line in fh:
      if not line:
        continue
      line_split = line.rstrip().split('\t')
      if len(line_split) != 3:
        continue
      key, pkts, bytes = line_split[0], int(line_split[1]), int(line_split[2])
      key = key.rstrip(':')
      if key not in self.total_bytes:
        self.total_bytes[key] = 0
      self.total_bytes[key] += bytes

      if key not in self.total_pkts:
        self.total_pkts[key] = 0
      self.total_pkts[key] += pkts

      if key not in self.file_stats[datestamp]:
        self.file_stats[datestamp][key] = [0, 0]
      self.file_stats[datestamp][key][0] += pkts
      self.file_stats[datestamp][key][1] += bytes

    fh.close()

  def GetCommonName(self, namea, nameb):
    # namea - larger one to combine into
    # nameb - smaller one to combine from
    # UDP:flood:0xffff:1.1.1.1|80
    nameasplit = namea.split(':')
    namebsplit = nameb.split(':')
    level_match = 0
    level = 0
    for level in xrange(4):
      if len(nameasplit) <= level or len(namebsplit) <= level:
        break
      if nameasplit[level] != namebsplit[level]:
        break
      level_match += 1
    combined_name = (':'.join(nameasplit[0:level])).rstrip(':')
    return (level_match, combined_name)

  def GetTopRows(self, stats_group_orig, max_elements, max_size_pct):
    # strategy:
    #  - combine the smallest elements until we have max_elements left
    stats_group_size = dict(stats_group_orig)
    stats_group = blist.sortedlist(
        stats_group_orig, key=lambda x: -stats_group_size[x])
    max_size = sum(stats_group_size.values()) * max_size_pct
    stats_parents = collections.defaultdict(set)
    while len(stats_group) > max_elements:
      combine = stats_group.pop()
      combine_parent = (':'.join(combine.split(':')[:-1])).rstrip(':')
      if len(stats_group)&0x7fff == 0:
        print 'processing', combine, len(stats_group), len(stats_group_size)
      common_name = None
      best_level = None
      best_common_name = ''
      best_parta = None
      # check for a short-circuit (see if the one-level-up value exists
      if combine_parent in stats_group_size:
        best_common_name = combine_parent
      else:
        for index in xrange(len(stats_group)-1, -1, -1):
          parta = stats_group[index]
          level_match, common_name = self.GetCommonName(parta, combine)
          if common_name != parta and stats_group_size[parta] > max_size:
            # this one is too big, don't do it.
            break
          if (best_level is None or level_match > best_level or
              common_name == parta):
            if (best_common_name and
                best_common_name == best_parta and best_level == level_match):
              # already have an exact match, no better than this one.
              continue
            if level_match <= best_level and common_name != parta:
              # less good of a level, not an exact match.
              continue
            best_level = level_match
            best_common_name = common_name
            best_parta = parta
        if not best_common_name:
          best_parta = None  # only combine with other, nothing else
        if best_common_name not in stats_group_size:
          stats_group_size[best_common_name] = 0
          if best_common_name:
            # Do not add 'other', we sum that up later. This
            # avoids putting stuff in 'other' if it can go anywhere else.
            stats_group.add(best_common_name)
        elif best_common_name == combine:
          # add it back
          stats_group.add(best_common_name)
      if combine != best_common_name:
        # remove and add it back after the size is updated to keep it sorted.
        stats_group.discard(best_common_name)
        stats_group_size[best_common_name] += stats_group_size[combine]
        if best_common_name:
          stats_group.add(best_common_name)

        stats_parents[best_common_name].add(combine)
        del stats_group_size[combine]
      if best_common_name != best_parta and best_parta:
        stats_group.discard(best_common_name)
        stats_group_size[best_common_name] += stats_group_size[best_parta]
        if best_common_name:
          stats_group.add(best_common_name)

        stats_parents[best_common_name].add(best_parta)
        stats_group.discard(best_parta)
        del stats_group_size[best_parta]
    expanded_stats = []
    # convert to a list so we can add in Other at the end that isn't sorted.
    stats_group = list(stats_group)
    if '' in stats_group_size:
      stats_group.append('')
    found_eg = set()
    estat_dict = {}
    for sg in sorted(stats_group, key=lambda x: -x.count(':')):
      expanded_group = self.GetExpandedGroup(sg, stats_parents,
                                             stats_group_orig)
      for eg in expanded_group:
        found_eg.add(eg)
      estat_dict[sg] = expanded_group
    for sg in stats_group:
      expanded_stats.append((sg, estat_dict[sg]))
    return expanded_stats

  def GetExpandedGroup(self, sg_name, parents, orig_group):
    val = set()
    if sg_name in parents:
      for sg in parents[sg_name]:
        val.update(self.GetExpandedGroup(sg, parents, orig_group))
      if sg_name in orig_group:
        val.add(sg_name)
    else:
      val.add(sg_name)
    return val

  def _WritePng(self, output_dir, key_name, totals, stats_offset,
                title, png_filename, interval=300.0, multiplier=1.0):
    data_fname = '%s/gnuplot.data.%s.%d' % (
        FLAGS.tmp_dir, key_name, os.getpid())
    plot_cfg_fname = '%s/gnuplot.plotcfg.%s.%d' % (
        FLAGS.tmp_dir, key_name, os.getpid())
    data_fh = open(data_fname, 'w+')
    cfg_fh = open(plot_cfg_fname, 'w+')

    data_log_fname = '%s/gnuplot.log.data.%s.%d' % (
        FLAGS.tmp_dir, key_name, os.getpid())
    data_log_fh = open(data_log_fname, 'w+')
    plot_cfg_log_fname = '%s/gnuplot.log.plotcfg.%s.%d' % (
        FLAGS.tmp_dir, key_name, os.getpid())
    print 'TOTAL', len(totals)
    t1s = time.time()
    key_list = self.GetTopRows(totals, TOPN, KEEP_PCT)
    print 'GetTopRows: %d sec' % (time.time()-t1s)
    t1s = time.time()

    print 'Writing %s' % png_filename
    file_list = list(self.file_stats)
    file_list.sort()
    expanded_rec = {}
    for key, expanded_set in key_list:
      for expanded in expanded_set:
        expanded_rec[expanded] = key
    print 'Key setup: %d sec' % (time.time()-t1s)
    t1s = time.time()
    for datestamp in file_list:
      gnuplot_line = [('%s-%s' % (datestamp[0], datestamp[1]))]
      gnuplot_log_line = [('%s-%s' % (datestamp[0], datestamp[1]))]
      this_datapoint = 0.0
      fsd = self.file_stats[datestamp]
      agg_total = collections.defaultdict(float)
      for fsinfo, val in fsd.iteritems():
        agg_total[expanded_rec[fsinfo]] += val[stats_offset]
      for key, expanded in key_list:
        stats = agg_total[key]
        # Stack the graphs
        this_datapoint += multiplier*stats/interval
        gnuplot_line.append('%.2f' % (this_datapoint))
        gnuplot_log_line.append('%.2f' % (multiplier*stats/interval))
      print >>data_fh, ' '.join(gnuplot_line)
      print >>data_log_fh, ' '.join(gnuplot_log_line)
    data_fh.close()
    data_log_fh.close()

    print 'Gnuplot data file writer: %d sec' % (time.time()-t1s)
    t1s = time.time()

    # create stacked graph
    print >>cfg_fh, 'plot \\'
    for index, (key, _) in enumerate(key_list):
      key_color = self.GetColorHash(key)
      if not key:
        key = 'Other'
      if index:
        print >>cfg_fh, (' , "%s" using 1:%d:%d title "%s" with filledcurve '
                         'closed lc rgb "#%s" \\' %
                         (data_fname, index+2, index+1, key, key_color))
      else:
        print >>cfg_fh, (' "%s" using 1:%d title "%s" with filledcurve '
                         'y1=0 lc rgb "#%s"\\' %
                         (data_fname, index+2, key, key_color))
    print >>cfg_fh, ''
    print >>cfg_fh, PLOT_COMMON
    print >>cfg_fh, STACKED_PLOT_COMMON
    print >>cfg_fh, 'set ylabel "%s-per-second"' % key_name
    print >>cfg_fh, 'set title "%s (Stacked)"' % title
    print >>cfg_fh, 'set output "%s/%s-stacked.png' % (output_dir, png_filename)
    print >>cfg_fh, 'replot'
    cfg_fh.close()

    # create log graph
    cfg_fh = open(plot_cfg_log_fname, 'w+')
    print >>cfg_fh, 'plot \\'
    for index, (key, _) in enumerate(key_list):
      key_color = self.GetColorHash(key)
      if not key:
        key = 'Other'
      lweight = 1.5
      if index:
        print >>cfg_fh, (' , "%s" using 1:%d title "%s" with lines '
                         'lw %.1f lc rgb "#%s" \\' %
                         (data_log_fname, index+2, key, lweight, key_color))
      else:
        print >>cfg_fh, (' "%s" using 1:%d title "%s" with lines '
                         'lw %.1f lc rgb "#%s" \\' %
                         (data_log_fname, index+2, key, lweight, key_color))
    print >>cfg_fh, ''
    print >>cfg_fh, PLOT_COMMON
    print >>cfg_fh, LOG_PLOT_COMMON
    print >>cfg_fh, 'set ylabel "%s-per-second"' % key_name
    print >>cfg_fh, 'set title "%s (Logscale)"' % title
    print >>cfg_fh, 'set output "%s/%s-log.png' % (output_dir, png_filename)
    print >>cfg_fh, 'replot'

    cfg_fh.close()
    cfg_fh = open(plot_cfg_log_fname)
    p1 = subprocess.Popen(['/usr/local/bin/gnuplot'], stdin=cfg_fh)
    cfg_fh.close()
    cfg_fh = open(plot_cfg_fname)
    p2 = subprocess.Popen(['/usr/local/bin/gnuplot'], stdin=cfg_fh)
    cfg_fh.close()
    p1.wait()
    p2.wait()
    DeleteIfEmpty('%s/%s-log.png' % (output_dir, png_filename))
    DeleteIfEmpty('%s/%s-stacked.png' % (output_dir, png_filename))
    print 'Gnuplot exec: %d sec' % (time.time()-t1s)
    t1s = time.time()
    os.unlink(data_fname)
    os.unlink(data_log_fname)
    os.unlink(plot_cfg_fname)
    os.unlink(plot_cfg_log_fname)

  def GetColorHash(self, key):
    hashdigest = map(ord, hashlib.md5(key).digest())
    while len(hashdigest) > 3:
      if sum(hashdigest[:3]) < 64 or sum(hashdigest[:3]) > 256*3-64:
        # too dark or too light
        hashdigest = hashdigest[1:]
      break
    return '%02x%02x%02x' % tuple(hashdigest[:3])

  def WriteImage(self, output_dir):
    self._WritePng(output_dir, 'packets', self.total_pkts, 0,
                   title=self.title+' Packets',
                   png_filename=self.png_filename+'-pps')
    self._WritePng(output_dir, 'bits', self.total_bytes, 1,
                   title=self.title+' Bitrate',
                   png_filename=self.png_filename+'-bps', multiplier=8.0)


def DeleteIfEmpty(fname):
  try:
    statf = os.stat(fname)
    if not statf.st_size:
      os.unlink(fname)
  except IOError:
    pass


def main(unused_argv):
  global FLAGS
  FLAGS = AP_FLAGS.parse_args()
  stats = []
  stats.append(ProcessStats(FLAGS.input_dir, '', subtitle='All subnets'))
  stats.append(ProcessStats(
      FLAGS.input_dir, '1.1.1.0', subtitle='Filter: 1.1.1.x'))
  stats.append(ProcessStats(
      FLAGS.input_dir, '1.2.3.0', subtitle='Filter: 1.2.3.x'))
  stats.append(ProcessStats(
      FLAGS.input_dir, '1.0.0.0', subtitle='Filter: 1.0.0.x'))
  while True:
    for stat in stats:
      print 'scanning... (%s)' % stat.subtitle
      # Only do a sigle dir if we're doing hourly/daily-only,
      # to allow faster cleanup
      if FLAGS.daily or FLAGS.weekly or FLAGS.monthly:
        stat.ScanNewFiles(single_dir=False)
      if FLAGS.hourly:
        stat.ScanHourlyFiles()
      stat.RenderStats()
      stat.AgeOutStats()
    time.sleep(10)


class ProcessStats(object):

  def __init__(self, input_dir, fname_match, subtitle=''):
    self.input_dir = input_dir
    self.fname_match = fname_match
    self.subtitle = subtitle
    self.hourly_stats = {}
    self.daily_stats = {}
    self.weekly_stats = {}
    self.monthly_stats = {}
    self.processed_files = {}
    if self.fname_match:
      self.fname_suffix = '-' + self.fname_match
    else:
      self.fname_suffix = '-all'

  def TooOld(self, fname):
    if FLAGS.scan_all_dates:
      return False
    date_match = DATE_RE.search(fname)
    if not date_match:
      return False
    yyyymmdd, hhmm = date_match.group(1), date_match.group(2)
    dt = datetime.datetime(
        int(yyyymmdd[:4]), int(yyyymmdd[4:6]), int(yyyymmdd[6:8]),
        int(hhmm[:2]), int(hhmm[2:4]))
    now = datetime.datetime.now()
    if FLAGS.monthly and (now-dt).days < 32:
      return False
    if FLAGS.weekly and (now-dt).days < 9:
      return False
    if FLAGS.daily and (now-dt).days < 2:
      return False
    return True

  def RenderStats(self):
    if FLAGS.hourly:
      for stat in self.hourly_stats.values():
        if stat.needs_render:
          stat.WriteImage(FLAGS.output_dir)
    if FLAGS.daily:
      for stat in self.daily_stats.values():
        if stat.needs_render:
          stat.WriteImage(FLAGS.output_dir)
    if FLAGS.weekly:
      for stat in self.weekly_stats.values():
        if stat.needs_render:
          stat.WriteImage(FLAGS.output_dir)
    if FLAGS.monthly:
      for stat in self.monthly_stats.values():
        if stat.needs_render:
          stat.WriteImage(FLAGS.output_dir)

  def ScanHourlyFiles(self):
    self.hourly_stats = {}
    for dirpath, _, filenames in os.walk(self.input_dir):
      for fname in sorted(filenames):
        if 'large' in fname:
          continue
        if self.fname_match and self.fname_match not in fname:
          continue
        full_path = os.path.join(dirpath, fname)
        if not self.WithinLastMins(fname, req_min_diff=65):
          continue
        self.ProcessStatFile(full_path)

  def WithinLastMins(self, fname, req_min_diff=60):
    date_match = DATE_RE.search(fname)
    if not date_match:
      return False
    yyyymmdd, hhmm = date_match.group(1), date_match.group(2)
    now = datetime.datetime.now()
    fdate = datetime.datetime(
        int(yyyymmdd[:4]), int(yyyymmdd[4:6]),
        int(yyyymmdd[6:8]), int(hhmm[:2]), int(hhmm[2:4]))
    timediff = now - fdate
    minute_diff = timediff.days * (24*60) + timediff.seconds/60
    if minute_diff <= req_min_diff:
      return True
    return False

  def ScanNewFiles(self, single_dir=False):
    found_files = False
    for dirpath, _, filenames in os.walk(self.input_dir):
      last_dirname_printed = ''
      file_count = 0
      fname = ''
      for fname in sorted(filenames):
        if 'large' in fname:
          continue
        if self.fname_match and self.fname_match not in fname:
          continue
        full_path = os.path.join(dirpath, fname)
        if self.TooOld(fname):
          continue
        statf = os.stat(full_path)
        if full_path in self.processed_files:
          # can't deal with changed files at this time, without restarting.
          # we've already seen it and it hasn't changed.
          continue
        if statf.st_size == 0 or statf.st_mtime+30 > time.time():
          # too new, or 0 bytes
          continue
        file_count += 1
        if last_dirname_printed != dirpath or (file_count%250 == 0):
          print 'Processing stats in dir: %s (%d files, last %s)' % (
              dirpath, file_count, fname)
        last_dirname_printed = dirpath
        self.ProcessStatFile(full_path)
        self.processed_files[full_path] = statf.st_mtime
        found_files = True
      if single_dir and found_files:
        # abort here, this allows cleanup in the daily files
        break
      if last_dirname_printed != '' and (file_count%250 != 0):
        print 'Processing stats in dir: %s (%d files, last %s)' % (
            dirpath, file_count, fname)

  def AgeOutStats(self):
    dt = datetime.datetime.now()
    # convert to a date
    dt = datetime.date(dt.year, dt.month, dt.day)
    if FLAGS.daily:
      statlist = list(self.daily_stats)
      for key_dt_tuple in statlist:
        key_dt = datetime.date(*key_dt_tuple)
        if (dt-key_dt).days > 1:
          del self.daily_stats[key_dt_tuple]
    if FLAGS.weekly:
      statlist = list(self.weekly_stats)
      for key_dt_tuple in statlist:
        key_dt = datetime.date(*key_dt_tuple)
        if (dt-key_dt).days > 8:
          del self.weekly_stats[key_dt_tuple]
    if FLAGS.monthly:
      statlist = list(self.monthly_stats)
      for key_dt_tuple in statlist:
        key_dt = datetime.date(*key_dt_tuple)
        if (dt-key_dt).days > 32:
          del self.monthly_stats[key_dt_tuple]
    print 'After ageout - daily/weekly/monthly: %d/%d/%d' % (
        len(self.daily_stats), len(self.weekly_stats), len(self.monthly_stats))

  def ProcessStatFile(self, fname):
    # get the directory, which has the yyyymmdd name
    datestr = os.path.basename(os.path.dirname(fname))
    if not datestr.startswith('2') or len(datestr) != 8:
      print 'Invalid dir: %s' % datestr
      return
    dateon = datetime.date(int(datestr[:4]), int(datestr[4:6]),
                           int(datestr[6:8]))
    hourly_key = (dateon.year, dateon.month, dateon.day)
    daily_key = (dateon.year, dateon.month, dateon.day)
    monthly_key = (dateon.year, dateon.month, 1)
    weekly_start = dateon
    while weekly_start.isoweekday() != 7:
      # find the closest sunday before
      weekly_start -= datetime.timedelta(1)
    weekly_key = (weekly_start.year, weekly_start.month, weekly_start.day)

    if FLAGS.hourly and hourly_key not in self.hourly_stats:
      title = 'OneNet (%s): 1-hour view - %d/%d/%d' % (
          self.subtitle, daily_key[1], daily_key[2], daily_key[0])
      filename = 'onenet-99999999-hourly%s' % (self.fname_suffix)
      self.hourly_stats[hourly_key] = StatsProc(title, filename)
    if FLAGS.daily and daily_key not in self.daily_stats:
      title = 'OneNet (%s): %d/%d/%d' % (
          self.subtitle, daily_key[1], daily_key[2], daily_key[0])
      filename = 'onenet-%04d%02d%02d-daily%s' % (
          daily_key[0], daily_key[1], daily_key[2], self.fname_suffix)
      self.daily_stats[daily_key] = StatsProc(title, filename)
    if FLAGS.weekly and weekly_key not in self.weekly_stats:
      week_end = datetime.date(*weekly_key) + datetime.timedelta(6)
      title = 'OneNet (%s): %d/%d/%d to %d/%d/%d' % (
          self.subtitle, weekly_key[1], weekly_key[2], weekly_key[0],
          week_end.month, week_end.day, week_end.year)
      filename = 'onenet-%04d%02d%02d-weekly%s' % (
          weekly_key[0], weekly_key[1], weekly_key[2], self.fname_suffix)
      self.weekly_stats[weekly_key] = StatsProc(title, filename)
    if FLAGS.monthly and monthly_key not in self.monthly_stats:
      month_end = datetime.date(*monthly_key) + datetime.timedelta(32)
      month_end = (datetime.date(month_end.year, month_end.month, 1) -
                   datetime.timedelta(1))
      title = 'OneNet (%s): %d/%d/%d to %d/%d/%d' % (
          self.subtitle, monthly_key[1], monthly_key[2], monthly_key[0],
          month_end.month, month_end.day, month_end.year)
      filename = 'onenet-%04d%02d01-monthly%s' % (
          monthly_key[0], monthly_key[1], self.fname_suffix)
      self.monthly_stats[monthly_key] = StatsProc(title, filename)

    if FLAGS.hourly:
      self.hourly_stats[hourly_key].AddStats(fname)
    if FLAGS.daily:
      self.daily_stats[daily_key].AddStats(fname)
    if FLAGS.weekly:
      self.weekly_stats[weekly_key].AddStats(fname)
    if FLAGS.monthly:
      self.monthly_stats[monthly_key].AddStats(fname)


try:
  print 'running'
  main(sys.argv)
except KeyboardInterrupt:
  pass
