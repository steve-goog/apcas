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

"""Clean up the pcap files after a period of time."""

import os
import re
import sys
import syslog
import time


FNAME_RE = re.compile(
    r'-([0-9]{4})([0-9][0-9])([0-9][0-9])-([0-9][0-9])([0-9][0-9]).pcap')
MAX_FNAME_AGE_GZ = (60*60)*40
MAX_FNAME_AGE_PCAP = (60*60)*11
MAX_FNAME_AGE_SAMPLED_GZ = (60*60)*24*90
MAX_FNAME_AGE_SAMPLED_PCAP = (60*60)*24*14

# Customize this based on the location of the files to clean up.
# Format: (Cleanup Directory, Cleanup Filesystem)
PCAP = (('/var/onenet/', '/'),
        ('/sdb2/onenet/', '/sdb2'))


def ReadLinks(finished_dir):
  files = os.listdir(finished_dir)
  links = set()
  for fname in files:
    fullpath = os.path.join(finished_dir, fname)
    try:
      links.add(os.path.basename(os.readlink(fullpath)))
    except (OSError, IOError):
      continue
  return links


def ScanFiles(files_to_scan_dir, base_dir):
  """Scan files, looking for things that we can clean up."""
  sv = os.statvfs(base_dir)
  pct_free = float(sv.f_bfree)/sv.f_blocks
  max_fname_adjust = 1.0
  if pct_free < 0.02:
    max_fname_adjust = 0.75  # speed up by 75%
  elif pct_free < 0.05:
    max_fname_adjust = 0.5  # speed up by 50%
  elif pct_free < 0.10:
    max_fname_adjust = 0.6  # speed up by 40%
  elif pct_free < 0.20:
    max_fname_adjust = 0.7  # speed up by 30%
  elif pct_free < 0.25:
    max_fname_adjust = 0.8  # speed up by 20%
  elif pct_free < 0.33:
    max_fname_adjust = 0.9  # speed up by 10%
  files = os.listdir(files_to_scan_dir)
  links = ReadLinks(os.path.join(files_to_scan_dir, 'finished'))
  nowtime = time.time()
  for base_fname in files:
    if base_fname == 'finished':
      continue
    start_dir = os.path.join(files_to_scan_dir, base_fname)
    for dirpath, dirnames, filenames in os.walk(start_dir):
      if not dirnames and not filenames:
        LogMsg('Cleaning up empty path: %s' % dirpath)
        os.rmdir(dirpath)
        continue
      for fname in filenames:
        mg = FNAME_RE.search(fname)
        if not mg:
          continue
        filetime_tuple = [int(mg.group(1)), int(mg.group(2)),
                          int(mg.group(3)), int(mg.group(4)),
                          int(mg.group(5)), 0, 0, 0, -1]
        filetime_sec = time.mktime(filetime_tuple)
        full_path = os.path.join(dirpath, fname)
        if fname.endswith('.gz'):
          if fname[0] == '1' and 'sample' in fname:
            # 1.1.1.0sample files, not largepktSampleRate128sample files
            # the large files are too big to keep for extended periods
            max_time = MAX_FNAME_AGE_SAMPLED_GZ
          else:
            max_time = MAX_FNAME_AGE_GZ * max_fname_adjust
        else:
          if fname[0] == '1' and 'sample' in fname:
            # 1.1.1.0sample files, not largepktSampleRate128sample files
            # the large files are too big to keep for extended periods
            max_time = MAX_FNAME_AGE_SAMPLED_PCAP
          else:
            max_time = MAX_FNAME_AGE_PCAP * max_fname_adjust
        if nowtime-filetime_sec > max_time:
          LogMsg('Deleting %s (%.1f hrs old, over limit of %.1f hrs)' %
                 (full_path, (nowtime-filetime_sec)/(60.0*60),
                  (max_time/(60.0*60))))
          if fname in links:
            LogMsg('Not removing %s, has not been uploaded!' % full_path)
            continue
          os.unlink(full_path)


def LogMsg(msg):
  syslog.syslog(msg)


def main(unused_argv):
  syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL6)
  for base_dir, root in PCAP:
    ScanFiles(base_dir, root)


main(sys.argv)
