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


"""Post processing for onenet file data."""

import os
import random
import re
import subprocess
import syslog
import time

SLEEP_TIMER = 20
FINISHED = ('/var/onenet/finished/', '/sdb2/onenet/finished/')
GSUTIL_RE = re.compile(r'^[ \t]*(\d+)[ \t]')


class RunProc(object):
  def __init__(self, cmdline, callback, callback_args,
               max_runtime=14400, stdout=subprocess.PIPE):
    self.cmdline = cmdline
    self.callback = callback
    self.callback_args = callback_args
    self.done = False
    self.proc = None
    self.max_runtime = max_runtime
    self.stdout = stdout
    self.Run()

  def Run(self):
    self.proc = subprocess.Popen(
        self.cmdline, stdout=self.stdout, stderr=subprocess.PIPE)
    self.starttime = time.time()
    self.deadtime = self.starttime + self.max_runtime
    LogMsg('Running (PID %d): %s' % (self.proc.pid, ' '.join(self.cmdline)))

  def DoCallback(self):
    stdout, stderr = self.proc.communicate()
    if stdout:
      stdout = stdout.rstrip()
      LogMsg('Stdout from %d: %s' % (self.proc.pid, stdout))
    if stderr:
      stderr = stderr.strip()
      LogMsg('Stderr from %d: %s' % (self.proc.pid, stderr))
    if self.callback:
      self.callback(stdout, stderr, *self.callback_args)

  def CheckState(self):
    if self.done:
      # it's done and we already know it.
      return self.done
    if self.proc.poll() is not None:
      self.done = True
    elif self.deadtime < time.time():
      # It's not done but the timer expired.  kill it.
      LogMsg('Timer expired for PID %d, killing' % self.proc.pid)
      self.proc.terminate()
      time.sleep(2)
      self.done = True
      if self.proc.poll() is None:
        self.proc.kill()
      self.proc.poll()
    return self.done


class DirHandler(object):
  def __init__(self):
    self.files_processing = {}
    self.concurrent_gzip = 0
    self.concurrent_gsutil = 0
    self.do_copy = set()

  def CheckExecuteState(self):
    done_files = []
    for full_path in self.files_processing:
      if self.files_processing[full_path].CheckState():
        done_files.append(full_path)
    for full_path in done_files:
      val = self.files_processing[full_path]
      del self.files_processing[full_path]
      val.DoCallback()

  def ScanPath(self, path):
    fnames = os.listdir(path)
    # randomize it in case of issues.
    random.shuffle(fnames)
    for fname in fnames:
      full_path = os.path.join(path, fname)
      if (not os.path.islink(full_path) or
          not os.path.isfile(os.readlink(full_path))):
        continue
      if full_path not in self.files_processing:
        if not full_path.endswith('.gz'):
          if os.path.exists(full_path + '.gz'):
            # we've already compressed it. Ignore.
            continue
          if self.concurrent_gzip > 5:
            continue
          target_file = os.readlink(full_path)
          target_gz_file = os.readlink(full_path) + '.gz'
          fh = open(target_gz_file, 'w+', 0)
          self.files_processing[full_path] = RunProc(
              ['/usr/bin/nice', '/bin/gzip', '-1', '-c', '-f', target_file],
              self.UpdatingLinkGz, [full_path, target_gz_file, fh],
              stdout=fh.fileno())
          self.concurrent_gzip += 1
        else:
          if (full_path[:-3] in self.files_processing or
              full_path in self.files_processing):
            # don't do anything if we're already processing it
            continue
          if self.concurrent_gsutil > 20:
            continue
          gs_path_list = os.readlink(full_path).split('/')
          while len(gs_path_list) > 1 and gs_path_list[0][:2] != '20':
            gs_path_list.pop(0)
          gs_path = 'gs://onedotpackets/%s' % '/'.join(gs_path_list)

          if full_path not in self.do_copy:
            # once the ls completes, it's removed out of self.files_processing
            self.LaunchLs(None, None, full_path, gs_path)
          else:
            self.do_copy.remove(full_path)
            self.files_processing[full_path] = RunProc(
                ['/usr/bin/gsutil', 'cp', os.readlink(full_path), gs_path],
                self.CopyDoneLaunchLs, [full_path, gs_path])
            self.concurrent_gsutil += 1

  def LaunchLs(self, unused_stdout, unused_stderr, full_path, gs_path):
    self.files_processing[full_path] = RunProc(
        ['/usr/bin/gsutil', 'ls', '-l', gs_path], self.CheckFileSizes,
        [full_path, gs_path], max_runtime=60)

  def CopyDoneLaunchLs(self, unused_stdout, unused_stderr, full_path, gs_path):
    self.concurrent_gsutil -= 1
    self.LaunchLs(None, None, full_path, gs_path)

  def UpdatingLinkGz(self, unused_stdout, unused_stderr, old_link_name,
                     target_gz_file, fh):
    LogMsg('Renaming link to add gz suffix: %s' % old_link_name)
    self.concurrent_gzip -= 1
    try:
      fh.close()
      # don't keep the old symlink around.
      # the file still exists though, we need a cronjob to clean up
      # occasionally so we don't run out of disk space.
      # The general plan (change this if your disk is different):
      # - keep the .gz files around on the machine for about 2 weeks
      # - keep the uncompressed files on the machine for about 3 days
      os.unlink(old_link_name)
      os.symlink(target_gz_file, old_link_name + '.gz')
    except (IOError, OSError), e:
      LogMsg('Error in rename: %s' % e)

  def CheckFileSizes(self, stdout, unused_stderr, full_path, gs_path):
    if not stdout:
      self.do_copy.add(full_path)
      return
    remote_size = 0
    for line in stdout.split('\n'):
      if gs_path in line:
        mg = GSUTIL_RE.match(line)
        if not mg:
          LogMsg('Unable to parse to find file size: %s' % line)
          continue
        remote_size = int(mg.group(1))
    try:
      stat = os.stat(full_path)
    except (IOError, OSError), e:
      # this may cause loops...
      LogMsg('Unable to get local file size: %s' % full_path)
      return
    if stat.st_size != remote_size:
      LogMsg('File sizes differ on %s (%d bytes) to %s (%d bytes)' %
             (full_path, stat.st_size, gs_path, remote_size))
      self.do_copy.add(full_path)
      return
    # file sizes are the same. We're done here, folks!
    LogMsg('Removing sym link, copy complete: %s' % full_path)
    # do the file analysis...
    if ('sample' in full_path and
        os.path.basename(full_path).startswith('1') and
        full_path.endswith('.gz')):
      # post-process files that match 1*sample.gz, remove the .gz part
      self.files_processing[full_path] = RunProc(
          ['/usr/local/bin/file_analysis.py', os.readlink(full_path)[:-3]],
          None, None)
    try:
      os.unlink(full_path)
    except (IOError, OSError), e:
      LogMsg('Error in unlink: %s' % e)


def LogMsg(msg):
  syslog.syslog(msg)


def main():
  syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL6)
  dh = DirHandler()
  while True:
    LogMsg('Scanning for completed files...')
    for dirpath in FINISHED:
      dh.ScanPath(dirpath)
    time.sleep(SLEEP_TIMER)
    dh.CheckExecuteState()

try:
  main()
except KeyboardInterrupt:
  pass
