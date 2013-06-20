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

"""Provide the CGI graphing interface to the sniffer data."""

import cgi
import os

GRAPHS = '/var/www/graphs/graph-data'

print 'Content-Type: text/html\n'


def IsValidImage(imgfname):
  if '/' in imgfname or not os.path.exists(os.path.join(GRAPHS, imgfname)):
    return False
  return True


def GetMatchingImg(files, must_include, closest=None, next_img=False,
                   exact=False):
  possible_match = []
  for fname in files:
    found_all = True
    for must in must_include:
      if must not in fname:
        found_all = False
        break
    if found_all:
      if not closest:
        return fname
      possible_match.append(fname)
  if len(possible_match) == 1:
    return possible_match[0]
  if not possible_match:
    return None
  if closest not in possible_match:
    possible_match.append(closest)
  possible_match.sort()
  return_next = False
  for index, fname in enumerate(possible_match):
    if return_next:
      return fname
    if fname == closest:
      if next_img:
        # return the next one
        return_next = True
      elif index == 0:
        if exact:
          return None
        return_next = True
      else:
        return possible_match[index-1]
  if return_next and exact:
    return None
  return possible_match[-2]


def GetDefaultImg(files):
  files.sort()
  files.reverse()
  fname = GetMatchingImg(files, ('-daily-', '-all-', 'pps-stacked'))
  if fname:
    return fname
  return files[-1]


def MakeLink(fname, title, is_link=True):
  if is_link and fname is not None:
    return '<a href="/graphs/?img=%s">%s</a>' % (fname, title)
  return title


def PrintHeader(files, img):
  links = []
  img_group = img.split('-')

  matching = img_group[:-1]
  img_file = GetMatchingImg(files, matching + ['-log'], closest=img)
  links.append(MakeLink(img_file, 'Logview', is_link=bool('-log' not in img)))
  img_file = GetMatchingImg(files, matching + ['-stacked'], closest=img)
  links.append(
      MakeLink(img_file, 'Stacked', is_link=bool('-stacked' not in img)))
  print '<font size=-2>[ %s] </font> ' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = img_group[:-2] + [(img_group[-1])]
  img_file = GetMatchingImg(files, matching + ['-pps'], closest=img)
  links.append(MakeLink(img_file, 'Packets', is_link=bool('-pps' not in img)))
  img_file = GetMatchingImg(files, matching + ['-bps'], closest=img)
  links.append(MakeLink(img_file, 'Bits', is_link=bool('-bps' not in img)))
  print '<font size=-2>[ %s] </font> ' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = img_group[3:]
  img_file = GetMatchingImg(files, matching + [('-daily')], closest=img)
  links.append(
      MakeLink(img_file, 'Daily',
               is_link=bool('-daily' not in img and img_file != img)))
  img_file = GetMatchingImg(files, matching + [('-weekly')], closest=img)
  links.append(
      MakeLink(img_file, 'Weekly',
               is_link=bool('-weekly' not in img and img_file != img)))
  img_file = GetMatchingImg(files, matching + [('-monthly')], closest=img)
  links.append(
      MakeLink(img_file, 'Monthly',
               is_link=bool('-monthly' not in img and img_file != img)))

  print '<font size=-2>[ %s ]</font> ' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = [img_group[0], img_group[1], img_group[2],
              img_group[-2], img_group[-1]]
  img_file = GetMatchingImg(files, matching + [('-all-')], closest=img)
  links.append(MakeLink(img_file, 'All', is_link=bool('-all-' not in img)))
  img_file = GetMatchingImg(files, matching + [('-1.1.1.0-')], closest=img)
  links.append(
      MakeLink(img_file, '1.1.1.0',
               is_link=bool('-1.1.1.0-' not in img and img_file != img)))
  img_file = GetMatchingImg(files, matching + [('-1.2.3.0-')], closest=img)
  links.append(
      MakeLink(img_file, '1.2.3.0',
               is_link=bool('-1.2.3.0-' not in img and img_file != img)))
  img_file = GetMatchingImg(files, matching + [('-1.0.0.0-')], closest=img)
  links.append(
      MakeLink(img_file, '1.0.0.0',
               is_link=bool('-1.0.0.0-' not in img and img_file != img)))

  print '<font size=-2>[ %s ]</font> ' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = img_group[2:]
  img_file = GetMatchingImg(files, matching, closest=img, next_img=False,
                            exact=True)
  links.append(MakeLink(img_file, '&lt;&lt; Prev',
                        is_link=bool(img_file != img)))
  img_file = GetMatchingImg(files, matching, closest=img,
                            next_img=True, exact=True)
  links.append(MakeLink(img_file, 'Next &gt;&gt;',
                        is_link=bool(img_file != img)))
  print '<font size=-2>[ %s ]</font>' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = img_group[2:]
  img_file = GetMatchingImg(files, matching, closest='onenet-99999999',
                            next_img=False)
  links.append(MakeLink(img_file, 'Latest'))
  print '<font size=-2>[ %s ]</font>' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  matching = img_group[3:]
  img_file = GetMatchingImg(files, matching + [('-hourly')], next_img=False)
  links.append(MakeLink(img_file, 'Latest (hourly)'))
  print '<font size=-2>[ %s ]</font>' % (' &nbsp; | &nbsp; '.join(links))
  links = []

  print '<br>'


def PrintImageLink(img):
  ua = os.environ.get('HTTP_USER_AGENT', '')
  if ('Chrome' in ua and
      ('MOBILE' not in ua.upper() and 'ANDROID' not in ua.upper())):
    print ('<script>function runLoad() { img.setAttribute("src",'
           '"/graphs/graph-data/%s"); } </script>' % img)
  else:
    print ('<script>function runLoad() { }</script> <img src="'
           '/graphs/graph-data/%s">' % img)


def main():
  form = cgi.FieldStorage()
  files = os.listdir(GRAPHS)
  fh = open('/var/www/graphs/graph.head.html')
  print fh.read()
  fh.close()
  img = form.getfirst('img')
  if not img or not IsValidImage(img):
    img = GetDefaultImg(files)
  files.sort()
  PrintHeader(files, img)
  PrintImageLink(img)
  fh = open('/var/www/graphs/graph.tail.html')
  print fh.read()
  fh.close()


try:
  main()
except KeyboardInterrupt:
  pass

