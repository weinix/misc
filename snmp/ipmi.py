#! /usr/bin/python

# This file is part of tcollector.
# Copyright (C) 2013  The tcollector Authors.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
# General Public License for more details.  You should have received a copy
# of the GNU Lesser General Public License along with this program.  If not,
# see <http://www.gnu.org/licenses/>.
#
"""SMART disk stats for TSDB"""

import glob
import os
import signal
import subprocess
import sys
import time
import re

IPMICLI = "/usr/bin/ipmitool sdr"
VENDORCLI = "/usr/sbin/dmidecode -s system-manufacturer"

SLEEP_BETWEEN_POLLS = 30 
COMMAND_TIMEOUT = 10


class Alarm(RuntimeError):
  pass


def alarm_handler(signum, frame):
  print >>sys.stderr, ("Program took too long to run, "
                       "consider increasing its timeout.")
  raise Alarm()

def dmidecode_is_broken():
  """Determines whether dmidecode can be used.

  Args:
    drives: A list of device names on which we intend to use SMART.

  Returns:
    True if dmidecode is available, False otherwise.
  """
  if os.path.exists("/usr/sbin/dmidecode"):
    return False
  else:
    return True


def process_output(ipmi_output):
  """Print formatted ipmitool output """
  ts = int(time.time())
  ipmi_output = ipmi_output.split("\n")

  for line in ipmi_output:
    match = re.search( r'^(.*) Temp.*(\d+\.*\d+) degrees', line )
    if match:
        sensor = match.group(1)
        reading = match.group(2)
        print ("ipmi.temp %d %s sensor=%s" % (ts, int(float(reading) * 1.8 + 32), sensor.replace(" ", "_")))

    match = re.search( r'^(.*) Input Power.*(\d+\.*\d+) Watts', line )
    if match: 
        sensor = match.group(1)
        reading = match.group(2)
        print ("ipmi.inputpower %d %s sensor=%s" % (ts, reading, sensor.replace(" ", "_")))
         

def main():
  """main loop for ipmitool collector"""

  # Exit gracefully if no block devices found
  #if not drives:
  #  sys.exit(13)
  #if dmidecode_is_broken:
  #   sys.exit(12)
  signal.alarm(COMMAND_TIMEOUT)
  dmicmd = subprocess.Popen( VENDORCLI,
                               shell=True, stdout=subprocess.PIPE)
  dmi_output = dmicmd.communicate()[0].split("\n")[0]
  #print dmi_output
  
  if dmi_output == "OpenStack Foundation" or dmi_output == "Bochs":
     sys.exit(13)

  while True:
    signal.alarm(COMMAND_TIMEOUT)
    ipmicmd = subprocess.Popen( IPMICLI,
                                 shell=True, stdout=subprocess.PIPE)
    ipmi_output = ipmicmd.communicate()[0]
    signal.alarm(0)
    if ipmicmd.returncode != 0:
      if smart_ctl.returncode == 127:
        sys.exit(13)
      else:
        print >>sys.stderr, "Command exited with: %d" % smart_ctl.returncode
    process_output(ipmi_output)

    sys.stdout.flush()
    time.sleep(SLEEP_BETWEEN_POLLS)


if __name__ == "__main__":
  main()
