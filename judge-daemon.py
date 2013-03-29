#coding: utf-8

import os

import daemon

from judge import main


if os.getuid() == 0:
    with daemon.DaemonContext():
        main()
else:
    print 'This script must run as root.'
