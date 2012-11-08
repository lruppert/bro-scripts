#!/usr/bin/python
#
# This script will notice when bro has crashed and attempt to restart it.
#
# Some possible enhancements:
# Syslog the restart so that prelude can catch it, rather than emailing
# Throttle the restarts in case we've got a process crashing continually.
#
import os
import sys
from syslog import syslog
from subprocess import Popen, PIPE, STDOUT

BROCMD = "/usr/local/bro/current/bin/broctl"
BROENV = {"HOME": "/root", "PATH": "/bin:/sbin:/usr/bin:/usr/sbin"}
MAXLOSS = 5.0

indigents = []


#
# Sends the message to syslog for posterity
def tell_the_boss(message):
    syslog(message)

# Manages the following scenarios:
# high-1: 1324492012.296506 recvd=92016701 dropped=7 link=92016701
# high-3: <error: cannot connect to 192.168.18.138:47765>


def accuse_the_incompetent():
    stream = Popen([BROCMD, "netstats"],
                    env=BROENV, stdout=PIPE).communicate()[0]
    for chunk in stream.splitlines():
        data = chunk.split()
        worker = data[0].split(":")[0]
        # If we don't have five fields, the worker is already dead, but we
        # need the first field so that we have the condemned worker's name
        if (len(data) != 5):
            print "DEBUG: %s is unresponsive." % worker
            tell_the_boss("Worker %s is unresponsive.  Restarting." % worker)
            indigents.append(worker)
            return
        recvdeq = data[2]
        droppdeq = data[3]
        recvd = recvdeq.split('=')[1]
        droppd = droppdeq.split('=')[1]
        percentloss = 100.0 * (float(droppd) / float(recvd))

        if (percentloss > MAXLOSS):
            print "DEBUG: Looks like %s is stalled (%f percent post-capture packet loss)" % (worker, percentloss)
            tell_the_boss("Worker %s has %f percent post-capture packet loss. Restarting." % (worker, percentloss))
            indigents.append(worker)


#
# This restarts the workers flagged in the accuseTheIncompetent() routine
# and any which have crashed
def replace_the_indigent():
    for worker in indigents:
        p = Popen([BROCMD, "restart", worker], env=BROENV)
        sts = os.waitpid(p.pid, 0)[1]


def main():
    accuse_the_incompetent()
    replace_the_indigent()


if __name__ == "__main__":
    main()
