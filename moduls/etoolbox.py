#!/usr/bin/env python

from moduls.elog import logme
import ConfigParser
import re
import time
import sys

def timestamp():
    now = time.time()
    localtime = time.localtime(now)
    milliseconds = '%03d' % int((now - int(now)) * 1000)
    return time.strftime('%Y%m%dT%H%M%ST', localtime) + milliseconds


def ip4or6(ip):

    if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip):
        return "4"
    else:
        return "6"


def readcfg(MODULE,ITEMS,FILE):

    RC = {}

    config = ConfigParser.ConfigParser()
    config.read(FILE)

    for items in ITEMS:
        if config.has_option(MODULE,items) == True and len(config.get(MODULE,items)) > 0:
            RC[items] = config.get(MODULE,items)
        else:
            print(" => [ERROR] Config parameter [%s] '%s=' didn't find or empty in %s config file. Abort !"%(MODULE,items, FILE))
            sys.exit()

    if "ip" in RC:
        RC["ipv"] = ip4or6(RC["ip"])

    return RC


def readonecfg(MODULE,item,FILE):

    config = ConfigParser.ConfigParser()
    config.read(FILE)

    if config.has_option(MODULE,item) == True and len(config.get(MODULE,item)) > 0:
        return config.get(MODULE,item)
    elif config.has_option(MODULE,item) == True and len(config.get(MODULE,item)) == 0:
        return "NULL"
    elif config.has_option(MODULE,item) == False:
        return "FALSE"
    else:
        return "UNKNOW"


if __name__ == "__main__":
    pass
