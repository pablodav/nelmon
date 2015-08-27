#!/usr/bin/env python2
#####################################################################

from nelmon import constants as C
from nelmon.common import nelmon_exit
from nelmon.globals import NelmonGlobals
from nelmon.snmp_oids import general_oids as O
from nelmon.snmp import NelmonSnmp, SnmpArguments
from nelsnmp.hostinfo.device import HostInfo

NelmonGlobals(PLUGIN_VERSION='1.0')

description = """This plugin queries a network device by SNMP to check which
version is running on the device. Currently only works with Cisco IOS and
Cisco ASA.

"""

# For more information about this plugin visit:
# http://networklore.com/nelmon/

def main():
    argparser = SnmpArguments(description)
    args = argparser.parser.parse_nelmon_args()
    snmp = NelmonSnmp(args)
    hostinfo = HostInfo(snmp)
    hostinfo.get_version()
    nelmon_exit(C.OK, hostinfo.version)

if __name__ == "__main__":
    main()