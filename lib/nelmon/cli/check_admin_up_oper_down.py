"""Plugin: Check Admin Up Oper Down."""
from nelmon import constants as C
from nelmon.common import nelmon_exit
from nelmon.globals import NelmonGlobals
from nelmon.snmp.oids import cisco_oids as O
from nelmon.snmp.args import SnmpArguments
from nelmon.snmp.handler import NelmonSnmp
import re

NelmonGlobals(PLUGIN_VERSION='1.3')

description = """This plugin queries a network device by SNMP to check if there are
any interfaces which are in the admin up (no shutdown) but are operationally
down. It returns a warning or critical state depending on if you use -w or -c

"""
# For more information about this plugin visit:
# https://networklore.com/check-admin-up-oper-down


def main():
    """Plugin: check_admin_up_oper_down."""
    argparser = SnmpArguments(description)
    argparser.parser.add_argument('-w', action='store_true',
                                  help='Return Warning if interfaces are down')
    argparser.parser.add_argument('-c', action='store_true',
                                  help='Return Critical if interfaces are down')
    argparser.parser.add_argument('-d', '--descr', dest='ifdescr_arg',  default=None, const=None,
                                  help='Search over Interface descr with regex'
                                       'example: GigabitEthernet(\d+)/0/(4[78]|[5][0-2])'
                                       'matches any of: GigabitEthernetx/0/47,48,50,51,52')
    argparser.parser.add_argument('-al', '--alias', dest='ifalias_arg',  default=None, const=None,
                                  help='Search over Interface alias with regex'
                                       'example: UPLINK'
                                       'matches any interfaces with keyword UPLINK on its alias')
    argparser.parser.add_argument('-id', '--ignore_descr', dest='ifdescr_ignore_arg',  default=None, const=None,
                                  help='Search over Interface ifDescr with regex and ignores that'
                                       'example: Stack')

    args = argparser.parser.parse_nelmon_args()

    if args.c:
        exit_status = C.CRITICAL
    elif args.w:
        exit_status = C.WARNING
    else:
        nelmon_exit(C.UNKNOWN, 'Use -w or -c')

    ifdescr_arg = args.ifdescr_arg
    ifalias_arg = args.ifalias_arg
    ifdescr_ignore_arg = args.ifdescr_ignore_arg

    snmp = NelmonSnmp(args)

    oidlist = []
    oidlist.append(O.ifAdminStatus)
    oidlist.append(O.ifOperStatus)

    var_table = snmp.getnext(*oidlist)

    admin_up = []
    oper_down = []

    for var_binds in var_table:

        for oid, value in var_binds:
            if O.ifAdminStatus in oid and value == 1:
                ifIndex = int(oid.rsplit('.', 1)[-1])
                admin_up.append(ifIndex)
            if O.ifOperStatus in oid and value == 2:
                ifIndex = int(oid.rsplit('.', 1)[-1])
                oper_down.append(ifIndex)

    down_interfaces = list(set(admin_up) & set(oper_down))
    if len(down_interfaces) == 0:
        nelmon_exit(C.OK, 'No interfaces down')

    oidlist = []
    interface_descr = {}
    interface_alias = {}
    for ifIndex in down_interfaces:
        oidlist.append(O.ifDescr + "." + str(ifIndex))
        oidlist.append(O.ifAlias + "." + str(ifIndex))
    var_binds = snmp.get(*oidlist)
    for oid, value in var_binds:
        if O.ifDescr in oid:
            ifIndex = int(oid.rsplit('.', 1)[-1])
            interface_descr[ifIndex] = value
        if O.ifAlias in oid:
            ifIndex = int(oid.rsplit('.', 1)[-1])
            interface_alias[ifIndex] = value
    return_string = []

    # Change the down_interfaces only to those that ifDescr matches regex passed to ifdescr_arg
    if ifdescr_arg:
        down_interfaces = []
        for ifIndex, ifDescr in interface_descr.items():
            # Add the regex from -d command, like: GigabitEthernet(\d+)/0/(4[78]|[5][0-2])
            ifdescr_regex = re.compile(ifdescr_arg)
            # Only add to down_interfaces if regex matches
            if ifdescr_regex.search(ifDescr):
                down_interfaces.append(ifIndex)

    # Change the down_interfaces only to those that ifAlias matches regex passed to ifalias_arg
    if ifalias_arg:
        down_interfaces = []
        if interface_alias:
            for ifIndex, ifAlias in interface_alias.items():
                # Add the regex from -al command, like: UPLINK
                ifalias_regex = re.compile(ifalias_arg)
                # Only add to down_interfaces if regex matches
                if ifalias_regex.search(ifAlias):
                    down_interfaces.append(ifIndex)

    # Change the down_interfaces only to those that ifDescr doesn't match regex passed to ifdescr_ignore_arg
    if ifdescr_ignore_arg:
        for ifIndex, ifDescr in interface_descr.items():
            # Add the regex from --id command, like: GigabitEthernet(\d+)/0/(4[78]|[5][0-2]) or Stack
            ifdescr_regex = re.compile(ifdescr_ignore_arg)
            # Remove from down_interfaces if regex matches
            if ifdescr_regex.search(ifDescr):
                down_interfaces.remove(ifIndex)

    if len(down_interfaces) > 0:
        return_string.append("%d interfaces down" % (len(down_interfaces)))
    else:
        nelmon_exit(C.OK, 'No interfaces down')

    for ifIndex in down_interfaces:
        if len(str(interface_alias[ifIndex])) > 0:
            return_string.append(str(interface_descr[ifIndex]) + " - " + str(interface_alias[ifIndex]))
        else:
            return_string.append(str(interface_descr[ifIndex]))

    nelmon_exit(exit_status, return_string)

if __name__ == "__main__":
    main()
