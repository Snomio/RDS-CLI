#!/usr/bin/python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

# Changelog:
#
# 20-03-2018: ver. 1.2.04-alpha
#
# - FIX: usage of colon in credentials
# - ADD: support for SNOM_DEBUG environment variable
#
# 09-03-2018: ver. 1.2.03-alpha
#
# - REM: removed snom360
# - FIX: improved robustness in error handling the check command
#
# 06-03-2018: ver. 1.2.02-alpha
#
# - REM: removed snom820
# - FIX: fixed error handling in getting redirection
#
# 25-01-2018: ver. 1.2.01-alpha
#
# - ADD: new mac ranges
#
# 25-01-2018: ver. 1.2.00-alpha
#
# - ADD: support for SRAPS
#
# 19-01-2017: ver. 1.1.11
#
# - FIX: typo in some snom710 and snom725 dev. name
#
# 28-11-2017: ver. 1.1.10
#
# - FIX: typo in mac 8A
# - MOD: added some more debug info in case of error
#
# 30-08-2017: ver. 1.1.9
# - ADD: new mac ranges
#
# 09-08-2017: ver. 1.1.8
# - FIX: fix usage of | char in loading defaults
#
# 21-04-2017: ver. 1.1.7
# - MOD: Updated copyright note
# - ADD: Dockerfile
#
# 08-03-2017: ver. 1.1.6
# - ADD: New mac ranges
# 
# 07-03-2017: ver. 1.1.5
# - FIX: input() Vs raw_input() backward compatible
#
# 30-12-2016: ver. 1.1.4
# - New mac range for the 715
#
# 10-11-2016: ver. 1.1.3
#  - Python 3 support
#  - use of default url if url is not present into add
#
# 06-10-2016: ver. 1.1.2
#   - Add 7E Snom 710 range
#
# 04-08-2016: ver. 1.1.1
#   - Fixed m9 response parsing
#
# 15-03-2016: ver. 1.1.0
#   - Added Versioning: version command and first number
#   - Updated Copyright notice
#   - Extract setting_server from the response via regex
#   - PEP8 compliance

import cmd
import rlcompleter
try:
    import readline
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
except ImportError:
    # no readline support
    pass
import getpass
import binascii

try:
    from xmlrpc.client import SafeTransport, ServerProxy, Error
    import http.client as HttpClient
except ImportError:  # Python 2 fallback
    from xmlrpclib import SafeTransport, ServerProxy, Error
    import httplib as HttpClient

import os.path
import sys
import re
import ssl
from base64 import b64encode

__version__ = "1.2.04-alpha"

# check raw_input (python2.6)
try:
    input = raw_input
except NameError:
    pass


error_map = {
    "Error:malformed_mac": "Invalid MAC address",
    "Error:no_such_mac": "MAC address not registered.",
    "Error:owned_by_other_user": "MAC address is owned by another user."
}

defaults = {
    "username": "",
    "password": "",
    "url": "",
    "savelocals": 0,
}

type_map = {
    "24": "snom320",
    "25": "snom300",
    "26": "snom370",
    "27": "snom320",
    "28": "snom300",
    "2C": "snom320",
    "2D": "snom300",
    "2E": "snom370",
    "2F": "snom300",
    "30": "snomm9",
    "31": "snom320",
    "32": "snomMP",
    "33": "snomPA1",
    "34": "snom300",
    "35": "snom320",
    "36": "snom300",
    "37": "snom300",
    "38": "snom320",
    "3A": "snom370",
    "3B": "snom300",
    "3C": "snom370",
    "3D": "snom300",
    "3E": "snom300",
    "3F": "snom320",
    "41": "snom870",
    "45": "snom821",
    "46": "snom821",
    "47": "snom870",
    "48": "snom821",
    "49": "snom300",
    "4A": "snom300",
    "4B": "snom821",
    "4C": "snom300",
    "4E": "snom300",
    "4D": "snom320",
    "50": "snom300",
    "51": "snom320",
    "52": "snom370",
    "53": "snom821",
    "54": "snom870",
    "55": "snomMP",
    "56": "snomm9",
    "61": "snomM700",
    "62": "snomM300",
    "64": "snomM200SC",
    "70": "snom720",
    "71": "snom760",
    "74": "snom710",
    "75": "snom715",
    "76": "snom710",
    "77": "snom720",
    "78": "snom725",
    "7A": "snom710",
    "7B": "snom760",
    "7C": "snom710",
    "7D": "snom720",
    "7E": "snom710",
    "7F": "snom715",
    "79": "snomD745",
    "82": "snomD120",
    "83": "snomD305",
    "84": "snomD315",
    "85": "snomD345",
    "86": "snom725",
    "87": "snom715",
    "88": "snomD712",
    "89": "snom710",
    "8A": "snom715",
    "8D": "snomPA1",
    "8B": "snom725",
    "8E": "snomD305",
    "8F": "snomD315",
    "90": "snomD765",
    "91": "snomD375",
    "92": "snomD785",
    "93": "snomD385",
    "94": "snomD765",
    "95": "snomD375",
    "A0": "snomC520",
    "A1": "snomD345"
}

server = None

local_vars = {}

class HTTPSSafeAuth(SafeTransport):
    def __init__(self, user, password, *l, **kw):
        SafeTransport.__init__(self, *l, **kw)
        self.user = user
        self.password = password

    def send_content(self, connection, request_body):
        if sys.version_info > (3, 0):
            auth = b64encode(bytes(self.user + ':' + self.password, "utf-8")).decode("ascii")
        else:
            auth = b64encode(self.user + ':' + self.password)
        connection.putheader('Content-Type', 'text/xml')
        connection.putheader('Authorization', 'Basic %s' % auth)
        connection.putheader("Content-Length", str(len(request_body)))
        connection.endheaders()
        if request_body:
            connection.send(request_body)

# Util

def make_rpc_conn(user, passwd, debug=False):
    url = 'https://secure-provisioning.snom.com:8083/xmlrpc/'
    if sys.version_info > (2, 7):
        transport = HTTPSSafeAuth(user, passwd, context=ssl._create_unverified_context())
        return ServerProxy(url, transport=transport, verbose=debug, allow_none=True)
    else:  # Python 2.6 compatible:
        transport = HTTPSSafeAuth(user, passwd)
        return ServerProxy(url, transport=transport, verbose=debug, allow_none=True)


def validate_mac(mac):
    # not a snom MAC
    if not mac.startswith("000413"):
        return False

    # unknown phone type
    if not get_type(mac):
        return False

    # remaining part is not a HEX number
    try:
        binascii.a2b_hex(mac[8:])
    except TypeError:
        return False
    return True


def get_type(mac):
    if mac[6:8] in type_map:
        return type_map[mac[6:8]]
    else:
        print("Unknown device type (maybe not a snom MAC?)")
        return None


def set_var(name, value):
    local_vars[name] = value


def get_var(name):
    if name in local_vars:
        return local_vars[name]
    else:
        print("unknown variable %s" % name)
        return None


def print_error(res):
    if len(res) == 2:
        if res[1] in error_map:
            print(error_map[res[1]])
        else:
            print(res[1])
    else:
        print(res)


def store_defaults():
    homedir = os.path.expanduser('~')
    file = open("%s/.snomcli" % homedir, "w")
    file.write("\n".join(["%s|%s" % (x, defaults[x]) for x in defaults]))
    if defaults["savelocals"]:
        file.write("\n=====\n")
        file.write("\n".join(["%s|%s" % (x, local_vars[x])
                              for x in local_vars]))
    file.close()


def load_defaults():
    homedir = os.path.expanduser('~')
    try:
        file = open("%s/.snomcli" % homedir, "r")
    except IOError:
        return
    line = ""
    is_defaults = True
    for line in file.readlines():
        try:
            if line == "=====\n":
                is_defaults = False
                continue
            (name, value) = line.split("|", 1)
            if is_defaults == False:
                local_vars[name] = value.strip()
            else:
                defaults[name] = value.strip()
        except Error:
            pass

# Commands

def validate_password(user, passwd):
    s = make_rpc_conn(user, passwd)

    try:
        s.network.echo("ping")
    except Error as err:
        print("Error: %d %s" % (err.errcode, err.errmsg))
        return False

    return True


# Replace variable values
def replace_value(var):
    if var.startswith('%'):
        varname = var[1:]
        if varname in local_vars:
            return local_vars[varname]
        else:
            return var
    else:
        return var


class RedirectionCli(cmd.Cmd):
    """Command processor"""
    phone_types = sorted(set(type_map.values()))

    def __init__(self):
        cmd.Cmd.__init__(self)
        self._history = []
        self.prompt = "%s%%> " % username
        self.intro = banner  # defaults to None
        self.doc_header = "Available commands (type help <command>):"

    def _get_redirection_target(self, mac):
        redirection = server.redirect.getPhoneRedirection(mac)
        if redirection[0] == True:
            company = redirection[1] or ''
            target = redirection[2] or ''
            return " %s | %s " % (company.ljust(32), target.ljust(80))
        else:
            print("Error in getting phone redirection (%s)" % mac)
            return ''

    def _print_result(self, result):
        print("-" * 136)
        print("| MAC  address |              Company              | URL%s|" % (" " * 79))
        print("-" * 136)
        for x in result:
            target = self._get_redirection_target(x)
            print("\n".join(["| %s | %s |" % (x.upper().ljust(10), target)]))
        print("-" * 136)
        return

    def _list_all(self):
        result = []
        print("Loading information ...\n")
        for t in self.phone_types:
            r = server.redirect.listPhones(t, None)
            result.extend(r)
        if len(result) > 0:
            self._print_result(result)
        else:
            print("No phones registered for this user.")

    def do_list(self, params):
        """List phones configured in redirection service
            'list all' list all phones
            'list <phone_type>' list only phone matching <phone_type> (Eg. "list snom370")
            'list <phone_type> <url>' list only phone matching thist <phone_type> and <url> (Eg. "list snom370 http://server.example.com/" )
        """
        args = params.split()
        if len(args) >= 1:
            # list all
            if args[0] == "all":
                return self._list_all()
            model = args[0]
            if model not in type_map.values():
                print("Error: model %s not found" % model)
                return
            if len(args) == 2:
                url = args[1]
            else:
                url = None
            result = server.redirect.listPhones(model, url)
            if len(result) > 0:
                if not result[0]:
                    print("Error: %s" % result[1])
                    return
                self._print_result(result)
                return
            else:
                if len(args) == 2:
                    print("No phones of type %s redirected to %s registered for this user." % (model, url))
                else:
                    print("No phones of type %s registered for this user." % model)
                return
        else:
            print("Wrong arguments. Use 'list phonetype [url]' or 'list all'")
            return

    # add command
    def do_add(self, params):
        """Add phone in redirection service
            'add <mac> <url>' add redirection to <url> for mac address <mac> (Eg. "add 000413XXXXXX http://server.example.com")
            in case the <url> param is missing the default url value will be used (see the 'defaults' command)
        """
        args = list(map(replace_value, params.split()))
        if len(args) == 1:
            if len(defaults['url']) > 0:
                args.append(defaults['url'])
            else:
                print("ERROR: Default url not defined, please define it using 'default url <url>'")
                return
        if len(args) != 2:
            print("Wrong arguments. Use 'add mac_address target_url'")
            return
        if not validate_mac(args[0]):
            print("%s does not seem to be a valid snom MAC address." % args[0])
            return
        print("Adding redirection for %s to %s." % (args[0], args[1]))
        result = server.redirect.checkPhone(args[0])
        if result[0]:
            print("Phone already registered, use 'remove' or 'update' command")
            return
        result = server.redirect.registerPhone(args[0], args[1])
        if result[0]:
            print("Redirection to %s for %s with MAC address %s has been successfully registered." % (args[1], get_type(args[0]), args[0]))
        else:
            print_error(result)
            return

    # update command
    def do_update(self, params):
        """Update phones in redirection service
            'update <mac> <url>' modify redirection to <url> for mac address <mac> (Eg. "add 000413XXXXXX http://server.example.com"'
        """
        args = params.split()
        if len(args) != 2:
            print("Wrong arguments. Use 'update mac_address target_url'")
            return
        if not validate_mac(args[0]):
            print("%s does not seem to be a valid snom MAC address." % args[0])
            return
        print("Updating redirection for %s to %s." % (args[0], args[1]))
        server.redirect.deregisterPhone(args[0])
        result = server.redirect.registerPhone(args[0], args[1])
        if result[0]:
            print("Redirection to %s for %s with MAC address %s has been successfully updated." % (args[1], get_type(args[0]), args[0]))
        else:
            print_error(result)
            return

    # remove command
    def do_remove(self, params):
        """Remove phone from redirection service
            'remove <mac>' remove redirection for mac address <mac> (Eg. "remove 000413XXXXXX"'
        """
        args = params.split()
        if len(args) != 1:
            print("Wrong arguments. Use 'remove mac_address'")
            return
        if not validate_mac(args[0]):
            print("%s does not seem to be a valid snom MAC address." % args[0])
            return

        result = server.redirect.deregisterPhone(args[0])
        if result[0]:
            print("Successfully removed redirection for %s with MAC address %s." % (get_type(args[0]), args[0]))
        else:
            print_error(result)
            return

    # check command
    def do_check(self, params):
        """Verify redirection for a specific mac address
            'check <mac>' verify redirection for mac address <mac> (Eg. "check 000413XXXXXX")
        """
        args = params.split()
        if len(args) == 1:
            mac = args[0].upper()
            result = server.redirect.checkPhone(mac)
            if result[0]:
                target = server.redirect.getPhoneRedirection(mac)
                print("%s with MAC address %s is registered." % (get_type(mac), mac))
                if target[0] == True:
                    if target[1] != '':
                        print("\tMac is owned by %s" % target[1])
                    if target[2] != '':
                        print("\tCurrent redirection target is: %s" % target[2])
                    else:
                        print("\tThe mac is not redirected")
                else:
                    print("\tError getting the redirection target: %s" % target[1])
            else:
                print_error(result)
        else:
            print("Wrong arguments. Use 'check MAC_Address'")

    # set command
    def do_set(self, params):
        """Set a variable value
            'set <var_name> <value>' set a variable <var_name> to value <value> (Eg. "set server http://my.server.example.com/provscript.php)"
        """
        args = params.split()
        if len(args) == 2:
            set_var(args[0], args[1])
            return
        else:
            print("Wrong arguments. Use 'set <var_name> <value>'")
            return

    # print command
    def do_print(self, params):
        """Print local variables
            'print all' print all defined variables
            'print <var_name>' print local variable <var_name>
        """
        args = params.split()
        if len(args) == 1:
            if args[0] == "all":
                print("\nLocal variables:")
                print("================")
                if len(local_vars) == 0:
                    print("\nNo local variables defined. Use 'set var_name var_value' to define variables.")
                else:
                    print("\n".join(["%s = %s" % (var, local_vars[var]) for var in local_vars]))
                print("")
            else:
                if args[0] in local_vars:
                    print("%s = %s" % (args[0], local_vars[args[0]]))
                else:
                    print("Unknown variable %s" % args[0])
        else:
            print("Wrong arguments. Use 'print var_name or print all")

    def do_defaults(self, params):
        """Manage default settings
            'defaults print' print current defaults setting
            'defaults store' store all current settings in configuration file
            'defaults <setting> <value>' store single setting in configuration file
        """
        args = params.split()
        if len(args) == 1:
            if args[0] == "print":
                print("\nCurrent default settings:")
                print("-------------------------")
                print("\n".join(["%s => %s" % (x.ljust(10), defaults[x]) for x in defaults]))
            elif args[0] == "store":
                store_defaults()
                print("Defaults written...")
            else:
                var = args[0]
                if var in defaults:
                    defaults[var] = ''
                    print("Removed value for %s" % var)
                    store_defaults()
                else:
                    print("Default setting not found: %s" % var)
        elif len(args) == 2:
            var = args[0]
            val = args[1]
            if var in defaults:
                defaults[var] = val
                print("Changed default value %s to %s" % (var, val))
                store_defaults()
            else:
                print("Default setting not found: %s" % var)
        else:
            print("Wrong arguments. Use 'defaults [name] [value]' or 'defaults print'.")

    def do_history(self, args):
        """Print a list of commands that have been entered"""
        print("\n".join(self._history))

    def do_exit(self, args):
        """Exits from the console"""
        return True

    ## Command definitions to support Cmd object functionality ##
    def do_EOF(self, args):
        """Exit on system end of file character"""
        return self.do_exit(args)

    def do_help(self, args):
        """Get help on commands
           'help' or '?' with no arguments prints a list of commands for which help is available
           'help <command>' or '? <command>' gives help on <command>
            """
        # The only reason to define this method is for the help text in the doc
        # string
        cmd.Cmd.do_help(self, args)

    def do_version(self, args):
        """Print the sofware version"""
        print("Version: %s" % __version__)

    def emptyline(self):
        pass

    def precmd(self, params):
        if params.strip() != "":
            self._history += [params.strip()]
        replaced = list(map(replace_value, params.split()))
        return ' '.join(replaced)

    def get_names(self):
        ret = []
        for d in dir(self.__class__):
            if d == "do_EOF":
                continue
            ret.append(d)
        return ret

# Main application loop
if __name__ == "__main__":
    load_defaults()
    banner = """###############################################
  Snom Redirection Server Console Ver. %s
  (c) 2010-2018 snom technology AG
###############################################""" % __version__

    if not defaults["username"]:
        username = input("Username: ")
    else:
        username = defaults["username"]

    if defaults["password"]:
        password = defaults["password"]
    else:
        password = None

    count = 0

    # Prompt for password
    while not password:

        password = getpass.getpass("Password: ")
        pwd_val = validate_password(username, password)

        if not pwd_val:
            password = None
            count = count + 1
            if count == 3:
                print("Three wrong passwords provided. Exiting.")
                sys.exit(-1)
        else:
            break

    defaults["username"] = username
    defaults["password"] = password

    command = None

    if "SNOM_DEBUG" in os.environ:
        debug = True
    else:
        debug = False
    server = make_rpc_conn(username, password, debug=debug)

    try:
        if len(sys.argv) > 1:
            RedirectionCli().onecmd(' '.join(sys.argv[1:]))
        else:
            RedirectionCli().cmdloop()
    except KeyboardInterrupt:
        print("\nGot keyboard interrupt. Exiting...")
        sys.exit(0)
