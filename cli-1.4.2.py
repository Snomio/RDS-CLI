#!/usr/bin/python
# vi:si:et:sw=4:sts=4:ts=4
# -*- coding: UTF-8 -*-
# -*- Mode: Python -*-

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

__version__ = "1.4.2"

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

macPattern = re.compile("^(000413[0-9A-F]{6})|(00087[bB][0-9A-F]{6})$")

macRegexList = [
        (re.compile('000413(25|28|2D|2F|34|36|37|3B|3D|3E|49|4A|4C|50|4E)[0-9A-F]{4}'), 'snom300'),
        (re.compile('000413(24|27|2C|31|35|38|3F|4D|51)[0-9A-F]{4}'), 'snom320'),
        (re.compile('000413(26|2E|3A|3C|52)[0-9A-F]{4}'), 'snom370'),
        (re.compile('000413(30|56)[0-9A-F]{4}'), 'snomm9'),
        (re.compile('000413(32|55)[0-9A-F]{4}'), 'snomMP'),
        (re.compile('00041361[0-9A-F]{4}|00087B(08|09|0B)[0-9A-F]{4}'), 'snomM700'),
        (re.compile('000413(62|B8)[0-9A-F]{4}|00087BD7[0-9A-F]{4}'), 'snomM300'),
        (re.compile('000413B6[0-9A-F]{4}'), 'snomM900'),
        (re.compile('000413(33|8D)[0-9A-F]{4}'), 'snomPA1'),
        (re.compile('00041340[0-9A-F]{4}'), 'snom820'),
        (re.compile('000413(45|46|48|4B|53)[0-9A-F]{4}'), 'snom821'),
        (re.compile('000413(41|47|54)[0-9A-F]{4}'), 'snom870'),
        (re.compile('000413(70|77|7D)[0-9A-F]{4}'), 'snom720'),
        (re.compile('000413(78|86|8B|B7)[0-9A-F]{4}'), 'snom725'),
        (re.compile('000413(71|7B)[0-9A-F]{4}'), 'snom760'),
        (re.compile('00041394B4[0-1]{1}[0-9A-F]{1}|00041394B420'), 'snomD765'), # this must preceed the next rule: from 00041394B400 to 00041394B420 are D765
        (re.compile('00041394B[4-9A-E]{1}[0-9A-F]{1}|00041394BF0[0-3]'), 'snom715'), # 00041394B421 to 00041394BF03 are 715
        (re.compile('000413790[0-9A-F]{3}|000413(90|94)[0-9A-F]{4}'), 'snomD765'), # In the 00041379xxxx range only 000413790000 to 000413790FFF is used for snomD765
        (re.compile('000413(79|8C)[0-9A-F]{4}'), 'snomD745'), # This test must follow the test for snomD765, as 000413790xxx is D765, 000413791000 to 00041379FFFF is snomD745
        (re.compile('000413(74|76|7A|7C|7E|89)[0-9A-F]{4}'), 'snom710'),
        (re.compile('000413(75|7F|87|8A|A5|B2)[0-9A-F]{4}'), 'snom715'),
        (re.compile('000413(88|A8)[0-9A-F]{4}'), 'snomD712'),
        (re.compile('000413(91|95)[0-9A-F]{4}'), 'snomD375'),
        (re.compile('000413(83|8E)[0-9A-F]{4}'), 'snomD305'),
        (re.compile('00041384001[A-F6-9]|0004138400[2-6][0-9A-F]|0004138400[2-7][0-9]'), 'snomD305'), #the MACs of the range '000413840016' to '000413840079' are D305 devices, rest is D315
        (re.compile('00041384[0-9A-F]{4}|0004138F[0-9A-F]{4}'), 'snomD315'), # this must follow the D305 regex
        (re.compile('00041385[0-9A-F]{4}|000413A1[0-9A-F]{4}'), 'snomD345'),
        (re.compile('000413A6[0-9A-F]{4}'), 'snomD717'),
        (re.compile('00041382[0-9A-F]{4}'), 'snomD120'),
        (re.compile('000413A3[0-9A-F]{4}'), 'snomD735'),
        (re.compile('000413A4[0-9A-F]{4}'), 'snomD335'),
        (re.compile('00041364[0-9A-F]{4}'), 'snomM200SC'),
        (re.compile('000413(92|96)[0-9A-F]{4}'), 'snomD785'),
        (re.compile('00041393[0-9A-F]{4}'), 'snomD385'),
        (re.compile('00041398[0-9A-F]{4}'), 'snomD765')
]

models = list(set([ x[1] for x in macRegexList ]))

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

def make_rpc_conn(user, passwd):
    if "SNOM_DEBUG" in os.environ:
        debug = True
    else:
        debug = False
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
    """ The function converts the given 'mac' address into the appropriate phone type respectively. """
    if mac and len(mac) == 12:
        mac = mac.upper()
        match = macPattern.match(mac)
        if not match:
            print("Unknown device type (maybe not a snom MAC?): %s" % mac)
            return None
        for regex, phone in macRegexList:
            if regex.match(mac):
                return phone
    print("Unknown device type (maybe not a snom MAC?): %s" % mac)
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
        for t in models:
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
            if model not in models:
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
    # type command
    def do_type(self, params):
        """Get the devie type of a given mac address
            'type <mac>' returns the device type of the mac address <mac>
        """
        args = params.split()
        for mac in args:
            print("%s: %s" % (mac, get_type(mac)))

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

    server = make_rpc_conn(username, password)

    try:
        if len(sys.argv) > 1:
            RedirectionCli().onecmd(' '.join(sys.argv[1:]))
        else:
            RedirectionCli().cmdloop()
    except KeyboardInterrupt:
        print("\nGot keyboard interrupt. Exiting...")
        sys.exit(0)
