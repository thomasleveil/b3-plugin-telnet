# encoding: utf-8
#
# Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
# Copyright (C) 2008 courgette@bigbrotherbot.net
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA    02110-1301    USA
#----------------------------------------------------------------------------
#
# CHANGELOG:
#
# 1.1 - 2011-06-08
#    * add message of the day
#    * resolve ip to domain name upon connection
# 1.2 - 2011-06-09
#    * refactor TelnetAuthenticatedCommandProcessor so it is easier to add new commands
#    * add /who /name
# 1.3 - 2011-06-09
#    * refactor
#    * now telnet users authenticate using their B3 account (password must be set)
#    * add commands !tlist and !tkick
#
__version__ = '1.3'
__author__    = 'Courgette'
from ConfigParser import NoOptionError
from datetime import datetime, timedelta
import SocketServer
import b3
import b3.events
import b3.plugin
import os
import re
import select
import socket
import sys
import thread
import threading
import time
import traceback
from b3.clients import Client

TELNET_BANTIME_SECONDS = 60*2
RE_COLOR = re.compile(r'(\^[0-9])')
#--------------------------------------------------------------------------------------------------
class TelnetPlugin(b3.plugin.Plugin):
    telnetIp = None
    telnetPort = None
    telnetService = None
    telnetClients = None
    
    def onLoadConfig(self):
        # get the admin plugin so we can register commands
        self._adminPlugin = self.console.getPlugin('admin')
        if not self._adminPlugin:
            # something is wrong, can't start without admin plugin
            self.error('Could not find admin plugin')
            self.disable()
            return
        
        # load Metabans_account
        self.allGoodToStart = True
        try:
            self.telnetIp = self.config.get('general_preferences', 'ip')
            if self.telnetIp in ('', None):
                self.telnetIp = '0.0.0.0'
        except NoOptionError:
            self.info('no ip found in the general_preferences section of the config file. Listening on all network interfaces instead')
            self.telnetIp = '0.0.0.0'
            
        try:
            self.telnetPort = self.config.getint('general_preferences', 'port')
        except ValueError:
            self.allGoodToStart = False
            self.error('The port value found in the general_preferences section of the config file must be a number')
        except NoOptionError:
            self.allGoodToStart = False
            self.error('no port found in the general_preferences section of the config file. You need to set the port for the Telnet plugin to work')

        if not self.allGoodToStart:
            self.disable()
        
        if 'commands' in self.config.sections():
            for cmd in self.config.options('commands'):
                level = self.config.get('commands', cmd)
                sp = cmd.split('-')
                alias = None
                if len(sp) == 2:
                    cmd, alias = sp

                func = self._getCmd(cmd)
                if func:
                    self._adminPlugin.registerCommand(self, cmd, level, func, alias)

    def _getCmd(self, cmd):
        cmd = 'cmd_%s' % cmd
        if hasattr(self, cmd):
            func = getattr(self, cmd)
            return func

    def onStartup(self):
        if not self.allGoodToStart:
            self.info("Not starting Telnet service")
            return
        
        self.telnetClients = b3.clients.Clients(self.console)
        self.telnetClients.newClient = self._newClient
        self.telnetClients.disconnect = self._disconnect
        
        self.console.createEvent('EVT_CONSOLE_SAY', "console say")
        self.console.createEvent('EVT_CONSOLE_SAYBIG', "console bigsay")

        forwarded_events_names = ('EVT_CLIENT_SAY', 'EVT_CONSOLE_SAY', 
                           'EVT_CONSOLE_SAYBIG', 'EVT_CLIENT_CONNECT', 
                           'EVT_CLIENT_DISCONNECT', 'EVT_CLIENT_NAME_CHANGE', 
                           'EVT_CLIENT_KICK', 'EVT_CLIENT_BAN', 
                           'EVT_CLIENT_BAN_TEMP', 'EVT_CLIENT_UNBAN', 
                           'EVT_GAME_ROUND_START', 'EVT_GAME_MAP_CHANGE')
        
        self.forwarded_events = []
        for v in forwarded_events_names:
            event = self.console.Events.getId(v)
            if event:
                self.forwarded_events.append(event)
                self.registerEvent(event)

        original_say = self.console.say
        def _say(msg):
            self.console.queueEvent(self.console.getEvent('EVT_CONSOLE_SAY', msg))
            original_say(msg)
        self.console.say = _say
    
        original_saybig = self.console.saybig
        def _saybig(msg):
            self.console.queueEvent(self.console.getEvent('EVT_CONSOLE_SAYBIG', msg))
            original_saybig(msg)
        self.console.saybig = _saybig

        self.telnetService = TelnetServiceThread(self, self.telnetIp, self.telnetPort)
        self.telnetService.start()


    def onEvent(self, event):
        if event.type in (b3.events.EVT_STOP, b3.events.EVT_EXIT):
            self.telnetService.stop()
        elif event.type in self.forwarded_events:
            thread.start_new_thread(self._dispatchEvent, (event,))

    #===============================================================================
    # 
    #    Commands implementations
    #
    #===============================================================================

    def cmd_telnetlist(self, data, client, cmd=None):
        """\
        Show connected telnet users
        """        
        response = []
        for k, v in self.telnetClients.iteritems():
            tmp = datetime.now() - v.connection_datetime
            since = timedelta(seconds=int(tmp.total_seconds()))
            response.append("[%s] %s from %s since %s" % (k, v.name, v.cid, since))
        cmd.sayLoudOrPM(client, ', '.join(response))

    def cmd_telnetkick(self, data, client, cmd=None):
        """\
        <telnet session id> - kick a telnet user
        """        
        m = self._adminPlugin.parseUserCmd(data)
        if not m:
            client.message('^7Invalid parameters')
            return False

        cid, keyword = m
        reason = self._adminPlugin.getReason(keyword)

        if not reason and client.maxLevel < self._adminPlugin.config.getint('settings', 'noreason_level'):
            client.message('^1ERROR: ^7You must supply a reason')
            return False

        sclient = self.findClientPrompt(cid, client)
        if sclient:
            if sclient.cid == client.cid:
                self.console.say(self._adminPlugin.getMessage('kick_self', client.exactName))
            elif sclient.maxLevel >= client.maxLevel:
                if sclient.maskGroup:
                    client.message('^7%s ^7is a masked higher level player, can\'t kick' % client.exactName)
                else:
                    self.console.say(self._adminPlugin.getMessage('kick_denied', sclient.exactName, client.exactName, sclient.exactName))
            else:
                if reason:
                    sclient.message("you were kicked by %s (@%s) : %s" % (client.name, client.id, reason))
                else:
                    sclient.message("you were kicked by %s (@%s)" % (client.name, client.id))
                sclient.session.working = False
                sclient.session.server.shutdown_request(sclient.session.request)

    #===============================================================================
    # 
    #    others
    #
    #===============================================================================

    def findClientPrompt(self, client_id, client=None):
        matches = self.telnetClients.getByMagic(client_id)
        if matches:
            if len(matches) > 1:
                names = []
                for _p in matches:
                    names.append('[^2%s^7] %s' % (_p.cid, _p.name))

                if client:
                    client.message(self._adminPlugin.getMessage('players_matched', client_id, ', '.join(names)))
                return False
            else:
                return matches[0]
        else:
            if client:
                client.message(self._adminPlugin.getMessage('no_players', client_id))
            return None

    #===============================================================================
    # 
    # managing telnet sessions
    #
    #===============================================================================

    def _newClient(self, client):
        me = self.telnetClients
        client.cid = len(me) + 1
        client.console = me.console
        client.timeAdd = me.console.time()
        client.connection_datetime = datetime.now()
        client.authed = True
        
        me[client.cid] = client
        me.resetIndex()
        self.debug('Telnet Client Connected: [%s] %s - %s', client.cid, client.name, client.ip)
        return client
    
    def _disconnect(self, client):
        me = self.telnetClients
        client.connected = False
        if client.cid == None:
            return
        cid = client.cid
        if me.has_key(cid):
            me[cid] = None
            del me[cid]
            del client
        me.resetIndex()
    
    def _dispatchEvent(self, event):
        try:
            for k in self.telnetClients.keys():
                self._onB3Event(self.telnetClients[k], event)
        except:
            self.exception(sys.exc_info())


    def _onB3Event(self, client, event):
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_SAY'):
            client.message("  %s: %s" % (event.client.name, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAY'):
            client.message("  console: %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAYBIG'):
            client.message("  CONSOLE: %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_CONNECT'):
            client.message("  client connection : %s" % event.client)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_DISCONNECT'):
            client.message("  client disconnection : %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_NAME_CHANGE'):
            client.message("  %s renamed to %s" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_KICK'):
            client.message("  %s kicked (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN'):
            client.message("  %s banned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN_TEMP'):
            client.message("  %s tempbanned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_UNBAN'):
            client.message("  %s unbanned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_GAME_ROUND_START'):
            client.message("  round started %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_GAME_MAP_CHANGE'):
            client.message("  map change %s" % event.data)

class TelnetServiceThread(threading.Thread):
    def __init__(self, plugin, ip, port):
        threading.Thread.__init__(self)
        self.plugin = plugin
        self.ip = ip
        self.port = port
        self.server = None
        
    def run(self):
        self.server = TelnetServer((self.ip, self.port), TelnetRequestHandler, self.plugin)
        self.plugin.info("listening on %s:%s", self.ip, self.port)
        self.server.serve_forever()
        
    def stop(self):
        if self.server:
            self.server.shutdown()


class TelnetServer(SocketServer.ThreadingTCPServer):
    # By setting this we allow the server to re-bind to the address by
    # setting SO_REUSEADDR, meaning you don't have to wait for
    # timeouts when you kill the server and the sockets don't get
    # closed down correctly.
    allow_reuse_address = True
    
    def __init__(self, server_address, RequestHandlerClass, plugin):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        self.plugin = plugin
        self._banlist = {}

    def verify_request(self, request, client_address):
        return client_address[0] not in self.banlist
    
    @property
    def banlist(self):
        # remove old entries form banlist
        newbanlist = {}
        for ip, timestamp in self._banlist.iteritems():
            if timestamp > time.time():
                newbanlist[ip] = timestamp
        self._banlist = newbanlist
        return self._banlist
        
    def ban(self, ip):
        self.banlist[ip] = time.time() + TELNET_BANTIME_SECONDS

    

class TelnetRequestHandler(SocketServer.BaseRequestHandler):
    client = None
    processor = None
    working = True

    def setup(self):
        plugin = self.server.plugin
        plugin.info("telnet client connecting from %s:%s" % self.client_address)
        plugin.info("%r", socket.gethostbyaddr(self.client_address[0]))

    def handle(self):
        plugin = self.server.plugin

        self.request.send("HELLO from B3 Telnet plugin v%s\n\r" % __version__)
        self.processor = TelnetAuthProcessor(self)
        self.request.send("user id : ")
                            
        ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], None)
        text = ''
        try:
            while self.working:
                if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
                    data = self.request.recv(1024)
        
                    if not data:
                        break
                    elif len(data) > 0:
                        text += str(data)
        
                        while text.find("\n") != -1:
                            line, text = text.split("\n", 1)
                            line = line.rstrip()
                            try:
                                self.processor.process(line)
                            except TelnetCloseSession:
                                self.working = False
                            except:
                                lines = traceback.format_exc().splitlines()
                                self.request.send(lines[-1] + "\n\r")
                                plugin.error("%s", lines)
                                raise
        
        except socket.timeout:
            plugin.info("socket timeout")
            pass
        self.request.close()


    def onClientAuthenticated(self, client):
        for c in self.server.plugin.telnetClients.values():
            if c.id == client.id:
                client.message("There is already an other telnet session for that account from %s" % c.ip)
                client.message("Cannot connect. Bye")
                raise TelnetCloseSession("Account already in use")

        client.session = self
        self.client = self.server.plugin.telnetClients.newClient(client)
        
        # change Client.message() method so any message B3 would like to be
        # sent to that fake client as PM is redirected to this telnet session.
        # Also remove Quake3 color codes
        def message(msg):
            self.request.send("%s\n\r" % re.sub(RE_COLOR, '', msg).strip())
        client.message = message
            
        client.ip = self.client_address[0]

        self.processor = TelnetCommandProcessor(self)
        self._displayMOTD()
        self.request.send("type 'help' to have a list of available commands\n\r")


    def onClientAuthenticationFailed(self):
        if self.client_address[0] != '127.0.0.1':
            self.request.send("your are banned\n\r")
            self.server.ban(self.client_address[0])
        raise TelnetCloseSession("Too many tries")

    def finish(self):
        self.server.plugin.telnetClients.disconnect(self.client)

    def _displayMOTD(self):
        plugin = self.server.plugin
        try:
            motd_file = plugin.config.getpath('general_preferences', 'motd')
            if not os.path.isfile(motd_file):
                plugin.warning("Could not find MOTD file at %s" % motd_file)
                return
            with open(motd_file, 'r') as f:
                for line in f:
                    self.request.send(line.rstrip() + "\n\r")
        except NoOptionError:
            pass

class TelnetCloseSession(Exception):
    pass

class TelnetLineProcessor(object):
    def __init__(self, request_handler):
        self.request_handler = request_handler
        self.plugin = request_handler.server.plugin
        self.server = request_handler.server
        self.request = request_handler.request
    
    def process(self, line):
        """act upon a line received from the telnet client.
        
        Should raise a TelnetCloseSession Exception to close the session with
        the current telnet client
        """
        raise NotImplementedError

class TelnetAuthProcessor(TelnetLineProcessor):
    """line processor responsible for obtaining a Client object from a
    user id or login and a user password.
    
    On success, send the client object to request_handler.onClientAuthenticated
    or After 3 failed attempts, call request_handler.onClientAuthenticationFailed
    """
    userid = None
    password_retries = 0

    def process(self, line):
        if self.userid is None:
            self._get_user_id(line)
        else:
            self._get_password(line)

    def _get_password(self, line):
        client = self._fetch_client(line)
        if client:
            self.request_handler.onClientAuthenticated(client) 
        else:
            self.userid = None
            self.password_retries += 1
            if self.password_retries < 3:
                time.sleep(2)
                self.request.send("bad user id or password\n\r")
                self.request.send("user id : ")
            else:
                self.request_handler.onClientAuthenticationFailed()


    def _get_user_id(self, line):
        if line != '':
            self.userid = line
            self.request.send("password : ")
        else:
            self.request.send("user id : ")


    def _fetch_client(self, password):
        client = None
        
        clientMatcher = {'password': password}
        try:
            clientMatcher['id'] = int(self.userid)
        except ValueError:
            clientMatcher['login'] = self.userid
        
        results = self.plugin.console.storage.getClientsMatching(clientMatcher)
        if len(results)==1:
            client = results[0]
        return client


class TelnetCommandProcessor(TelnetLineProcessor):
    help = """available commands :
  /quit, quit      : terminate the telnet session
  /whoami          : display your name
  /name <new name> : change your name
  /who             : list current telnet sessions 
  /bans            : list current telnet bans 
  !<b3_command>    : execute a b3 command

anything that is not a recognized command will be broadcasted to the game server chat
"""

    def __init__(self, request_handler):
        TelnetLineProcessor.__init__(self, request_handler)
        self.client = request_handler.client
    
    def process(self, line):
        """Process a command"""
        if line == '':
            return        
        self.plugin.console.console("%s\t: %s", self.client.cid, line)
        args = line.split(' ', 1)
        command = args[0].strip().lower()
        if len(args)>1:
            arg = args[1]
        else:
            arg = ''
            
        cmd_funcname = 'cmd_' + command[1:]
        if command == 'help':
            return self.cmd_help(arg)
        elif command == 'quit':
            return self.cmd_quit(arg)
        elif command[0] == '/' and hasattr(self, cmd_funcname):
            func = getattr(self, cmd_funcname)
            return func(arg)
        elif command == '!iamgod':
            self.client.message("There is no god down here")
        elif line[0] in ('!','#'):
            adminPlugin = self.plugin.console.getPlugin('admin')
            adminPlugin.OnSay(self.plugin.console.getEvent('EVT_CLIENT_PRIVATE_SAY', line, self.client))
        else:
            self.plugin.console.say("[%s] %s" %(self.client.name, line))

    def cmd_help(self, arg):
        self.client.message("\n\r".join(self.help.split("\n")))
        
    def cmd_quit(self, arg):
        self.client.message('OK, SEE YOU LATER')
        raise TelnetCloseSession()
        
    def cmd_whoami(self, arg):
        self.client.message("@%s \"%s\" %s [%s]" % (
                                                     self.client.id,
                                                     self.client.name,
                                                     self.client.cid,
                                                     self.client.maxGroup.name                                                     
                                                     ))
        
    def cmd_name(self, arg):
        newname = arg.strip()
        if len(newname)<2:
            self.client.message("new name is too short")
        else:
            self.client.name = newname
        
    def cmd_who(self, arg):
        for sid, client in self.plugin.telnetClients.iteritems():
            if client:
                tmp = datetime.now() - client.connection_datetime
                since = timedelta(seconds=int(tmp.total_seconds()))
                data = {
                    'sid': sid,
                    'id': client.id,
                    'name': client.name,
                    'group': client.maxGroup.name,
                    'ip': client.session.client_address[0],
                    'port': client.session.client_address[1],
                    'since': since,
                }
                self.client.message("[%(sid)s] @%(id)s \"%(name)s\" (%(group)s) from %(ip)s:%(port)s since %(since)s" % data)
        
    def cmd_bans(self, arg):
        if len(self.server.banlist)==0:
            self.client.message("no active ban")
        else:
            for ip, timestamp in self.server.banlist.iteritems():
                delta = datetime.fromtimestamp(timestamp) - datetime.now()
                delta_rounded = timedelta(seconds=int(delta.total_seconds()))
                self.client.message("%s banned for %s" % (ip, delta_rounded))
        
        
        
if __name__ == '__main__':
    from b3.fake import joe, moderator, superadmin, fakeConsole
    
    #from b3.storage.database import DatabaseStorage
    #fakeConsole.storage =  DatabaseStorage("sqlite://c:/tmp/b3.sqlite", fakeConsole)
    
    conf1 = b3.config.XmlConfigParser()
    conf1.loadFromString("""<configuration plugin="telnet">
    <settings name="general_preferences">
        
        <!-- The ip the telnet service will be listening on. If not set, B3
        will listen on all available network interfaces -->
        <set name="ip"></set>
        
        <!-- The port the telnet service will be listening on. If not set, B3
        will listen on all available network interfaces -->
        <set name="port">27111</set>
        
        <!-- specify a Message Of The Day file that content will be displayed
        to authenticated users -->
        <set name="motd">c:/tmp/telnet_motd.txt</set>
    </settings>
    <settings name="commands">
        <set name="telnetkick-tkick">80</set>
        <set name="telnetlist-tlist">20</set>
    </settings>
</configuration>
""")
    
    from b3.querybuilder import QueryBuilder
    from getopt import getopt
    server_ip = server_port = None
    opts, args = getopt(sys.argv[1:], 'h:p:')
    for k, v in opts:
        if k == '-h':
            server_ip = v
        elif k == '-p':
            server_port = int(v)
    
    p = TelnetPlugin(fakeConsole, conf1)
    if server_port: p.telnetPort = server_port 
    if server_ip: p.telnetIp = server_ip 
    p.onStartup()

    joe.connects(0)
    fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'login': 'iamjoe', 'password': 'pass'}, 'clients', { 'id' : joe.id }))
    print "Joe id : %s" % joe.id
    
    moderator.connects(1)
    fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'password': 'test'}, 'clients', { 'id' : moderator.id }))
    print "Moderator id : %s" % moderator.id
    
    superadmin.auth()
    fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'password': 'test'}, 'clients', { 'id' : superadmin.id }))
    print "superadmin id : %s" % superadmin.id
    
    
    time.sleep(10)
    joe.says("what's up ?")
    time.sleep(5)
    moderator.says("having a beer and you ?")
    while True: pass
    