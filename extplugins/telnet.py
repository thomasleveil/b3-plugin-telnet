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
#
__version__ = '1.2'
__author__    = 'Courgette'
from ConfigParser import NoOptionError, ConfigParser
from b3.clients import Client
from datetime import datetime, timedelta
import SocketServer
import b3
import b3.events
import b3.plugin
import logging
import os
import re
import select
import socket
import sys
import thread
import threading
import time
import traceback


TELNET_QUIT = object()
TELNET_AUTHENTICATED = object()
TELNET_BANTIME_SECONDS = 60*2
RE_COLOR = re.compile(r'(\^[0-9])')
#--------------------------------------------------------------------------------------------------
class TelnetPlugin(b3.plugin.Plugin):
    client = None
    telnetIp = None
    telnetPort = None
    telnetService = None
    telnetGroup = None
    _telnetSessionsID = 0
    telnetSessions = {}
    
    def onLoadConfig(self):
        # get the admin plugin so we can register commands
        self._adminPlugin = self.console.getPlugin('admin')
        if not self._adminPlugin:
            # something is wrong, can't start without admin plugin
            self.error('Could not find admin plugin')
            self.disable()
            return
        
        # credit : http://passwordadvisor.com/CodePython.aspx
        strength = ['Blank','Very Weak','Weak','Medium','Strong','Very Strong']
        def checkPassword(password):
            score = 1
        
            if len(password) < 1:
                return 0
            
            if password.lower() in ('changethis', 'pass', 'password', 'test', 
                                    '123', '1234', '12345', '123456', '1324567', 
                                    '13245678', '132456789', 'iloveyou', 
                                    'princess', 'rockyou', 'abc123', '123abc', 
                                    'qwerty', 'azerty', 'monkey' ):
                return 1
            
            if len(password) < 4:
                return 1
        
            if len(password) >=8:
                score = score + 1
            if len(password) >=11:
                score = score + 1
            
            if re.search('\d+',password):
                score = score + 1
            if re.search('[a-z]',password) and re.search('[A-Z]',password):
                score = score + 1
            if re.search('.[!,@,#,$,%,^,&,*,?,_,~,-,�,(,)]',password):
                score = score + 1
        
            return score
                
        
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
            tmp = self.config.get('general_preferences', 'admin_level')
            self.telnetGroup = self.console.storage.getGroup(b3.clients.Group(keyword=tmp))
        except KeyError, err:
            self.allGoodToStart = False
            self.error('invalid group %s. Pick on of : guest, user, reg, mod, admin, fulladmin, senioradmin, superadmin.' % tmp)
        except NoOptionError:
            self.info('no admin_level found in the general_preferences section of the config file. using default : moderator')
        if self.telnetGroup is None:
            self.telnetGroup = self.console.storage.getGroup(b3.clients.Group(keyword='mod'))
        self.info("Telnet admins will have group : %s (%s)" % (self.telnetGroup.name, self.telnetGroup.level))
            
        try:
            self.telnetPort = self.config.getint('general_preferences', 'port')
        except ValueError:
            self.allGoodToStart = False
            self.error('The port value found in the general_preferences section of the config file must be a number')
        except NoOptionError:
            self.allGoodToStart = False
            self.error('no port found in the general_preferences section of the config file. You need to set the port for the Telnet plugin to work')
            
        try:
            self.telnetPassword = self.config.get('general_preferences', 'password')
            score = checkPassword(self.telnetPassword)
            if score < 3:
                self.allGoodToStart = False                
                self.error("your Telnet password is strength is : %s. Choose a stronger one" % strength[score])
        except NoOptionError:
            self.allGoodToStart = False                
            self.error('no password found in the general_preferences section of the config file. You need to set the password for the Telnet plugin to work')

        if not self.allGoodToStart:
            self.disable()
            


    def onStartup(self):
        if not self.allGoodToStart:
            self.info("Not starting Telnet service")
            return
        
        
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
            self.debug("----------------> %s" % msg)
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

    def addTelnetSession(self, listener):
        if not listener in self.telnetSessions:
            self._telnetSessionsID += 1
            self.telnetSessions[self._telnetSessionsID] = listener
    
    def removeTelnetSession(self, listener):
        for k in self.telnetSessions.keys():
            if self.telnetSessions[k] is listener:
                del self.telnetSessions[k]

    def _dispatchEvent(self, event):
        try:
            for k in self.telnetSessions.keys():
                self.telnetSessions[k].onB3Event(event)
        except:
            self.exception(sys.exc_info())


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
    authed = False

    def setup(self):
        plugin = self.server.plugin
        plugin.info("telnet client connecting from %s:%s" % self.client_address)
        plugin.info("%r", socket.gethostbyaddr(self.client_address[0]))
        
        plugin.addTelnetSession(self)
        
        self.client = plugin.console.clients.newClient(cid="(%s:%s)" % self.client_address, name="remote admin (%s:%s)" % self.client_address, groupBits=0, hide=True)
        self.client.connection_datetime = datetime.now()
        
        # change Client.message() method so any message B3 would like to be
        # sent to that fake client as PM is redirected to this telnet session.
        # Also remove Quake3 color codes
        def message(msg):
            self.request.send("%s\n\r" % re.sub(RE_COLOR, '', msg).strip())
        self.client.message = message
        
        self.password_retries = 0
        

    def handle(self):
        plugin = self.server.plugin

        self.request.send("HELLO from B3 Telnet plugin v%s\n\r" % __version__)
        self.request.send("enter your password: ")
        
        processor = TelnetCommandProcessor(plugin, self.client, self.server)
        ready_to_read, ready_to_write, in_error = select.select([self.request], [], [], None)
        text = ''
        try:
            done = False
            while not done:
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
                                result = processor.process(line, self.request)
                            except:
                                for line in traceback.format_exc().splitlines():
                                    self.request.send(line + "\n\r")

                            if result == TELNET_QUIT:
                                done = True
                                break
                            elif result == TELNET_AUTHENTICATED:
                                self.client.authed = True # make B3 believe this client is authenticated so it can issue commands
                                self.client.groupBits = plugin.telnetGroup.id
                                self.authed = True
                                processor = TelnetAuthenticatedCommandProcessor(plugin, self.client, self.server)
                                self._displayMOTD()
                                self.request.send("type 'help' to have a list of available commands\n\r")
                            elif not self.authed:
                                self.password_retries += 1
                                if self.password_retries < 3:
                                    time.sleep(2)
                                    self.request.send("enter your password: ")
                                else:
                                    if self.client_address[0] != '127.0.0.1':
                                        self.request.send("your are banned\n\r")
                                        self.server.ban(self.client_address[0])
                                    self.request.close()
        
        except socket.timeout:
            pass
        self.request.close()
        self.client.disconnect()


    def onB3Event(self, event):
        if not self.authed:
            return
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_SAY'):
            self.client.message("  %s: %s" % (event.client.name, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAY'):
            self.client.message("  console: %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAYBIG'):
            self.client.message("  CONSOLE: %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_CONNECT'):
            self.client.message("  client connection : %s" % event.client)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_DISCONNECT'):
            self.client.message("  client disconnection : %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_NAME_CHANGE'):
            self.client.message("  %s renamed to %s" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_KICK'):
            self.client.message("  %s kicked (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN'):
            self.client.message("  %s banned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN_TEMP'):
            self.client.message("  %s tempbanned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_CLIENT_UNBAN'):
            self.client.message("  %s unbanned (%r)" % (event.client, event.data))
        if event.type == b3.events.eventManager.getId('EVT_GAME_ROUND_START'):
            self.client.message("  round started %s" % event.data)
        if event.type == b3.events.eventManager.getId('EVT_GAME_MAP_CHANGE'):
            self.client.message("  map change %s" % event.data)
            

    def finish(self):
       self.server.plugin.removeTelnetSession(self)

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

class TelnetCommandProcessor(object):
    def __init__(self, plugin, client, server):
        self.server = server
        self.plugin = plugin
        self.client = client
        
    def process(self, line, request):
        """Process a command"""
        if line == self.plugin.telnetPassword:
            request.send('\n\rauthenticated\n\r')
            return TELNET_AUTHENTICATED
            
class TelnetAuthenticatedCommandProcessor(TelnetCommandProcessor):
    help = """available commands :
  /quit, quit      : terminate the telnet session
  /whoami          : display your name
  /name <new name> : change your name
  /who             : list current telnet sessions 
  /bans            : list current telnet bans 
  !<b3_command>    : execute a b3 command

anything that is not a recognized command will be broadcasted to the game server chat
"""

    def process(self, line, request):
        """Process a command"""
        if line == '':
            return        
        self.plugin.console.console(line)
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
        elif line[0] in ('!','#'):
            adminPlugin = self.plugin.console.getPlugin('admin')
            adminPlugin.OnSay(self.plugin.console.getEvent('EVT_CLIENT_PRIVATE_SAY', line, self.client))
        else:
            self.plugin.console.say("[%s] %s" %(self.client.name, line))

    def cmd_help(self, arg):
        self.client.message("\n\r".join(self.help.split("\n")))
        
    def cmd_quit(self, arg):
        self.client.message('OK, SEE YOU LATER')
        return TELNET_QUIT
        
    def cmd_whoami(self, arg):
        self.client.message(self.client.name)
        
    def cmd_name(self, arg):
        newname = arg.strip()
        if len(newname)<2:
            self.client.message("new name is too short")
        else:
            self.client.name = newname
        
    def cmd_who(self, arg):
        for sid, session in self.plugin.telnetSessions.iteritems():
            if session.client:
                tmp = datetime.now() - self.client.connection_datetime
                since = timedelta(seconds=int(tmp.total_seconds()))
                data = {
                    'sid': sid,
                    'name': session.client.name,
                    'group': session.client.maxGroup.name if session.client.authed else 'non authenticated',
                    'ip': session.client_address[0],
                    'port': session.client_address[1],
                    'since': since,
                }
                self.client.message("[%(sid)s] \"%(name)s\" (%(group)s) from %(ip)s:%(port)s since %(since)s" % data)
            else:
                self.client.message("[%s] %s:%s" % (sid, session.client_address[0], session.client_address[1]))
        
    def cmd_bans(self, arg):
        if len(self.server.banlist)==0:
            self.client.message("no active ban")
        else:
            for ip, timestamp in self.server.banlist.iteritems():
                delta = datetime.fromtimestamp(timestamp) - datetime.now()
                delta_rounded = timedelta(seconds=int(delta.total_seconds()))
                self.client.message("%s banned for %s" % (ip, delta_rounded))
        
        
        
if __name__ == '__main__':
    from b3.fake import fakeConsole, joe, moderator
    conf1 = b3.config.XmlConfigParser()
    conf1.loadFromString("""<configuration plugin="telnet">
    <settings name="general_preferences">
        
        <!-- The ip the telnet service will be listening on. If not set, B3
        will listen on all available network interfaces -->
        <set name="ip"></set>
        
        <!-- The port the telnet service will be listening on. If not set, B3
        will listen on all available network interfaces -->
        <set name="port">27111</set>
        
        <!-- The password to use the telnet service -->
    <set name="password">321321321</set>
        
        <!-- The B3 group tha telnet admins belong to. 
        Specify the group keyword : 
              guest, user, reg, mod, admin, fulladmin, senioradmin, superadmin -->
        <set name="admin_level">superadmin</set> 
           
        <!-- specify a Message Of The Day file that content will be displayed
        to authenticated users -->
        <set name="motd">c:/tmp/telnet_motd.txt</set>
    </settings>
</configuration>
""")
    
    p = TelnetPlugin(fakeConsole, conf1)
    p.onStartup()

    joe.connects(0)
    moderator.connects(1)
    
    time.sleep(10)
    joe.says("what's up ?")
    time.sleep(5)
    moderator.says("having a beer and you ?")
    while True: pass
    