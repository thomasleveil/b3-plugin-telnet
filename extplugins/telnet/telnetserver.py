# encoding: utf-8
#
# Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
# Copyright (C) 2011 courgette@bigbrotherbot.net
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
from . import __version__
from ConfigParser import NoOptionError
from datetime import datetime, timedelta
import dpkt
import SocketServer
import os
import re
import select
import socket
import threading
import time
import traceback
from hashlib import md5



TELNET_BANTIME_SECONDS = 60*2
RE_COLOR = re.compile(r'(\^[0-9])')

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
        buffer = ''
        try:
            while self.working:
                if len(ready_to_read) == 1 and ready_to_read[0] == self.request:
                    data = self.request.recv(1024)
        
                    if not data:
                        break
                    elif len(data) > 0:
                        buffer += str(data)
        
                        while buffer.find("\n") != -1:
                            line, buffer = buffer.split("\n", 1)
                            line = line.rstrip()
                            lines, options = dpkt.telnet.strip_options(line)
                            plugin.info("options : %r" % options)
                            for l in lines:
                                try:
                                    self.processor.process(l)
                                except TelnetCloseSession:
                                    self.working = False
                                except:
                                    lines = traceback.format_exc().splitlines()
                                    self.request.send(lines[-1] + "\n\r")
                                    plugin.error("%s", lines)
        
        except socket.timeout:
            plugin.info("socket timeout")
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
        
        clientMatcher = {'password': md5(password).hexdigest()}
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
        
        

    