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
# 1.4 - 2011-06-10
#    * properly decode telnet packets
#    * assume password are hashed through md5 in db
# 1.4.1 - 2011-06-11
#    * when running the test, Ctrl-C properly ends the script
# 1.4.2 - 2011-06-22
#    * better handling of B3 shutdown/restart
# 1.4.3 - 2011-07-03
#    * fix connection timeout issue
# 1.4.4 - 2011-07-04
#    * do not fail with gethostbyaddr
#
__version__ = '1.4.4'
__author__    = 'Courgette'

from ConfigParser import NoOptionError
from b3.clients import Client
from datetime import datetime, timedelta
from telnet.telnetserver import TelnetServiceThread
import b3
import b3.events
import b3.plugin
import os
import re
import sys
import thread
import time



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
                           'EVT_GAME_ROUND_START', 'EVT_GAME_MAP_CHANGE',
                           'EVT_STOP', 'EVT_EXIT')
        
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
        if event.type in self.forwarded_events:
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
                return None
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
        if not client:
            return
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
        if event.type in (b3.events.eventManager.getId('EVT_EXIT'), 
                  b3.events.eventManager.getId('EVT_STOP')):
            client.disconnect()
        elif event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAY'):
            client.message("  console: %s" % event.data)
        elif event.type == b3.events.eventManager.getId('EVT_CONSOLE_SAYBIG'):
            client.message("  CONSOLE: %s" % event.data)
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_CONNECT'):
            client.message("  client connection : %s" % event.client)
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_DISCONNECT'):
            client.message("  client disconnection : %s" % event.data)
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_NAME_CHANGE'):
            client.message("  %s renamed to %s" % (event.client, event.data))
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_KICK'):
            client.message("  %s kicked (%r)" % (event.client, event.data))
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN'):
            client.message("  %s banned (%r)" % (event.client, event.data))
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_BAN_TEMP'):
            client.message("  %s tempbanned (%r)" % (event.client, event.data))
        elif event.type == b3.events.eventManager.getId('EVT_CLIENT_UNBAN'):
            client.message("  %s unbanned (%r)" % (event.client, event.data))
        elif event.type == b3.events.eventManager.getId('EVT_GAME_ROUND_START'):
            client.message("  round started %s" % event.data)
        elif event.type == b3.events.eventManager.getId('EVT_GAME_MAP_CHANGE'):
            client.message("  map change %s" % event.data)

        
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
    
    from hashlib import md5
    from b3.querybuilder import QueryBuilder
    from getopt import getopt
    server_ip = server_port = None
    opts, args = getopt(sys.argv[1:], 'h:p:')
    for k, v in opts:
        if k == '-h':
            server_ip = v
        elif k == '-p':
            server_port = int(v)
    
    try:
        p = TelnetPlugin(fakeConsole, conf1)
        if server_port: p.telnetPort = server_port 
        if server_ip: p.telnetIp = server_ip 
        p.onStartup()

        joe.connects(0)
        fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'login': 'iamjoe', 'password': md5('test').hexdigest()}, 'clients', { 'id' : joe.id }))
        print "Joe id : %s" % joe.id

        moderator.connects(1)
        fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'password': md5('test').hexdigest()}, 'clients', { 'id' : moderator.id }))
        print "Moderator id : %s" % moderator.id

        superadmin.auth()
        fakeConsole.storage.query(QueryBuilder(fakeConsole.storage.db).UpdateQuery({'password': md5('test').hexdigest(), 'login': 'superadmin'}, 'clients', { 'id' : superadmin.id }))
        print "superadmin id : %s" % superadmin.id


        time.sleep(10)
        joe.says("what's up ?")
        time.sleep(5)
        moderator.says("having a beer and you ?")
        while True: 
            pass
    except KeyboardInterrupt:
        p.telnetService.stop()
    print "*"*30