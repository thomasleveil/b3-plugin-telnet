Telnet plugin for Big Brother Bot (www.bigbrotherbot.net)
=========================================================

By Courgette


Description
-----------

This plugin will make B3 act as a telnet server you can then connect to with
your favorite telnet client.
Once authenticated, you can see actions taking place on your game server (chat, 
kick, etc) and can talk back or issue B3 commands



Installation
------------

 * copy telnet.py into b3/extplugins
 * copy plugin_telnet.xml into b3/extplugins/conf
 * update your main b3 config file with :

<plugin name="telnet" config="@b3/extplugins/conf/plugin_telnet.xml"/>



Changelog
---------

2011-06-08 - 1.0
* first release
2011-06-08 - 1.1
* add message of the day
* resolve ip to domain name upon connection
2011-06-09 - 1.2
* refactor TelnetAuthenticatedCommandProcessor so it is easier to add new commands
* add /who /name



Support
-------

http://forum.bigbrotherbot.net/plugins-by-courgette/telnet-plugin/
