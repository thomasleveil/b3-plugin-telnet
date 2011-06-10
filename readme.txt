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

1.0 - 2011-06-08
  * first release
  
1.1 - 2011-06-08
  * add message of the day
  * resolve ip to domain name upon connection

1.2 - 2011-06-09
  * refactor TelnetAuthenticatedCommandProcessor so it is easier to add new commands
  * add /who /name

1.3 - 2011-06-09
  * refactor
  * now telnet users authenticate using their B3 account (password must be set) 
    use phpmyadmin or the password plugin : https://github.com/xlr8or/b3-plugin-password
  * add commands !tlist and !tkick

1.4 - 2011-06-10
  * properly decode telnet packets
  * assume password are hashed through md5 in db



Support
-------

http://forum.bigbrotherbot.net/plugins-by-courgette/telnet-plugin/
