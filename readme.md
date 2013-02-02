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

 * copy the telnet folder into b3/extplugins
 * copy plugin_telnet.ini in the same directory as the one your b3.xml file is in
 * update your main b3 config file with :

<plugin name="telnet" config="@conf/plugin_telnet.ini"/>


Usage
-----


### Setting up an account

You must create a B3 account in your B3 database. This can be done using phpmyadmin or the
[password plugin](https://github.com/xlr8or/b3-plugin-password).
Using phpmyadmin, you need to fill the columns 'login' and 'password' in the _clients_ table for your user (password
must be encrypted with the MD5 algorithm).


### Connecting

Use your favorite telnet client and connect to the ip of the host B3 is running on and at the port you set in the
telnet plugin config file.
You will then be prompted for your login and password.



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

1.4.1 - 2011-06-11
  * when running the test, Ctrl-C properly ends the script

1.4.2 - 2011-06-22
  * better handling of B3 shutdown/restart

1.4.3 - 2011-07-03
  * fix connection timeout issue
  
1.4.4 - 2011-07-04
  * do not fail with gethostbyaddr
  
1.5.0 - 2011-07-05
  * add telnet command /chat <on|off>

1.6.0 - 2011-11-05
  * fix issues related to the use of !die and !restart

1.7.0 - 2012-09-12
  * handle unicode data from B3 events data

1.7.1 - 2013-02-02
  * fix minor bugs when reacting to B3 shutdown events
  * change default config file from _xml_ to _ini_ format


Support
-------

http://forum.bigbrotherbot.net/plugins-by-courgette/telnet-plugin/
