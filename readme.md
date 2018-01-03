PyTS3Bot
========

This is a basic Python 3 implementation of the TeamSpeak 3 Client (**not** ServerQuery) protocol.
It can be used to implement own resource-efficient, headless and platform-independent TS3 bots for various purposes. Check out [Splamy/TS3AudioBot](https://github.com/Splamy/TS3AudioBot/blob/master/TS3Client/ts3protocol.md) to learn more about the TS3 protocol.

## 0. Requirements ##

    pip3 install pyasn1
    pip3 install pycryptodome
    pip3 install fastecdsa

Note: The script was only tested on Linux so far, but it *should* be platform-independent.


## 1. Generate identity ##
Before joining a TS3 server you first need to generate an ECDSA identity. You can use the script `identity.py` to do that. 
Simply run `./identity.py` or `python3 identity.py` . The script will generate a new key pair and immediately print a Python binary string representing the private key. Example:

    b'\x07\x1f\x9e\x89,\xa0\x92r\xa7\xf4a3SE\xbe\x99gJ\x96\xb4\xb2\x93\xe3\x15C\x19i\xcc\xfe\xb2\x89#'

Copy and save this string for later use. The script will now automatically start to increase the security level.  Each time a new security level is reached, it is printed to the console. Example:

    new security level: 23 at 5887856
    new security level: 25 at 10297620
    new security level: 27 at 31805735
Once your desired security level is reached, you can simply terminate the script and copy the corresponding offset (in this example: 31805735).

If you want to further increase the security level at a later point, uncomment line 17 in the `identity.py` script and paste both your private key and your last valid offset as follows:

    key = ecdsa.SigningKey.from_string(b'\x07\x1f\x9e\x89,\xa0\x92r\xa7\xf4a3SE\xbe\x99gJ\x96\xb4\xb2\x93\xe3\x15C\x19i\xcc\xfe\xb2\x89#', curve=curve)
	keyoffset  = 31805735

Then, run the script again as explained above.

## 2. Run the bot ##
The following snippet (see file `pyts3bot-example.py`) will connect the bot to a TS3 server:

    from pyts3bot import Identity, TS3Client
    
    # Insert your key string and key offset here
    
    i = Identity(privkey=b'\x07\x1f\x9e\x89,\xa0\x92r\xa7\xf4a3SE\xbe\x99gJ\x96\xb4\xb2\x93\xe3\x15C\x19i\xcc\xfe\xb2\x89#'
    , keyoffset=31805735)
    #                       TS IP            Port    Nickname
    client = TS3Client(i, 'xxx.xxx.xxx.xxx', 9987, b'yournickname')
    client.connect()
    
    # Start interactive command-line mode
    client.interactive(verbose=True)
    # or alternatively: do whatever you want...


Assign your private key and key offset generated in step 1 to the `Identity` and set IP, port and nickname.
In this example, we start interactive mode.

### Interactive mode ###
Calling `client.interactive(verbose=True)` will start the interactive mode. This allows you to enter commands into your console which are then sent directly to the TS server. The server's reply is then printed to the console (unless you set `verbose=False`). This might help you extending the bot to fit your needs or to do some experiments.

There is no official documentation of all possible commands. A very rich list of commands with short explanations (in German, though) can be found at http://yat.qa/ressourcen/voice-client-anti-flood/.  Furthermore, you can use [ReSpeak/TS3Hook](https://github.com/ReSpeak/TS3Hook) to analyse the commands sent by the official client. A lot of the commands are identical to the ServerQuery commands which you can find in the [TS Server Query Manual](http://media.teamspeak.com/ts3_literature/TeamSpeak%203%20Server%20Query%20Manual.pdf). 

###  Reading client list and channel list ###
After connecting, you can get the client list and channel list as an array of dicts using `client.channelList` and `client.clientList`.  

### Moving the bot to a channel ###
`client.moveto(cid)` will move the bot to the channel with id `cid`.

### Disconnect the bot ###
Call `client.disconnect()`.
