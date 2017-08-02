# Windows Process Injection
Some simple and unoriginal process injection techniques targeting the Windows platform


Based off the first four entries in [this Endgame blogpost](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
which provides good background on the following techniques:
1. __Classic DLL injection__
2. __PE injection__
3. __Process hollowing__
4. __Thread hijacking__


Written in C, error handling has been removed for brevity.
Uses documented WinAPI functions where possible for simplicity, as opposed
to more esoteric ones favoured by malware authors.
Tested using Visual Studio 2017 on Windows 10 Pro v1703 build 15063.483


A quick way to test these techniques out is to write a small console
application that prints a message every 5 seconds to ensure it hasn't
crashed. Use this as your injection target.


_For educational purposes only e.t.c._
