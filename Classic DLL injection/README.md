# Classic DLL injection
Write the path of a dll that resides on disk into a target process's
memory and call LoadLibrary() with it as the parameter.


A simple way to test this is to write a dll with a dllmain function that
prints a message to the console on DLL\_PROCESS\_ATTACH and inject this
into your target console application mentioned in the repo readme.
