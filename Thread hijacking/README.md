# Thread hijacking
Suspend a thread in a remote process, allocate some space to inject
shellcode then change the thread's context to run your code. Attempts
to recover normal thread operation once shellcode has run.

Some code adapted from [OpenSecurityResearch's dllinjector](https://github.com/OpenSecurityResearch/dllinjector/blob/master/src/ExecThread.cpp)
