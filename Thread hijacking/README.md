# Thread hijacking
Suspend a thread in a remote process, allocate some space to inject
shellcode then change the thread's context to run your code. Also known as SIR (Suspend, Inject, Resume). Attempts
to recover normal thread operation once shellcode has run.
Operates on the first thread it comes across in the target process.
Should print the text "Success" to the console of the target application.


Some code adapted from [OpenSecurityResearch's dllinjector](https://github.com/OpenSecurityResearch/dllinjector/blob/master/src/ExecThread.cpp)
