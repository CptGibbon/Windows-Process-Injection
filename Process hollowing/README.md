# Process hollowing
Starts a new process, unmaps its contents and replaces it with a different
image. Mismatched subsystems (trying to replace a console application
with a GUI application) can cause weirdness.

Lots of code adapted from [m0n0ph1's C++ process hollowing example](https://github.com/m0n0ph1/Process-Hollowing)
