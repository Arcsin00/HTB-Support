# BehindTheScenes
Challenge Name: The Last Dance
------------------------------

*   **Status:** Active
*   **Category:** Reversing
*   **Difficulty:** Very Easy
*   **Date Owned:** 6/16/2023
*   Description:

> After struggling to secure our secret strings for a long time, we finally figured out the solution to our problem: Make decompilation harder. It should now be impossible to figure out how our programs work!

<br>

File Review
-----------

The file provided is an ELF (Executable and Linkable Format) file which is a common type of executable for linux platforms.

First test the program to see what happens.

```text-plain
./behindthescenes                  
./challenge <password>
```

Looks like its requesting a password as an argument.

Next use strings which is a tool that pulls text strings out of an executable file. 

```text-plain
strings ./behindthescenes 
/lib64/ld-linux-x86-64.so.2
libc.so.6
strncmp
puts
__stack_chk_fail
printf
strlen
sigemptyset
memset
sigaction
__cxa_finalize
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
./challenge <password>
> HTB{%s}
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

The command line I/O prompt is listed here './challenege <password> and the line below it looks like the format of a flag.

Open the file in Ghidra and look for the same prompt string.

![](BehindTheScenes/image.png)

Under the prompt string there are lines that look like they did not decompile. At the end of the text values there are a few characters that spell out HTB{%s} vertically. In the list of strings the flag was the line after the prompt, maybe the characters between the prompt and flag is the password for the program!?

Providing this with whitespaces removed as the password when running the program returns the flag!

```text-plain
./behindthescenes Itz_0nLy_UD2  
> HTB{********************************}
```