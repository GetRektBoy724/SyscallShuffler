# SyscallShuffler
SyscallShuffler is like a vaccine for your NTDLL so it will immune from modern direct syscall methods like [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), [FreshyCalls](https://github.com/crummie5/FreshyCalls) and [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md)/[Tartarus Gate](https://github.com/trickster0/TartarusGate/) (will not be immune if you dont hook the APIs at runtime for Halo's Gate/Tartarus Gate). What SyscallShuffler do is shuffling the position of NT* functions in memory, so the syscall ID doesnt corresponds with the position of the function in memory, which will make methods that get the syscall ID from sorting the position in memory get the wrong syscall ID. For now, SyscallShuffler can only make a "vaccinated" NTDLL from disk, and cant do it on runtime. **The NTDLL modified by SyscallShuffler doesnt have a valid checksum yet! Expect a BSOD when you try to boot a Windows with that. Contribution is really appreciated.**

# Demonstration
### SysWhispers2 and FreshyCalls method demonstration (using [SysGate](https://github.com/GetRektBoy724/SysGate))
https://user-images.githubusercontent.com/41237415/161262430-edaf42ef-83a7-4b9a-928b-1decbb9f567c.mp4

So the reason the NTAVM call output returns InvalidParameter on the second test is not because the parameter is wrong, but because it calls the wrong syscall, which doesnt match the parameter with NTAVM's parameter, causing InvalidParameter. Hence, the NTDLL is immune from this technique.

### Halo's Gate/Tartarus Gate method demonstration (using [SharpHalos](https://github.com/GetRektBoy724/SharpHalos))
https://user-images.githubusercontent.com/41237415/161800615-0ffdbc6f-b374-4dc2-b50b-b0527db95dad.mp4

The result is really different compared with the SysWhispers2 and FreshyCalls method demonstration. As I said before, the NTDLL will not be immune if you dont hook the APIs at runtime. So the reason that the Halo's Gate/Tartarus Gate method successfully used the syscalls from the modified NTDLL is because the APIs inside the NTDLL aren't hooked, Halo's Gate/Tartarus Gate only walks through the memory "neighbours" when the wanted API is hooked, but because it isn't hooked, the method successfully got the syscall ID and used it. As I said before, the NTDLL will not be immune if you dont hook the APIs at runtime.
