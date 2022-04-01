# SyscallShuffler
SyscallShuffler is like a vaccine for your NTDLL so it will immune from modern direct syscall methods like [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2), [FreshyCalls](https://github.com/crummie5/FreshyCalls) and [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md)/[Tartarus Gate](https://github.com/trickster0/TartarusGate/). What SyscallShuffler do is shuffling the position of NT* functions in memory, so the syscall ID doesnt corresponds with the position of the function in memory, which will make methods that get the syscall ID from sorting the position in memory get the wrong syscall ID. For now, SyscallShuffler can only make a "vaccinated" NTDLL from disk, and cant do it on runtime. **The NTDLL modified by SyscallShuffler is not good yet! Expect a BSOD when you try to boot a Windows with that.**

# Demonstration
https://user-images.githubusercontent.com/41237415/161262430-edaf42ef-83a7-4b9a-928b-1decbb9f567c.mp4

So the reason the NTAVM call output returns InvalidParameter on the second test is not because the parameter is wrong, but because it calls the wrong syscall, which doesnt match the parameter with NTAVM's parameter, causing InvalidParameter. Hence, the NTDLL is immune from this technique.
