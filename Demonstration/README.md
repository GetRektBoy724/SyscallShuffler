# Demonstration

video here

So the reason the NTAVM call output returns InvalidParameter on the second test is not because the parameter is wrong, but because it calls the wrong syscall, which doesnt match the parameter with NTAVM's parameter, causing InvalidParameter. Which means, the NTDLL is immune from this technique.
