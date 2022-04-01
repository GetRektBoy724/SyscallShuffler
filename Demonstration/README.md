# Demonstration

https://user-images.githubusercontent.com/41237415/161262430-edaf42ef-83a7-4b9a-928b-1decbb9f567c.mp4

So the reason the NTAVM call output returns InvalidParameter on the second test is not because the parameter is wrong, but because it calls the wrong syscall, which doesnt match the parameter with NTAVM's parameter, causing InvalidParameter. Which means, the NTDLL is immune from this technique.
