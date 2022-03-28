using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.IO;

public static class ListExtension {
    public static void ScrambleTheList<T>(this IList<T> list, Random rng)
    {
        int n = list.Count;  
        while (n > 1) {  
            n--;  
            int k = rng.Next(n + 1);  
            T value = list[k];  
            list[k] = list[n];  
            list[n] = value;  
        }  
    }
}

public class SyscallScrambler {
    
    public struct SyscallTableEntry {
        public string Name;
        public Int64 OriginalExportAddress;
        public IntPtr EATAddress;
        public byte[] Stub;
    }

    public static unsafe void Copy(IntPtr source, ref byte[] destination, int startIndex, int length) { // copy from unmanaged to managed
        if (source == IntPtr.Zero || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > destination.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of destination bytes!");
        }
        byte* TargetByte = (byte*)(source.ToPointer());
        int sourceIndex = 0;
        for (int targetIndex = startIndex; targetIndex < (startIndex + length); targetIndex++) {
            destination[targetIndex] = *(TargetByte + sourceIndex);
            sourceIndex++;
        }
    }

    public static void Main(string[] args) {
        if (args.Length != 2) {
            Console.WriteLine("Usage : {0} <source ntdll path> <new ntdll path>", Environment.GetCommandLineArgs()[0]);
            Console.WriteLine("Example : {0} C:\\Windows\\System32\\ntdll.dll .\\newntdll.dll", Environment.GetCommandLineArgs()[0]);
            return;
        }

        Console.WriteLine("SyscallShuffler v0.2 - By GetRektBoy724");
        Console.WriteLine("[*] Preparing and mapping the NTDLL...");
        List<SyscallTableEntry> FunctionList = new List<SyscallTableEntry>();
        List<Int64> AddressHolder = new List<Int64>();

        string ModuleFileName = args[0];
        byte[] ModuleRawByte = File.ReadAllBytes(ModuleFileName);
        // manually map the NTDLL
        int RegionSize = BitConverter.ToInt32(ModuleRawByte, (BitConverter.ToInt32(ModuleRawByte, (int)0x3C) + 0x18) + 56);
        int SizeOfHeaders = BitConverter.ToInt32(ModuleRawByte, (BitConverter.ToInt32(ModuleRawByte, (int)0x3C) + 0x18) + 60);
        IntPtr ModuleBase = Marshal.AllocHGlobal(RegionSize);
        
        Marshal.Copy(ModuleRawByte, 0, ModuleBase, SizeOfHeaders);
        IntPtr SectionHeaderBaseAddr = ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 0x18 + Marshal.ReadInt16((IntPtr)(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 20));
        Int16 NumberOfSections = Marshal.ReadInt16(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 6);
        for (int i = 0; i < NumberOfSections; i++) {
            IntPtr CurrentSectionHeaderAddr = SectionHeaderBaseAddr + (i * 40);
            Int32 CurrentSectionSize = Marshal.ReadInt32(CurrentSectionHeaderAddr + 8);
            Int32 CurrentSectionOffset = Marshal.ReadInt32(CurrentSectionHeaderAddr + 20);
            Int32 CurrentSectionRVA = Marshal.ReadInt32(CurrentSectionHeaderAddr + 12);
            Marshal.Copy(ModuleRawByte, CurrentSectionOffset, (IntPtr)(ModuleBase.ToInt64() + CurrentSectionRVA), CurrentSectionSize);
        }

        // Traverse the PE header in memory
        Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
        Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
        Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
        Int64 pExport = 0;
        if (Magic == 0x010b) {
            pExport = OptHeader + 0x60;
        }
        else {
            pExport = OptHeader + 0x70;
        }

        // Read -> IMAGE_EXPORT_DIRECTORY
        Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
        Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
        Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
        Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
        Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
        Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

        for (int i = 0; i < NumberOfNames; i++) {
            string CurrentFunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
            Int32 CurrentFunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
            Int32 CurrentFunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (CurrentFunctionOrdinal - OrdinalBase))));
            IntPtr CurrentFunctionPtr = (IntPtr)((Int64)ModuleBase + CurrentFunctionRVA);

            // collect all NT* functions and their addresses
            if (CurrentFunctionName.StartsWith("Nt") && !CurrentFunctionName.StartsWith("Ntdll") && CurrentFunctionName != "NtGetTickCount") {
                SyscallTableEntry currententrytable = new SyscallTableEntry();
                currententrytable.Name = CurrentFunctionName;
                currententrytable.OriginalExportAddress = (Int64)CurrentFunctionPtr;
                currententrytable.Stub = new byte[32];
                Copy(CurrentFunctionPtr, ref currententrytable.Stub, 0, 32);
                currententrytable.EATAddress = (IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (CurrentFunctionOrdinal - OrdinalBase)));
                FunctionList.Add(currententrytable);
                AddressHolder.Add((long)CurrentFunctionPtr);
            }
        }

        Console.WriteLine("[*] Shuffling the addresses...");
        // scramble the position
        Random rng = new Random();  
        AddressHolder.ScrambleTheList(rng);

        // check if there is any scrambled address that are the same with the original address
        while (true) {
            bool ClearToContinue = true;
            for (int i = 0; i < FunctionList.Count; i++) {
                if (FunctionList[i].OriginalExportAddress == AddressHolder[i]) {
                    AddressHolder.ScrambleTheList(rng);
                    ClearToContinue = false;
                    break;
                }
            }
            if (ClearToContinue)
                break;
        }

        Console.WriteLine("[*] Placing the syscall stubs to the new addresses...");
        // copy the function stubs to the randomized addresses
        for (int i = 0; i < FunctionList.Count; i++) {
            Marshal.Copy(FunctionList[i].Stub, 0, (IntPtr)AddressHolder[i], 32);
            Marshal.WriteInt32(FunctionList[i].EATAddress, (Int32)(AddressHolder[i] - (long)ModuleBase));
        }

        Console.WriteLine("[*] Unmapping and finishing...");
        // unmap it
        byte[] NewNTDLL = new byte[ModuleRawByte.Length];
        Marshal.Copy(ModuleBase, NewNTDLL, 0, SizeOfHeaders);

        for (int i = 0; i < NumberOfSections; i++) {
            IntPtr CurrentSectionHeaderAddr = SectionHeaderBaseAddr + (i * 40);
            Int32 CurrentSectionOffset = Marshal.ReadInt32(CurrentSectionHeaderAddr + 20);
            Int32 CurrentSectionRVA = Marshal.ReadInt32(CurrentSectionHeaderAddr + 12);
            Int32 CurrentSectionSize = 0;
            if (i == NumberOfSections - 1) {
                CurrentSectionSize = RegionSize - CurrentSectionRVA;
            }else {
                CurrentSectionSize = Marshal.ReadInt32(CurrentSectionHeaderAddr + 40 + 12) - CurrentSectionRVA;
            }
            Marshal.Copy((IntPtr)(ModuleBase.ToInt64() + CurrentSectionRVA), NewNTDLL, CurrentSectionOffset, CurrentSectionSize);
        }

        File.WriteAllBytes(args[1], NewNTDLL);
        Console.WriteLine("[+] Done!");
    }
}