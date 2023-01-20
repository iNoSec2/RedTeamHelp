using System;
using System.Runtime.InteropServices;

namespace structs
{
    internal class r0bit
    {

       
        [DllImport("ntdll.dll")]
        
        public static extern uint NtCreateSection(
            ref IntPtr SectionHandle, 
            uint DesiredAccess,  //changed from UInt32 to uint
            IntPtr ObjectAttributes,
            ref ulong MaximumSize, //ref UInt32 change to ref ulong
            uint SectionPageProtection, //uint32 changed to uint
            uint AllocationAttributes, //uint32 changed to uint
            IntPtr FileHandle);

        [DllImport("ntdll.dll")]
       
        public static extern uint NtMapViewOfSection(
            IntPtr SectionHandle, 
            IntPtr ProcessHandle,
            out IntPtr BaseAddress, //changed from ref to out
            IntPtr ZeroBits, //changed from uintptr to intptr
            IntPtr CommitSize,//changed from uintptr to intptr
            IntPtr SectionOffset,
            out ulong ViewSize, //changed from out uint to out ulong
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll")]
        
        public static extern uint NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess, //uint32 changed to uint
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended, //changed inCreateSuspended to createSuspended
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList);
    }
}
