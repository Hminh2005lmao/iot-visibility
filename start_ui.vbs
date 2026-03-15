Option Explicit

Dim shell, fso, root, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

root = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "powershell -NoProfile -ExecutionPolicy Bypass -File """ & root & "\scripts\run.ps1"" -OpenBrowser"

' 0 = hidden window, False = do not wait
shell.Run cmd, 0, False
