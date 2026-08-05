' Runs the given command line with a hidden window (style 0) so scheduled
' tasks never flash a console over fullscreen apps.
' Usage: wscript.exe //B run-hidden.vbs <exe-or-cmd> [args...]
Dim sh, cmd, i
Set sh = CreateObject("WScript.Shell")
cmd = ""
For i = 0 To WScript.Arguments.Count - 1
  If i > 0 Then cmd = cmd & " "
  cmd = cmd & """" & WScript.Arguments(i) & """"
Next
sh.Run cmd, 0, False
