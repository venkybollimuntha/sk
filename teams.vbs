
'[Description]: Sends the keyboard input 'NUM LOCK' for every two minutes
'[Input]: Enter the approximate test execution time in hrs 
'=========================================================================================
'=========================================================================================
Dim VarHrs 
VarHrs = InputBox("Enter the approximate Execution time in Hrs")

exptime = DateAdd("h",VarHrs,Now)

Set Wshell = WScript.CreateObject("WScript.Shell")

While Now < exptime
Wscript.Sleep 120000
Wshell.SendKeys "{NUMLOCK}"
Wshell.SendKeys "{NUMLOCK}"

Wend



