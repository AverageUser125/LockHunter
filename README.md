This is a LockHunter utility... which detects if a file is locked and who is locking it.
I try to staticlly link the RestartManager which is the main windows API used to figure out which processes are locking the file
There are example programs in the resources to lock the file.

TO USE YOU MUST ENTER YOUR OWN VIRUSTOTAL API KEY!!!
Just set the environmemt variable VIRUSTOTAL_API_KEY to the key.
Or modify VirusTotal.cpp. Or look at CMakeSettingsExample.json