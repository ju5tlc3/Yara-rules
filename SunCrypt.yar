rule SunCrypt{
	meta:
		description = "SunCrypt Ransomware. Powershell loader" 
		author = "Viktoriia Taran"
		date = "2020-08-25"
		hash = "d87fcd8d2bf450b0056a151e9a116f72"
		reference = "https://app.any.run/tasks/9e9376c6-bbc5-4747-a3f8-8d3ce3b66d59"
	strings:
		$func1 = "VirtualAlloc"
		$func2 = "EnumDesktopsW"
		$powershell1 = "exe.llehsrewop\\0.1v\\llehSrewoPswodniW\\46WOWsyS\\swodniW\\:C"
		$powershell2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
		$powershell3 = "powershell.exe"
		$start_proc = "[System.Diagnostics.Process]::Start"
		$copy = "[Runtime.InteropServices.Marshal]::Copy"	
	condition:
		$func1 and $func2 and ($powershell1 or $powershell2 or $powershell3) and $copy and $start_proc
}
