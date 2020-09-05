rule Maze{
	meta:
		description = "Maze Ransomware" 
		author = "Ju5tlc3"
		date = "2020-08-24"
		hash = "644bea8a3ac7e9bcb70525bc381d54db"
		reference = "https://app.any.run/tasks/f1b10cc2-7b35-4124-b5ec-14d76fa7ac5d"
	strings:
		$str1 = "CMaze Ransomware" wide
		$str2 = "83729304958372930dhejskrlt9483s" ascii
		$str3 = "DECRYPT-FILES.txt" wide
		$str4 = "AhnLab" wide
		$str5 = "B--logging" wide
		$str6 = "--nomutex" wide
		$str7 = "--noshares" wide
		$str8 = "--nomutex" wide
		$str9 = "--path" wide
		$str10 = "NO SHARES | " wide
		$str11 = "NO MUTEX | " wide		
		$str12 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" ascii
		$str13 = "Secur32.dll" ascii
		$opcode1 = {0F 85 ?? F? FF FF 0F 84 ?? F? FF FF} 
		$opcode2 = {64 8B ?? 30 00 00 00 5? [5-20] 5? 8A ?? 02 84 ?? 74 11 BB ?? ?? 00 00 0F 85 ?? F? FF FF 0F 84 ?? 0? 00 00}	
	condition:
		uint16(0) == 0x5A4D and all of them
}
