rule diamondfox {
	
	strings:
		$s0 = "Renard" ascii wide
		$s1 = "cDeflate" ascii wide
		$s2 = "cRijndael" ascii wide
		$s3 = "?gpb=" ascii wide
		$s4 = "&il=" ascii wide
		$s5 = "&er=" ascii wide
		$s6 = "&ref=" ascii wide
		$s7 = "?lp=" ascii wide
		$s8 = "?prf=" ascii wide
		$s9 = "&proc=" ascii wide
		$s10 = "&env=" ascii wide
		$s11 = "&rt=" ascii wide
		$s12 = "?grf=" ascii wide
		$s13 = "?ct=" ascii wide
		$s14 = "&ac=" ascii wide
		$s15 = "&lt" ascii wide

	condition:
		8 of ($s*)
}