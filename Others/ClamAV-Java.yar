rule JavaTrojanAdwind060153340_0
{
strings:
	$hex0 = { 6a6176612f6c616e672f436c6173734c6f61646572 }
	$hex1 = { 6a6176612f6c616e672f7265666c6563742f4d6574686f64 }
	$hex2 = { 6765745265736f75726365417353747265616d }
	$hex3 = { 6a6176612f7574696c2f7a69702f475a4950496e70757453747265616d }
	$hex4 = { 2A0332C000??4C2A0432C000??C000??4D12 }
	$hex5 = { 2BBB00??59BB00??5912??10??B700 }
	$hex6 = { B700??05BD00??590312??535904 }
	$hex7 = { 53B600 }
condition:
	$hex0 and $hex1 and $hex2 and $hex3 and $hex4 and $hex5 and $hex6 and $hex7
}
rule JavaTrojanAdwind160153350_1
{
strings:
	$hex0 = { 6a6176612f6c616e672f436c6173734c6f61646572 }
	$hex1 = { 6a6176612f6c616e672f7265666c6563742f4d6574686f64 }
	$hex2 = { 6765745265736f75726365417353747265616d }
	$hex3 = { 6a6176612f7574696c2f7a69702f475a4950496e70757453747265616d }
	$hex4 = { 2ABB00??59BB00??5912??10??B700 }
	$hex5 = { B600 }
	$hex6 = { B700??05BD00??590312??53590412??53B600??0105BD00??590312??5359042B53B600??57 }
condition:
	$hex0 and $hex1 and $hex2 and $hex3 and $hex4 and $hex5 and $hex6
}
rule JavaTrojanAdwind260153360_2
{
strings:
	$hex0 = { 6a6176612f6c616e672f436c6173734c6f61646572 }
	$hex1 = { 6a6176612f6c616e672f7265666c6563742f4d6574686f64 }
	$hex2 = { 6765745265736f75726365417353747265616d }
	$hex3 = { 6a6176612f7574696c2f7a69702f475a4950496e70757453747265616d }
	$hex4 = { BEA200 }
	$hex5 = { 15??33649154 }
	$hex6 = { 840?01A7FF }
condition:
	$hex0 and $hex1 and $hex2 and $hex3 and $hex4 and $hex5 and $hex6
}
rule PUAJavaPackerAllatori1_3
{
strings:
	$hex0 = { 414c4c41544f52497844454d4f }
condition:
	$hex0
}
rule WinExploitCVE_2012_05076_4
{
strings:
	$hex0 = { 404047ae147ae148 }
	$hex1 = { 407b52b851eb851f }
	$hex2 = { FA55 }
	$hex3 = { D592 }
condition:
	$hex0 and $hex1 and $hex2 and $hex3
}
rule JavaExploitCVE_2013_14883_5
{
strings:
	$hex0 = { 6a646263436f6d706c69616e74 }
	$hex1 = { 46616b654472697665722e6a617661 }
	$hex2 = { 6a6176612f7574696c2f4162737472616374536574 }
	$hex3 = { 6a6176612f73716c2f447269766572 }
condition:
	$hex0 and $hex1 and $hex2 and $hex3
}
rule JavaExploitCVE_2012_172322_6
{
strings:
	$hex0 = { 6d73662f782f5061796c6f6164582453747265616d436f6e6e6563746f72 }
condition:
	$hex0
}
rule OsxTrojanFruitfly66654781_7
{
strings:
	$hex0 = { 436f646501000a73687566666c65696e74 }
	$hex1 = { 7472616e736c6174656b6579 }
	$hex2 = { 6170706c652e6177742e5549456c656d656e7401000474727565 }
	$hex3 = { 63726561746553637265656e43617074757265 }
	$hex4 = { 6d6f7573654d6f7665 }
	$hex5 = { 6d6f7573655072657373 }
	$hex6 = { 6d6f75736552656c65617365 }
	$hex7 = { 6b65795072657373 }
	$hex8 = { 6b657952656c65617365 }
	$hex9 = { 666c757368 }
condition:
	$hex0 and $hex1 and $hex2 and $hex3 and $hex4 and $hex5 and $hex6 and $hex7 and $hex8 and $hex9
}
