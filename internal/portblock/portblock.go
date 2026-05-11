// Package portblock lists local TCP/UDP ports that rift refuses to forward
// to without an explicit operator opt-in. Centralised so the server-side
// register path and the client-side spec validation agree on the policy.
package portblock

// TCPServices lists local TCP services whose accidental exposure as a
// rift TCP tunnel target is a known incident class.
var TCPServices = map[uint16]string{
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	135:   "RPC",
	139:   "NetBIOS",
	445:   "SMB",
	465:   "SMTPS",
	587:   "SMTP submission",
	1433:  "MSSQL",
	1434:  "MSSQL Browser",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	6379:  "Redis",
	9200:  "Elasticsearch",
	11211: "memcached",
	27017: "MongoDB",
}

// UDPServices lists local UDP services whose accidental exposure as a
// WebTransport datagram tunnel target is a known incident class. These
// services routinely bind to loopback and have weak or no authentication
// at the network layer.
var UDPServices = map[uint16]string{
	53:   "DNS",
	67:   "DHCP server",
	68:   "DHCP client",
	123:  "NTP",
	137:  "NetBIOS name",
	138:  "NetBIOS datagram",
	161:  "SNMP",
	162:  "SNMP trap",
	500:  "IKE",
	514:  "syslog",
	520:  "RIP",
	1900: "SSDP",
	5353: "mDNS",
}
