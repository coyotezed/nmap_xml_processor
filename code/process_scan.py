#! /usr/bin/env python3

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import sys

if __name__ == '__main__':
	try:
		nmap_report = NmapParser.parse_fromfile(sys.argv[1])
	except:
		print("There was an issue with the provided file name.\n")
	else:
		lSum = nmap_report.summary.split(" ; ")
		print("\nNmap scan summary:")
		for node in lSum:
			print(" {}".format(node))

		print("\n# --------------- #")
		print("#  Scanned Hosts  #")
		print("# --------------- #\n")
		for host in nmap_report.hosts:
			print(" IP: {}".format(host.address))
			if len(host.hostnames) > 0:
				print(" Host names:")
				for name in host.hostnames:
					print("   {}".format(name))
			print(" Open Ports:")
			if len(host.get_open_ports()) == 0:
				print("   No ports open")
			else:
				for port in host.get_open_ports():
					print("   {}: {}".format(
								port[0], 
								host.get_service(port[0], protocol=port[1]).service
							)
						)
					for key in host.get_service(port[0], protocol=port[1]).service_dict.keys():
						if key == "method":
							pass
						elif key == "cpelist":
							if len(host.get_service(port[0], protocol=port[1]).service_dict[key]):
								print("    cpelist:")
								for cpe in host.get_service(port[0], protocol=port[1]).service_dict[key]:
									print("      {}".format(cpe))
						else:
							print("    {}: {}".format(
										key,
										host.get_service(port[0], protocol=port[1]).service_dict[key]
									)
								)
					print()
			print()





# ----------------------------- End of File ----------------------------- #

