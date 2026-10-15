-- snmp-public-check-option1.nse
-- Enhancement 1: clear finding, safe response parsing, and remediation guidance

description = [[
Checks whether an SNMP agent returns its system description when queried
with the default community string "public". A successful readable response
indicates potential information exposure. A missing response is inconclusive.
]]
author = "Sanjith Madhavan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

local shortport = require "shortport"
local snmp = require "snmp"
local nmap = require "nmap"

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

action = function(host, port)
  local helper = snmp.Helper:new(host, port, "public")
  helper:connect()

  local status, response = helper:get({reqId = 1}, "1.3.6.1.2.1.1.1.0")
  if not status then
    return "INCONCLUSIVE: No usable response to the sysDescr request using community 'public'."
  end

  local sysDescr = response and response[1] and response[1][1]
  if sysDescr == nil then
    return "INCONCLUSIVE: The SNMP request completed but no readable sysDescr value was returned."
  end

  nmap.set_port_state(host, port, "open")
  return "POTENTIAL EXPOSURE: SNMP returned sysDescr using the default community 'public'.\n"
    .. "  sysDescr: " .. tostring(sysDescr) .. "\n"
    .. "  Risk: Unauthorised system-information disclosure.\n"
    .. "  Recommendation: Remove default communities, restrict UDP/161, and prefer SNMPv3."
end
