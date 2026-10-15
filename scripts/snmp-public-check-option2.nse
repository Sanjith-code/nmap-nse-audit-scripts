-- snmp-public-check-option2.nse
-- Enhancement 2: query multiple standard objects and report validated evidence

description = [[
Checks whether the default SNMP community string "public" can read the
standard sysName.0 and sysDescr.0 objects. Reports only values returned by
the SNMP library and treats missing or unusable data as inconclusive.
]]
author = "Sanjith Madhavan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

local shortport = require "shortport"
local snmp = require "snmp"
local nmap = require "nmap"

local SYS_DESCR = "1.3.6.1.2.1.1.1.0"
local SYS_NAME  = "1.3.6.1.2.1.1.5.0"

portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

action = function(host, port)
  local helper = snmp.Helper:new(host, port, "public")
  helper:connect()

  local status, response = helper:get({reqId = 2}, SYS_NAME, SYS_DESCR)
  if not status then
    return "INCONCLUSIVE: No usable SNMP response using the default community 'public'."
  end

  local sysName = response and response[1] and response[1][1]
  local sysDescr = response and response[2] and response[2][1]
  if sysName == nil and sysDescr == nil then
    return "INCONCLUSIVE: No readable sysName or sysDescr value was returned."
  end

  nmap.set_port_state(host, port, "open")
  local lines = {
    "POTENTIAL EXPOSURE: The default community 'public' returned readable system information."
  }
  if sysName ~= nil then
    table.insert(lines, "  sysName: " .. tostring(sysName))
  end
  if sysDescr ~= nil then
    table.insert(lines, "  sysDescr: " .. tostring(sysDescr))
  end
  table.insert(lines, "  Risk: Unauthorised system-information disclosure.")
  table.insert(lines, "  Recommendation: Disable default communities, restrict UDP/161, and use SNMPv3.")
  return table.concat(lines, "\n")
end
