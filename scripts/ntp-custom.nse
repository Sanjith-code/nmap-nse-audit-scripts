-- ntp-custom.nse
-- Checks for a response to a legacy NTP Mode 7 monlist probe.
-- A response is a signal for further validation, not conclusive proof by itself.

description = [[
Sends a legacy NTP Mode 7 monlist probe and reports whether a response is
received. A response must be validated before confirming CVE-2013-5211 exposure.
A missing response is inconclusive and must not be interpreted as proof of security.
]]
author = "Sanjith Madhavan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

local shortport = require "shortport"
local comm = require "comm"
local port_rule = shortport.portnumber(123, "udp")

local function is_loopback(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

portrule = function(host, port)
  return is_loopback(host) and port_rule(host, port)
end

action = function(host, port)
  if not is_loopback(host) then
    return "SKIPPED: This NTP check is restricted to localhost."
  end
  local query = string.char(
    0x17, 0x00, 0x03, 0x2a,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  )

  local status, response = comm.exchange(host, port, query,
    {timeout = 5000, proto = "udp"})

  if not status or not response or #response == 0 then
    return "INCONCLUSIVE: No response to the legacy monlist query; exposure was not demonstrated."
  end

  return "RESPONSE DETECTED: Received " .. #response .. " bytes from the NTP service.\n"
    .. "  Next step: Validate that the packet is a valid Mode 7 monlist response.\n"
    .. "  Risk if confirmed: NTP reflection/amplification (CVE-2013-5211).\n"
    .. "  Recommendation: Upgrade/patch the NTP service and restrict management queries."
end
