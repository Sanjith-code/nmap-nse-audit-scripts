local nmap = require "nmap"

description = [[
Bounded NTP monlist audit for loopback labs. Enhancement 1 adds strict reply
validation and a distinct result for malformed or non-matching replies. It
sends exactly one request, reads at most one UDP datagram, and never prints
client addresses or parses monitor-list entries.
]]

author = "Sanjith Madhavan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local function is_loopback(host)
  return host.ip == "127.0.0.1" or host.ip == "::1"
end

portrule = function(host, port)
  return is_loopback(host) and port.protocol == "udp" and port.number == 123
      and (port.state == "open" or port.state == "open|filtered")
end

action = function(host, port)
  if not is_loopback(host) then
    return {status = "skipped", reason = "This script is restricted to localhost."}
  end
  local sock = nmap.new_socket()
  sock:set_timeout(1500)
  local connected, err = sock:connect(host, port)
  if not connected then
    sock:close()
    return {status = "inconclusive", reason = "UDP connect failed: " .. (err or "unknown error")}
  end

  local request = string.char(0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00)
      .. string.rep("\0", 40)
  local sent, send_err = sock:send(request)
  if not sent then
    sock:close()
    return {status = "inconclusive", reason = "UDP send failed: " .. (send_err or "unknown error")}
  end

  local received, response = sock:receive()
  sock:close()
  if not received or not response then
    return {status = "no reply; inconclusive", note = "Closed/filtered UDP or timeout is not proof of security."}
  end

  if #response < 8 then
    return {status = "reply rejected", reason = "Response shorter than the 8-byte Mode 7 header", bytes = #response}
  end

  local flags = string.byte(response, 1)
  local is_response = (flags & 0x80) ~= 0
  local mode = flags & 0x07
  local implementation = string.byte(response, 3)
  local request_code = string.byte(response, 4)
  if is_response and mode == 7 and implementation == 3 and request_code == 42 then
    local status_nibble = (string.byte(response, 5) >> 4) & 0x0f
    return {
      status = "matching Mode 7 monlist reply",
      implementation = implementation,
      request_code = request_code,
      response_status_nibble = status_nibble,
      bytes = #response,
      note = "A matching reply confirms legacy Mode 7 handling; records were not displayed."
    }
  end

  return {
    status = "reply did not pass validation",
    response_bit = is_response,
    mode = mode,
    implementation = implementation,
    request_code = request_code,
    bytes = #response
  }
end
