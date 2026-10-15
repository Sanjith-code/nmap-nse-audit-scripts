local nmap = require "nmap"

description = [[
Loopback-only monlist exposure and response-size check. Enhancement 2 builds
on strict Mode 7 validation and reports the one reply's size and size ratio
against its 48-byte request. It reads one UDP datagram only and does not
enumerate or display monitor-list entries.
]]

author = "Sanjith Madhavan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local REQUEST_BYTES = 48
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
  if not (is_response and mode == 7 and implementation == 3 and request_code == 42) then
    return {
      status = "reply did not pass validation",
      response_bit = is_response,
      mode = mode,
      implementation = implementation,
      request_code = request_code,
      bytes = #response
    }
  end

  local ratio = #response / REQUEST_BYTES
  local status_nibble = (string.byte(response, 5) >> 4) & 0x0f
  local assessment = "matching reply; response is no larger than request"
  if #response > REQUEST_BYTES then
    assessment = "matching reply exceeds request size; review exposure and restrict NTP access"
  end
  return {
    status = "matching Mode 7 monlist reply",
    response_status_nibble = status_nibble,
    request_bytes = REQUEST_BYTES,
    response_bytes = #response,
    response_to_request_ratio = string.format("%.2f", ratio),
    assessment = assessment,
    note = "Only the first UDP datagram was measured; this is not a full amplification test."
  }
end
