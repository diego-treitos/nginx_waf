-- vim: set ts=2 sw=2 sts=2 et:
--

-- Helper function to convert an IP string into a 32-bit integer
local function ip_to_int(ip)
  local parts = {}
  for part in ip:gmatch("[0-9]+") do
    table.insert(parts, tonumber(part))
  end
  if #parts ~= 4 then return nil end
  return (parts[1] * 256^3) + (parts[2] * 256^2) + (parts[3] * 256^1) + parts[4]
end

--- Checks if an IP address belongs to a CIDR range.
function is_ip_in_cidr(ip, cidr)
  local ip_num = ip_to_int(ip)
  local base_ip_str, prefix_str = cidr:match("([%d%.]+)/(%d+)")
  if base_ip_str == nil or prefix_str == nil
  then
    -- Default to /32 if no subnet given
    cidr = cidr .. "/32"
    base_ip_str, prefix_str = cidr:match("([%d%.]+)/(%d+)")
  end

  if not ip_num or not base_ip_str or not prefix_str then return false end

  local network_num = ip_to_int(base_ip_str)
  local prefix = tonumber(prefix_str)

  if prefix < 0 or prefix > 32 then return false end
  if prefix == 0 then return true end

  -- Calculation: Use power of 2 to define the boundaries
  -- The range of IPs in a CIDR is [network, network + (2^(32-prefix) - 1)]
  local range_size = 2 ^ (32 - prefix)

  -- Check if ip falls within the block starting at network_num
  return ip_num >= network_num and ip_num < (network_num + range_size)
end
