-- vim: set ts=2 sw=2 sts=2 et:
--

require 'config'

if nw_enabled then
  -- check whitelist
  local whitelisted = false
  for _,host in pairs( nw_remote_whitelist ) do
    if ngx.re.match( ngx.var.remote_addr, host, 'ijo' ) then
      whitelisted = true
      break
    end
  end

  if not whitelisted then
    for _, rule_type in pairs(nw_rules) do
      rule_type.check()
    end
  end
end
