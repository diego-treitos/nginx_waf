-- vim: set ts=2 sw=2 sts=2 et:
--

require 'config'

if nw_enabled and not ngx.req.is_internal() then
  -- check whitelist
  local whitelisted = false
  for domain_re,wl in pairs( nw_domain_whitelist ) do
    if ngx.re.match( ngx.var.server_name, domain_re, 'ijo' ) then
      for _,ip in pairs( wl.ips ) do
        if ngx.re.match( ngx.var.remote_addr, ip, 'jo' ) then
          whitelisted = true
          break
        end
      end
    end
  end
  if not whitelist then
    for _,ip in pairs( nw_main_whitelist.ips ) do
      if ngx.re.match( ngx.var.remote_addr, ip, 'jo' ) then
        whitelisted = true
        break
      end
    end
  end

  if not whitelisted then
    for _, rule_type in pairs(nw_rules) do
      rule_type.check()
    end
  end
end
