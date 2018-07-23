-- vim: set ts=2 sw=2 sts=2 et:
--

require 'config'


---- helpers ----
--
-- builds the argument string from an args table
function build_args( args_map )
  local args = ''
  for key, val in pairs(args_map) do
    if type(val) == "table" then
      for _, v in pairs( val ) do
        if v == true then v="" end
        args = args..'&'..key..'='..v
      end
    else
      if val == true then val="" end
      args = args..'&'..key..'='..val
    end
  end
  
  -- remove the first '&' and unescape
  return ngx.unescape_uri( args:sub(2) )
end

-- logs blocked requests
function log_blocked( rule_type, rule_id, offending_text )
  if nw_log_enabled then
    -- gather info
    local ip_addr = ngx.var.remote_addr
    local time    = ngx.localtime()
    local domain  = ngx.var.server_name
    local line = string.format( '%s %s %15s [%7s:%4s] "%s"\n', time, domain, ip_addr, rule_type, rule_id, offending_text )

    -- write to file
    local log_file = io.open( nw_log_file, 'a' )
    if log_file == nil then
      ngx.log( ngx.ERR, 'WAF: Cannot open file for writting: '..nw_log_file )
      return false
    end
    log_file:write( line )
    log_file:flush()
    log_file:close()
  end
  return true
end

-- handles request blocking
function block( rule_type, rule_id, text_to_check )
  local id_min = nil
  local id_max = nil
  local id_rule = tonumber( rule_id )
  for domain_re, whitelisted_rules in pairs( nw_domain_whitelist ) do
    if ngx.re.match( ngx.var.server_name, domain_re, 'ijo' ) then
      for _,rule in pairs(whitelisted_rules) do
        -- rule is a range
        if rule:find("-") == 5 then
          id_min = tonumber( rule:sub(1,4) )
          id_max = tonumber( rule:sub(6,9) )
        -- rule is not a range
        else
          id_min = tonumber( rule )
          id_max = tonumber( rule )
        end
        if id_min <= id_rule and id_rule <= id_max then
          -- rule is whitelisted, we just return without blocking
          return true
        end
      end
    end
  end
  -- log the request
  log_blocked( rule_type, rule_id, text_to_check )
  -- block the request (also changes the url and clears the args)
  return ngx.exec( nw_location_denied, '' )
end

---- load rules ----
--
nw_rule_ids = {}
function load_rules( rule_type, rule_flag )
  local rules = {}
  if rule_flag then
    local rule_file = io.open( nw_path_rules..'/'..rule_type, 'r' )
    if rule_file ~= nil then
      for rule in rule_file:lines() do
        if rule ~= '' and rule:sub(1,1) ~= '#' and rule:find(':') == 5 then
          rule_id = rule:sub( 1, 4 )
          rule_re = rule:sub( 6 )
          rules[ rule_id ] = rule_re
          if nw_rule_ids[ rule_id ] == nil then
            nw_rule_ids[ rule_id ] = true
          else
            error("Rule ID "..rule_id.." is duplicated")
          end
        end
      end
      rule_file:close()
    end
  end
  return rules
end


---- common rules  ----
--
nw_common_rules = {
  -- always load common rules
  rules = load_rules( 'common', true ),
  check = function( text_to_check )
    if text_to_check ~= nil and text_to_check ~= '' then
      for rule_id, rule_re in pairs( nw_common_rules.rules ) do
        if ngx.re.match( text_to_check, rule_re, 'ijo' ) then
          block( ' common', rule_id, text_to_check )
        end
      end
    end
    return true
  end
}


---- rules table ----
--
nw_rules = {}


-- url rules --
nw_rules.url = {
  rules = load_rules( 'url', nw_check_url ),
  check = function()
    if nw_check_url then
      -- define TARGET to match against rules
      local TARGET = ngx.var.uri
      
      -- check common rules
      nw_common_rules.check( TARGET )

      -- check specific rules
      for rule_id, rule_re in pairs( nw_rules.url.rules ) do
        if ngx.re.match( TARGET, rule_re, 'ijo' ) then
          block( '    url', rule_id, TARGET )
        end
      end
    end
    return true
  end
}


-- args rules --
nw_rules.args = {
  rules = load_rules( 'args', nw_check_args ),
  check = function()
    if nw_check_args then
      -- parse args
      local args_tab, err = ngx.req.get_uri_args()
      if err == "truncated" then
        -- More than 100 args were passed
        block( '   args', 'none', 'more than 100 args supplied')
      end
        
      -- define TARGET to match against rules
      local TARGET = '?'..build_args( args_tab )
      
      if TARGET ~= '' then
        -- check common rules
        nw_common_rules.check( TARGET )

        -- check specific rules
        for rule_id, rule_re in pairs( nw_rules.args.rules ) do
          if ngx.re.match( TARGET, rule_re, 'ijo' ) then
            block( '   args', rule_id, TARGET )
          end
        end
      end
    end
    return true
  end
}


-- cookies rules --
nw_rules.cookies = {
  rules = load_rules( 'cookies', nw_check_cookies ),
  check = function()
    if nw_check_cookies then
      -- define TARGET to match against rules
      local TARGET = ngx.var.http_cookie
      
      -- check common rules
      nw_common_rules.check( TARGET )

      -- check specific rules
      for rule_id, rule_re in pairs( nw_rules.cookies.rules ) do
        if ngx.re.match( TARGET, rule_re, 'ijo' ) then
          block( 'cookies', rule_id, TARGET )
        end
      end
    end
    return true
  end
}


-- agent rules --
nw_rules.agent = {
  rules = load_rules( 'agent', nw_check_agent ),
  check = function()
    if nw_check_agent then
      -- define TARGET to match against rules
      local TARGET = ngx.var.http_user_agent
      if TARGET == nil then
        block( '  agent', ' nil', '' )
      end
      
      -- check common rules
      nw_common_rules.check( TARGET )

      -- check specific rules
      for rule_id, rule_re in pairs( nw_rules.agent.rules ) do
        if ngx.re.match( TARGET, rule_re, 'ijo' ) then
          block( '  agent', rule_id, TARGET )
        end
      end
    end
    return true
  end
}


-- post rules --
nw_rules.post = {
  rules = load_rules( 'post', nw_check_post ),
  check = function()
    if nw_check_post then
      -- force read POST body
      ngx.req.read_body()

      -- parse ags
      local args_tab, err = ngx.req.get_post_args()
      if err == "truncated" then
        -- More than 100 args were passed
        block( '   post', 'none', 'more than 100 args supplied')
      end

      -- define TARGET to match against rules
      local TARGET = build_args( args_tab )
      
      if TARGET ~= '' then
        -- check common rules
        nw_common_rules.check( TARGET )

        -- check specific rules
        for rule_id, rule_re in pairs( nw_rules.post.rules ) do
          if ngx.re.match( TARGET, rule_re, 'ijo' ) then
            block( '   post', rule_id, TARGET )
          end
        end
      end
    end
    return true
  end
}
