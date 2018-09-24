-- vim: set ts=2 sw=2 sts=2 et:
--

require 'config'
local etlua = require 'etlua'

--------------------------------------------------------------------------------
---------------------------------- globals -------------------------------------
--------------------------------------------------------------------------------
--
nw_common_rule_max_id = 999 -- max allowed id for a common rule
nw_common_rules = {} -- table with the common rules
nw_rule_ids = {} -- table to keep track of rule ids to grant they are unique
nw_rules = {} -- main table with the rules and check functions




--------------------------------------------------------------------------------
---------------------------------- helpers -------------------------------------
--------------------------------------------------------------------------------
--
-------------------------------------------------- args table to query string --
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

-------------------------------------------------------- log blocked requests --
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

------------------------------------------------------------ check whitelists --
function check_rule_wl( rule_id, rule_wl )
  local id_rule = tonumber( rule_id )
  if type(id_rule) == 'nil' or type(rule_wl) == 'nil' then
    -- cannot check whitelist so it is not whitelisted
    return false
  end

  for _,rule in pairs( rule_wl ) do
    -- rule is a range
    s_pos = rule:find("-")
    if s_pos ~= nil then
      id_min = tonumber( rule:sub(1,s_pos-1) )
      id_max = tonumber( rule:sub(s_pos+1) )
    -- rule is not a range
    else
      id_min = tonumber( rule )
      id_max = tonumber( rule )
    end

    if type(id_min) == 'nil' or type(id_max) == 'nil' then
      -- something went wrong parsing the whitelist rule
      ngx.log(ngx.ERR, 'Something went wrong parsing the rule "'..tostring(rule_wl)..'"')
      return false
    end

    if id_min <= id_rule and id_rule <= id_max then
      -- rule is whitelisted
      return true
    end
  end
  -- rule is not whiltelisted
  return false
end

--------------------------------------------------------------- block request --
function block( rule_type, rule_id, text_to_check )
  -- check main rules whitelist
  if check_rule_wl( rule_id, nw_main_whitelist.rules ) then
    -- rule is whitelisted, we just return without blocking
    return true
  end

  -- check per domain rules whitelist
  for domain_re,wl in pairs( nw_domain_whitelist ) do
    if ngx.re.match( ngx.var.server_name, domain_re, 'ijo' ) and
      check_rule_wl( rule_id, wl.rules ) then
      -- rule is whitelisted, we just return without blocking
      return true
    end
  end
  -- log the request
  log_blocked( rule_type, rule_id, text_to_check )
  -- block the request (also changes the url and clears the args)
  return ngx.exec( nw_location_denied, '' )
end


--------------------------------------------------------------------------------
--------------------------------- core check -----------------------------------
--------------------------------------------------------------------------------
--
------------------------------------------------------------------ check rule --
function nw_check( rule_type, target, re_flags )
  if target ~= nil and target ~= '' then
    -- iterate over rule templates for given rule type
    for rule_id, rule_re_t in pairs( nw_rules[rule_type].rules ) do
      -- render this rule
      local rule_re = etlua.render( rule_re_t, ngx.var )
      -- check if we need to block this rule
      if ngx.re.match( target, rule_re, re_flags ) then
        block( rule_type, rule_id, target)
      end
    end
  end
end


--------------------------------------------------------------------------------
--------------------------------- load rules -----------------------------------
--------------------------------------------------------------------------------
--
----------------------------------------------------------- load common rules --
function load_common_rules()
  local rule_file = io.open( nw_path_rules..'/common', 'r' )
  if rule_file ~= nil then
    for rule in rule_file:lines() do
      if rule ~= '' and rule:sub(1,1) ~= '#' and rule:find(':') == 4 then
        rule_id = tonumber(rule:sub( 1, 3 ))
        rule_re = rule:sub( 5 )
        if rule_id > nw_common_rule_max_id then
          error("Common rule ID "..tostring(rule_id).." is greater than "..tostring( nw_common_rule_max_id ))
        elseif nw_common_rules[ rule_id ] ~= nil then
          error("Common rule ID "..tostring(rule_id).." is duplicated")
        else
          nw_common_rules[ rule_id ] = rule_re
        end
      end
    end
    rule_file:close()
  end
end

------------------------------------------------------------ load other rules --
function load_rules( rule_type, base_id, rule_flag )
  local rules = {}
  if rule_flag then
    -- add common rules
    for c_rule_id,c_rule in pairs( nw_common_rules ) do
      rules[ base_id + c_rule_id ] = c_rule
    end

    -- add specific rules
    local rule_file = io.open( nw_path_rules..'/'..rule_type, 'r' )
    if rule_file ~= nil then
      for rule in rule_file:lines() do
        if rule ~= '' and rule:sub(1,1) ~= '#' and rule:find(':') == 6 then
          rule_id = tonumber(rule:sub( 1, 5 ))
          rule_re = rule:sub( 7 )
          rules[ rule_id ] = rule_re
          if rule_id < base_id + nw_common_rule_max_id then
            error("Rule ID "..tostring(rule_id).." is less than "..tostring(base_id + nw_common_rule_max_id))
          elseif nw_rule_ids[ rule_id ] ~= nil then
            error("Rule ID "..rule_id.." is duplicated")
          else
            nw_rule_ids[ rule_id ] = true
          end
        end
      end
      rule_file:close()
    end
  end
  return rules
end


--------------------------------------------------------------------------------
-------------------------------- rules table -----------------------------------
--------------------------------------------------------------------------------
--
---------------------------------------------------------------- common rules --
load_common_rules()

----------------------------------------------------------------- agent rules --
nw_rules.agent = {
  rules = load_rules( 'agent', 10000, nw_check_agent ),
  check = function()
    if nw_check_agent then
      -- define TARGET to match against rules
      local TARGET = ngx.var.http_user_agent
      if TARGET == nil then
        block( 'agent', ' nil', '' )
      end

      -- check rules
      nw_check('agent', TARGET, 'jo')
    end
    return true
  end
}

------------------------------------------------------------------ args rules --
nw_rules.args = {
  rules = load_rules( 'args', 20000, nw_check_args ),
  check = function()
    if nw_check_args then
      -- parse args
      local args_tab, err = ngx.req.get_uri_args()
      if err == "truncated" then
        -- More than 100 args were passed
        block( 'args', 'none', 'more than 100 args supplied')
      elseif err ~= nil or args_tab == nil then
        -- If anything was wrong retrieving the args, skip the checks
        return true
      end
        
      -- define TARGET to match against rules
      local TARGET = '?'..build_args( args_tab )
      
      -- check rules
      nw_check('args', TARGET, 'ijo')
    end
    return true
  end
}

------------------------------------------------------------------ post rules --
nw_rules.post = {
  rules = load_rules( 'post', 30000, nw_check_post ),
  check = function()
    if nw_check_post and ngx.req.get_method() == "POST" then
      -- force read POST body
      ngx.req.read_body()

      -- parse ags
      local args_tab, err = ngx.req.get_post_args()
      if err == "truncated" then
        -- More than 100 args were passed
        block( 'post', 'none', 'more than 100 args supplied' )
      elseif err ~= nil or args_tab == nil then
        -- If anything was wrong retrieving the args, skip the checks
        return true
      end

      -- define TARGET to match against rules
      local TARGET = build_args( args_tab )
      
      -- check specific rules
      nw_check('post', TARGET, 'ijo')
    end
    return true
  end
}

------------------------------------------------------------------- url rules --
nw_rules.url = {
  rules = load_rules( 'url', 40000, nw_check_url ),
  check = function()
    if nw_check_url then
      -- define TARGET to match against rules
      local TARGET = ngx.var.uri
      
      -- check specific rules
      nw_check('url', TARGET, 'ijo')
    end
    return true
  end
}

--------------------------------------------------------------- cookies rules --
nw_rules.cookies = {
  rules = load_rules( 'cookies', 50000, nw_check_cookies ),
  check = function()
    if nw_check_cookies then
      -- define TARGET to match against rules
      local TARGET = ngx.var.http_cookie

      -- check specific rules
      nw_check('cookies', TARGET, 'ijo')
    end
    return true
  end
}
