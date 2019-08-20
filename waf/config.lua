-- vim: set ts=2 sw=2 sts=2 et:

-- general --
nw_enabled = true
nw_location_denied = '@waf-blocked'
nw_max_args = 300

-- rule type toggle --
nw_check_url     = true
nw_check_args    = true
nw_check_post    = true
nw_check_cookies = true
nw_check_agent   = true

-- log --
nw_log_enabled = true
nw_log_file = '/var/log/nginx/waf.log'

-- exceptions --
nw_main_whitelist = {
  [ 'ips' ] = {'127.0.0.1'},
  ['rules'] = {}
}
nw_domain_whitelist = {
  ['.*\\.example\\.com'] = {
    [ 'ips' ] = {},
    ['rules'] = { '0012', '4000-4002' },
  },
}

-- rules --
nw_path_rules = '/etc/nginx/waf/rules'
