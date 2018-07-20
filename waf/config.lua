-- vim: set ts=2 sw=2 sts=2 et:

-- general --
nw_enabled = true
nw_location_denied = '@waf-blocked'

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
nw_remote_whitelist = {'127.0.0.1'}
nw_domain_whitelist = {
  ['.*\\.example\\.com'] = { '0012', '4000-4002' }
}

-- rules --
nw_path_rules = '/etc/nginx/waf/rules'
