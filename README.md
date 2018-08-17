# nginx_waf
WAF written in lua for NGINX http server

## Installation

### nginx lua
You need to install lua support for nginx. You can easily do that in a _Ubuntu_ or _Debian_ sytem by installing the package `libnginx-mod-http-lua`. You will have to ensure that you have this line at the begining of your `nginx.conf`

```include /etc/nginx/modules-enabled/*.conf;```

And that the symbolic link `50-mod-http-lua.conf -> /usr/share/nginx/modules-available/mod-http-lua.conf` exists in your `/etc/nginx/modules-enabled/` directory.

### nginx waf

1. Copy the `waf` directory to `/etc/nginx/`

2. Add to `nginx.conf`, in the `http` section:

```
  lua_package_path   "/etc/nginx/waf/?.lua";
  init_by_lua_file   "/etc/nginx/waf/init.lua";
  access_by_lua_file "/etc/nginx/waf/waf.lua";
```

3. Create a location for the blocked requests in the `server` section of your site configuration. Default `@waf-blocked` but can
be changed in the `waf/config.lua` configuration file.

## Configuration
This WAF allows several configuration options like:

* Enable/Disable the whole WAF
* Enable/Disable specific types of checks
* General whitelist of source IPs
* General whitelist of rules
* Domain regex matching whitelist of source IPs
* Domain regex matching whitelist of rules
* Toggle log, change log file, change blocked requests location, etc.

### main configuration
The main configuration file has these options:

`nw_enabled`: (true/false): Enables or disables the use of the WAF.
`nw_location_denied`: (nginx location): Sets the nginx location where the blocked requests will be sent.
`nw_check_url`: (true/false): Toggles the check of rules matching the URL in the requests
`nw_check_args`: (true/false): Toggles the check of rules matching the query arguments in the requests
`nw_check_post`: (true/false): Toggles the check of rules matching the post parameters in POST requests
`nw_check_cookies`: (true/false): Toggles the check of rules matching the `Cookie` HTTP header in the requests
`nw_check_agent`: (true/false): Toggles the check of rules matching the `User-Agent` HTTP header in the requests
`nw_log_enabled`: (true/false): Enables or disables the log of the blocked requests
`nw_log_file`: (filesystem path): Sets the path of the log file for the blocked requests
`nw_main_whitelist`: (lua table): Configures the general whitelist of source IP addresses and rules. See example in config file.
`nw_domain_whitelist`: (lua table): Configures whitelists of rules and source IPs that match regular expressions against domain names. Check the example in the config file.
`nw_path_rules`: (filesystem path): Sets the path of the directory from where to read the files of the rules

### rules
The rules are regular expressions with IDs that match evil data in the requests so they get blocked by the WAF.

#### overview
TODO:
 * Explain how are they deployed (rule files)
 * Explain the types of rules
 * Explain the common rules
 * Explain the rule IDs (how they work with common rules)
 
#### creating rules
TODO:
 * Explain IDs and regex
 * Explain best order (most restrictive first so less rules are checked)
##### templating
TODO:
 * Explain the templating engine for the rules
 
#### whitelisting
TODO:
 * Explain whitelisting

