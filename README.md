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

3. Create a location for the blocked requests in the `server` section of your site configuration. Default `@waf-blocked` but can be changed in the `waf/config.lua` configuration file.

4. Make sure that the log file has write permissions for the nginx user. In _Debian_ systems this user is `www-data` and you might need to set the log file to `/var/log/nginx/waf/waf.log` and then execute:

```
mkdir /var/log/nginx/waf
chown www-data:www-data /var/log/nginx/waf
chmod 640 /var/log/nginx/waf

```

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

`nw_max_args`: (number): Sets the maximum number of URI and POST arguments. Requests with more will be blocked.

`nw_check_url`: (true/false): Toggles the check of rules matching the URL in the requests

`nw_check_args`: (true/false): Toggles the check of rules matching the query arguments in the requests

`nw_check_post`: (true/false): Toggles the check of rules matching the post parameters in POST requests

`nw_check_cookies`: (true/false): Toggles the check of rules matching the `Cookie` HTTP header in the requests

`nw_check_agent`: (true/false): Toggles the check of rules matching the `User-Agent` HTTP header in the requests

`nw_log_enabled`: (true/false): Enables or disables the log of the blocked requests

`nw_log_file`: (filesystem path): Sets the path of the log file for the blocked requests

`nw_main_whitelist`: (lua table): Configures the general whitelist of source IP addresses and rules. See example in config 
file.

`nw_domain_whitelist`: (lua table): Configures whitelists of rules and source IPs that match regular expressions against domain names. Check the example in the config file.

`nw_path_rules`: (filesystem path): Sets the path of the directory from where to read the files of the rules

### rules
The rules are regular expressions with IDs that match evil data in the requests so they get blocked by the WAF.

#### overview

The rules are distributed in different files under the `/waf/rules` directory. Each file corresponds to a different category of rules. They are basically a list of regular expressions that match against potentially harmful data. There is also a _README_ file there where the internal structure of the rule files is explained. 

There are currently 6 types of rules:

 * **agent**: These rules will match against the `User-Agent` header value.
 * **args**: These rules will match against url arguments for `GET` requests.
 * **cookies**: These rules will match against the `Cookie` header value.
 * **post**: These rules will match against the arguments of a `POST` request.
 * **url**: These rules will match against the url of the request.
 * **common**: These rules will be used in all te type of checks.
 
 Each type of rule has a 5 digit base id (i.e.: 50000) and the first thousand ids are reserved for the common rules. This means that if the base id for `post` rules is `30000`, the first id allowed to be used in the `post` rules file will be `31000`, as any other id before that can be used by the common rules. This allows us to whitelist common rules of a specific type (for example `30001` would whitelist the common rule with id `001` for `post` checks).
 
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

