# nginx_waf
WAF written in lua for NGINX http server

## Installation

### nginx lua
You need to install lua support for nginx. You can easily do that in a _Ubuntu_ or _Debian_ sytem by installing the package `libnginx-mod-http-lua`

1. Copy the `waf` directory to `/etc/nginx/`

2. Add to `nginx.conf` in the `http` section:

```
  lua_package_path   "/etc/nginx/waf/?.lua";
  init_by_lua_file   "/etc/nginx/waf/init.lua";
  access_by_lua_file "/etc/nginx/waf/waf.lua";
```

3. Create a location for the blocked requests. Default `/waf-blocked` but can
be changed in the `waf/config.lua`


