#!/bin/bash
# vim: set ts=2 sw=2 sts=2 et:

TEST_SERVER="$1"  # https://192.168.12.123
[ -z "$TEST_SERVER" ] && echo "No test server given (https://fqdn|ip)" && exit 1

current_test=0
wtest() {
  r_path="$1"
  r_opts="$2"
  current_test=$(( $current_test + 1 ))

  #curl -vvvvvvk -o /dev/null "${TEST_SERVER}$r_path" "$r_opts"
  s_code=$(curl -svk -o /dev/null "${TEST_SERVER}$r_path" "$r_opts" 2>&1 \
    | egrep '< HTTP/1\.' \
    | cut -d' ' -f3)

  # Check if the status code is 470 because we return a 470 when blocked in
  # nginx /waf-blocked location
  if [ "$s_code" == "470" ]; then
    printf "TEST %3d --> Blocked\n" $current_test
  else
    printf "TEST %3d --> NOT BLOCKED!! $r_path [$r_opts]\n" $current_test
    exit 1
  fi
}

# disable expansion
set -f

echo "POST tests"
wtest "/" "-d \"t=select * from user\""
wtest "/" "-d \"t=current_user (a\""

echo "URL tests"
wtest "/t.php?t=select/*this is mysql space*/* from user" ""
wtest "/t.php_221321_copy" ""
wtest "/t.php~" ""
wtest "/public_html-213132-12312.tar.gz" ""

echo "ARGS tests"
wtest "/t.php?t=http://evil.com/sh.php" ""
wtest "/t.php?t=t/t/../../../t" ""

echo "AGENT tests"
wtest "/" "-Aunion all select * from users"
wtest "/" "-AMozilla/5.00 (Nikto/2.1.5)"
wtest "/" "-AInternet Ninja"
wtest "/" "-A "

echo "COOKIE tests"
wtest "/" "-HCookie: adfasdfasdfa';eval(base64_decode('ZXhlYygkX0dFVFsnYyddKTs='));"
wtest "/" "-HCookie: file=php://asdfasdfasd"
