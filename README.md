# basic\_hmac\_auth

HMAC auth helper for Squid.

TODO: Tell about format and idea.

## Usage

This auth helper can be used with configuration like this:

```
auth_param basic program /usr/local/bin/basic_hmac_auth -secret 1be3ada09688ca3c4a674a7d2e285a5a04ee423e082ae6c6b91946e2853af239
auth_param basic children 8 startup=8 idle=8 concurrency=50
auth_param basic credentialsttl 15 minutes
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
```

> [!IMPORTANT]  
> Note that this helper works **only** with concurrent helper protocol, so `concurrency=` parameter **must** be greater than zero.

> [!TIP]
> HMAC shared secret can be also specified in file referenced by `-secret-file` command line option or with `BASIC_AUTH_HMAC_SECRET` environment variable.

## Synopsis

```
$ basic_hmac_auth -h
Usage of /usr/local/bin/basic_hmac_auth:
  -buffer-size int
    	initial buffer size for stream parsing
  -secret string
    	hex-encoded HMAC secret value
  -secret-file string
    	file containing single line with hex-encoded secret
  -version
    	show program version and exit
```
