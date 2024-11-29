# basic\_hmac\_auth

HMAC auth helper for Squid.

basic\_hmac\_auth helper enables Squid basic authentication with HMAC-signatures passed as username and password. In that scheme username represents user login as usual and password should be constructed as follows: *password := urlsafe\_base64\_without\_padding(expire\_timestamp || hmac\_sha256(secret, "dumbproxy grant token v1" || username || expire\_timestamp))*, where *expire_timestamp* is 64-bit big-endian UNIX timestamp and *||* is a concatenation operator. [This Python script](https://gist.github.com/Snawoot/2b5acc232680d830f0f308f14e540f1d) can be used as a reference implementation of signing.

## Usage

This auth helper can be used with Squid configuration like this:

```
auth_param basic program /usr/local/bin/basic_hmac_auth -secret <INSERT YOUR SECRET HERE>
auth_param basic children 8 startup=8 idle=8 concurrency=50
auth_param basic credentialsttl 15 minutes
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
```

Secret key can be generated with following command: `openssl rand -hex 32`

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
