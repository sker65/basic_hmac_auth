# basic\_hmac\_auth

HMAC auth helper for Squid.

Authentication with [HMAC signatures](https://en.wikipedia.org/wiki/HMAC) essentially allows fleet of proxies to use centralized authentication without the need for proxies to communicate with any central server directly. It works like this: some entity (e.g. API server) issues HMAC-signed token with limited validity time to the users. Users can't forge HMAC-signed token because they don't know secret key, while proxy can validate signature sent by user as credentials and decide to allow access immediately, without any need to communicate with central server or database to check user's password and status. All relevant information to allow access is already carried by users within their requests.

basic\_hmac\_auth helper enables Squid basic authentication with HMAC-signatures passed as username and password, leveraging classic login-password scheme to carry HMAC signatures. In that scheme username represents user login as usual and password should be constructed as follows:

*password := urlsafe\_base64\_without\_padding(expire\_timestamp || hmac\_sha256(secret, "dumbproxy grant token v1" || username || expire\_timestamp))*

where *expire_timestamp* is 64-bit big-endian UNIX timestamp and *||* is a concatenation operator. [This Python script](https://gist.github.com/Snawoot/2b5acc232680d830f0f308f14e540f1d) can be used as a reference implementation of signing.

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

## See also

* This HMAC auth format was ported to Squid from [dumbproxy](https://github.com/SenseUnit/dumbproxy) project. dumbproxy is a modern lightweight, performant and easy to use proxy server.
