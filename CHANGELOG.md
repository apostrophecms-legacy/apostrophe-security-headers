## 1.0.2 2021-09-27

Fixes crash when workflow is enabled but no hostnames are configured for it.

## 1.0.1 2021-08-25

The headers `Referrer-Policy`, `X-Content-Type-Options` and `Permissions-Policy` were inadvertently left off a list that allows them to be configured. The default values for the first two are now as was always intended. The third is not enabled by default but can now optionally be configured.

## 1.0.0 2021-04-01

Fixed bug that caused errors on sites with a `baseUrl` setting. Declared stable.

## 1.0.0-beta.1

Beta release for evaluation.
