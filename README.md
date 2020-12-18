# apostrophe-security-headers

## Purpose

This module sends the modern HTTP security headers that are expected by various security scanners. The default settings are compatible with the needs of Apostrophe 2.x and as such are fairly permissive.

## Warning

Some third-party services, including Google Analytics, Google Fonts, YouTube and Vimeo, are included in the standard configuration. However even with these permissive settings, not all third-party services compatible with Apostrophe will be permitted out of the box. For instance, because they are used relatively rarely, no special testing has been done for Wufoo or Infogram. You should test your site and configure custom policies accordingly.

## Installation

```
npm install apostrophe-security-headers
```

## Configuration

To enable the module with its standard behavior:

```javascript
// in app.js
modules: {
  'apostrophe-security-headers': {}
}
```

The headers can be overridden by setting them as options to the module:

```javascript
// in app.js
modules: {
  'apostrophe-security-headers': {
    'X-Frame-Options': 'DENY'
  }
}
```

You can also disable a header entirely by setting the option to `false`.

The `Content-Security-Policy` header is more complex. The default response for it is the result of merging together options for individual use cases as shown below. However you may also simply set a string for it to override all of that. Bear in mind that Apostrophe 2.x and CKEditor 4.x inherently require `unsafe-inline` and `unsafe-eval` permissions for script tags.

## Default Behavior

Here are the headers that are sent by default, with their default values:

```javascript
  // 1 year. Do not include subdomains as they could be unrelated sites
  'Strict-Transport-Security': 'max-age=31536000',
  // You may also set to DENY, if you are not using features such
  // as iframe preview of commits in apostrophe-workflow
  'X-Frame-Options': 'SAMEORIGIN',
  // If you have issues with broken images etc., make sure content type
  // configuration is correct for your production server
  'X-Content-Type-Options': 'nosniff',
  // Very new. Used to entirely disable browser features like geolocation per host.
  // Since we don't know what your site may need, we don't try to set this
  // header by default (false means "don't send the header")
  'Permissions-Policy': false,
  // Don't send a "Referer" (sp) header unless the new URL shares the same
  // origin. You can set this to `false` if you prefer cross-origin "Referer"
  // headers be sent. Apostrophe does not rely on them
  'Referrer-Policy': 'same-origin',
  // `true` means it should be computed according to the rules below.
  // You may also pass your own string, or `false` to not send this header.
  'Content-Security-Policy': true,
  // All options ending in "Policies" are merged together as Content-Security-Policy
  // rules like those below. You can set any of these to `false` to block them,
  // or introduce your own like "customPolicies".
  //
  // Note the HOSTS wildcard which matches all expected hosts, including CDN hosts
  // and workflow hostnames known to Apostrophe, as well as `self`.
  //
  // Policies of the same type from different options are merged, with the largest set of
  // keywords and hosts enabled. This is done because browsers do not support more than one
  // style-src policy, for example, but do support specifying several hosts in one policy.

  defaultPolicies: {
    'default-src': `HOSTS`,
    'style-src': `'unsafe-inline' HOSTS`,
    'script-src': `'unsafe-inline' 'unsafe-eval' HOSTS`,
    'font-src': `HOSTS`,
    'frame-src': `'self'`
  },

  // Set this option to false if you wish to forbid google fonts
  googleFontsPolicies: {
    'style-src': 'fonts.googleapis.com',
    'font-src': 'fonts.gstatic.com'
  },

  // Set this option to false if you do not plan to embed youtube video.
  // Note this will break the Apostrophe video widget
  oembedPolicies: {
    'frame-src': '*.youtube.com *.vimeo.com'
  },

  // Set this option to false if you are not interested in Google Analytics
  // or Google Tag Manager
  analyticsPolicies: {
    'default-src': '*.google-analytics.com *.doubleclick.net',
    // Note that use of google tag manager by definition brings in scripts from
    // more third party sites and you will need to add policies for them
    'script-src': '*.google-analytics.com *.doubleclick.net *.googletagmanager.com'
  }
```

## Custom Policies

You may add any number of custom policies. Any opotion to this module with a name ending in `Policies` is treated just like the standard cases above.

## Disabling Standard Policies

You may set any of the standard policy options above to `false` to disable them.

## Hosts Wildcard

Note that the `HOSTS` wildcard is automaticalably replaced with a list of hosts including any `baseUrl` host, workflow hostnames for specific locales, CDN hosts from your uploadfs configuration, and `self`. Use of this wildcard is recommended as Apostrophe pushes assets to Amazon S3, CDNs, etc. when configured to do so, including scripts and stylesheets.

> You may override the normal list of hosts for `HOSTS` by setting the `legitimateHosts` option to an array of strings. You could also extend the `legitimateHosts` method of this module at project level.
