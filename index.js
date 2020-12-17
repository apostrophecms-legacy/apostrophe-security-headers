module.exports = {
  // 1 year. Do not include subdomains as they could be unrelated sites
  'Strict-Transport-Security': 'max-age=31536000',
  // You may also set to DENY, if you are not using features such
  // as iframe preview of commits in apostrophe-workflow
  'X-Frame-Options': 'SAMEORIGIN',
  'X-Content-Type-Options': 'nosniff',
  // Very new. Used to entirely disable browser features like geolocation.
  // Since we don't know what your site uses, we don't try to set this
  // header by default (false means "don't send the header")
  'Permissions-Policy': false,
  // Don't send a "Referer" (sp) header unless the new URL shares the same
  // origin. You can set this to `false` if you prefer cross-origin "Referer"
  // headers be sent. Apostrophe does not rely on them.
  'Referrer-Policy': 'same-origin',
  // `true` means it should be computed according to the Policies options,
  // shown below. You may also pass your own string, which disables all
  // Policies options, or `false` to not send this header at all.
  'Content-Security-Policy': true,
  
  // All options ending in "Policies" are pushed as Content-Security-Policy
  // rules like those below. You can set any of these to `false` to block them,
  // or introduce your own like "customPolicies".
  //
  // Note the HOSTS wildcard which matches all expected hosts including CDN hosts
  // and workflow hostnames.
  //
  // Policies of the same type from different options are merged, with the largest set of
  // keywords and hosts enabled. This is done because browsers do not support more than one
  // style-src policy, for example, but do support specifying several hosts.

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

  oembedPolicies: {
    'frame-src': '*.youtube.com *.vimeo.com'
  },

  analyticsPolicies: {
    'default-src': '*.google-analytics.com *.doubleclick.net',
    // Note that use of google tag manager by definition brings in scripts from
    // more third party sites and you will need to add policies for them
    'script-src': '*.google-analytics.com *.doubleclick.net *.googletagmanager.com',
  },

  construct(self, options) {
    self.securityHeaders = {};
    self.on('apostrophe:modulesReady', 'determineSecurityHeaders', () => {
      const simple = [
        'Strict-Transport-Security',
        'X-Frame-Options'
      ];
      for (const header of simple) {
        if (self.options[header]) {
          self.securityHeaders[header] = self.options[header];
        }
      }
      const hosts = self.legitimateHosts();
      if (self.options['Content-Security-Policy'] === true) {
        const hostsString = hosts.join(' ');
        const policies = {};
        Object.keys(self.options).filter(key => key.endsWith('Policies')).forEach(policy => {
          for (const [ key, val ] of Object.entries(self.options[policy])) {
            if (!policy) {
              continue;
            }
            if (policies[key]) {
              console.log(`appending to ${key}`);
              policies[key] += ` ${val}`;
              console.log(policies[key]);
            } else {
              policies[key] = val;
            }
          }
        });
        let flatPolicies = [];
        for (const [ key, val ] of Object.entries(policies)) {
          // Merge hosts and permissions from several 'style-src', 'default-src', etc.
          // spread over different policies like defaultPolicies and googleFontsPolicies
          const words = val.split(/\s+/);
          const newWords = [];
          console.log(key);
          console.log(words);
          for (const word of words) {
            if (!newWords.includes(word)) {
              newWords.push(word);
            }
          }
          flatPolicies.push(`${key} ${newWords.join(' ')}`);
        }
        console.log('>>', flatPolicies);
        flatPolicies = flatPolicies.map(policy => policy.replace(/HOSTS/g, hostsString));
        self.securityHeaders['Content-Security-Policy'] = flatPolicies.join('; ');
      } else if (self.options['Content-Security-Policy']) {
        self.securityHeaders['Content-Security-Policy'] = self.options['Content-Security-Policy'];
      }
    });
    self.expressMiddleware = (req, res, next) => {
      // For performance we precomputed everything
      for (const [ key, value ] of Object.entries(self.securityHeaders)) {
        res.setHeader(key, value);
      }
      return next();
    };

    self.legitimateHosts = function() {
      if (self.options.legitimateHosts) {
        return self.options.legitimateHosts;
      }
      let hosts = [];
      if (self.apos.baseUrl) {
        hosts.push(self.parseHostname(self.apos.baseUrl));
      }
      const workflow = self.apos.modules['apostrophe-workflow'];
      if (workflow) {
        hosts = [
          ...hosts,
          Object.values(workflow.options.hostnames),
          Object.keys(workflow.options.defaultLocalesByHostname)
        ];
      }
      const mediaUrl = self.apos.attachments.uploadfs.getUrl();
      if (mediaUrl.includes('//')) {
        hosts.push(self.parseHostname(mediaUrl));
      }
      // Inner quotes intentional
      hosts.push(`'self'`);
      // Keep unique
      return Array.from(new Set(hosts));
    };

    self.parseHostname = function(url) {
      const parsed = new URI(url);
      return parsed.hostname;
    };

  }
};

// NOT included because it is deprecated
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
// 'X-XSS-Protection'
