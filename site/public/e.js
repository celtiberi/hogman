// First-party cookieless traffic analytics via /e (Caddy reverse proxy).
(() => {
  const isDev = location.hostname === 'localhost' || location.hostname === '127.0.0.1';

  const loadPostHog = (token) => {
    !(function (t, e) {
      var o, n, p, r;
      e.__SV ||
        ((window.posthog = e),
        (e._i = []),
        (e.init = function (i, s, a) {
          function g(t, e) {
            var o = e.split('.');
            2 == o.length && ((t = t[o[0]]), (e = o[1]));
            t[e] = function () {
              t.push([e].concat(Array.prototype.slice.call(arguments, 0)));
            };
          }
          (p = t.createElement('script')).type = 'text/javascript';
          p.crossOrigin = 'anonymous';
          p.async = !0;
          p.src = s.api_host + '/static/array.js';
          (r = t.getElementsByTagName('script')[0]).parentNode.insertBefore(p, r);
          var u = e;
          for (
            void 0 !== a ? (u = e[a] = []) : (a = 'posthog'),
              u.people = u.people || [],
              Object.defineProperty(u, 'toString', {
                configurable: !0,
                enumerable: !0,
                writable: !0,
                value: function (t) {
                  var e = 'posthog';
                  return 'posthog' !== a && (e += '.' + a), t || (e += ' (stub)'), e;
                },
              }),
              Object.defineProperty(u.people, 'toString', {
                configurable: !0,
                enumerable: !0,
                writable: !0,
                value: function () {
                  return u.toString(1) + '.people (stub)';
                },
              }),
              o =
                'capture identify alias people.set people.set_once set_config register register_once unregister opt_out_capturing has_opted_out_capturing opt_in_capturing reset isFeatureEnabled onFeatureFlags getFeatureFlag getFeatureFlagResult reloadFeatureFlags group updateEarlyAccessFeatureEnrollment getEarlyAccessFeatures getActiveMatchingSurveys getSurveys getNextSurveyStep onSessionId'.split(
                  ' '
                ),
              n = 0;
            n < o.length;
            n++
          )
            g(u, o[n]);
          e._i.push([i, s, a]);
        }),
        (e.__SV = 1));
    })(document, window.posthog || []);

    window.posthog.init(token, {
      api_host: '/e',
      ui_host: 'https://us.posthog.com',
      cookieless_mode: 'always',
      person_profiles: 'identified_only',
      capture_pageview: true,
      capture_pageleave: true,
      autocapture: true,
      disable_session_recording: true,
      disable_surveys: true,
    });
  };

  fetch('/e/cfg', { cache: 'no-store' })
    .then((r) => (r.ok ? r.json() : null))
    .then((cfg) => {
      const token = cfg && typeof cfg.token === 'string' ? cfg.token.trim() : '';
      if (!token) {
        if (isDev) {
          throw new Error(
            'POSTHOG_KEY variable required by PostHog is missing or un-configured, this causes events to be silently missed. This error stops appearing once POSTHOG_KEY is configured'
          );
        }
        return;
      }
      loadPostHog(token);
    })
    .catch((err) => {
      if (isDev && err && String(err.message || '').includes('POSTHOG_KEY')) {
        throw err;
      }
    });
})();
