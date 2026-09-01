"""Technology fingerprints.

Each signature lists categories and a set of matchers. A matcher may capture a
version with a regex group named ``version`` (or group 1), which is what the
version-based CVE lookup consumes.

Matcher keys:
  header   {header-name: regex}
  cookie   {cookie-name-regex: regex or ""}
  html     [regex, ...]         matched against the response body
  script   [regex, ...]         matched against <script src> values
  meta     {meta-name: regex}
  url      [regex, ...]         matched against the page URL
  implies  [technology, ...]    additional technologies to report
"""
from __future__ import annotations

SIGNATURES: list[dict] = [
    # ---- Web servers / reverse proxies -------------------------------------
    {"name": "Nginx", "cpe": "nginx", "categories": ["Web servers", "Reverse proxies"],
     "header": {"Server": r"(?i)\bnginx(?:/(?P<version>[\d.]+))?"}},
    {"name": "Apache", "cpe": "apache:http_server", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bApache(?:/(?P<version>[\d.]+))?"}},
    {"name": "Microsoft IIS", "cpe": "microsoft:internet_information_services",
     "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bMicrosoft-IIS(?:/(?P<version>[\d.]+))?"}},
    {"name": "LiteSpeed", "cpe": "litespeedtech:litespeed_web_server", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bLiteSpeed(?:/(?P<version>[\d.]+))?"}},
    {"name": "OpenResty", "cpe": "openresty:openresty", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bopenresty(?:/(?P<version>[\d.]+))?"}},
    {"name": "Caddy", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bCaddy\b"}},
    {"name": "Cloudflare", "categories": ["CDN", "Reverse proxies"],
     "header": {"Server": r"(?i)^cloudflare", "CF-Ray": r".+"}},
    {"name": "Varnish", "categories": ["Caching"],
     "header": {"Via": r"(?i)varnish", "X-Varnish": r".+"}},
    {"name": "Envoy", "categories": ["Reverse proxies"],
     "header": {"Server": r"(?i)^envoy"}},
    {"name": "Gunicorn", "cpe": "gunicorn:gunicorn", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bgunicorn(?:/(?P<version>[\d.]+))?"}},
    {"name": "Werkzeug", "cpe": "palletsprojects:werkzeug", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bWerkzeug(?:/(?P<version>[\d.]+))?"}},
    {"name": "Apache Tomcat", "cpe": "apache:tomcat", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\b(?:Apache-Coyote|Tomcat)(?:/(?P<version>[\d.]+))?"}},
    {"name": "Jetty", "cpe": "eclipse:jetty", "categories": ["Web servers"],
     "header": {"Server": r"(?i)\bJetty(?:\((?P<version>[\d.]+)\))?"}},

    # ---- Operating systems --------------------------------------------------
    {"name": "Ubuntu", "categories": ["Operating systems"],
     "header": {"Server": r"(?i)\(Ubuntu\)"}},
    {"name": "Debian", "categories": ["Operating systems"],
     "header": {"Server": r"(?i)\(Debian\)"}},
    {"name": "CentOS", "categories": ["Operating systems"],
     "header": {"Server": r"(?i)\(CentOS\)"}},
    {"name": "Red Hat", "categories": ["Operating systems"],
     "header": {"Server": r"(?i)\(Red Hat\)"}},
    {"name": "Windows Server", "categories": ["Operating systems"],
     "header": {"Server": r"(?i)Microsoft-IIS"}},

    # ---- Languages / app servers -------------------------------------------
    {"name": "PHP", "cpe": "php:php", "categories": ["Programming languages"],
     "header": {"X-Powered-By": r"(?i)\bPHP(?:/(?P<version>[\d.]+))?"},
     "cookie": {"PHPSESSID": ""}},
    {"name": "ASP.NET", "cpe": "microsoft:asp.net", "categories": ["Web frameworks"],
     "header": {"X-AspNet-Version": r"(?P<version>[\d.]+)",
                "X-Powered-By": r"(?i)\bASP\.NET"},
     "cookie": {"ASP.NET_SessionId": ""}},
    {"name": "Node.js", "cpe": "nodejs:node.js", "categories": ["Programming languages"],
     "header": {"X-Powered-By": r"(?i)^Express|\bNode\.js"}},
    {"name": "Express", "cpe": "expressjs:express", "categories": ["Web frameworks"],
     "header": {"X-Powered-By": r"(?i)^Express"}},
    {"name": "Django", "cpe": "djangoproject:django", "categories": ["Web frameworks"],
     "cookie": {"csrftoken": "", "django_language": ""}},
    {"name": "Ruby on Rails", "cpe": "rubyonrails:rails", "categories": ["Web frameworks"],
     "header": {"X-Powered-By": r"(?i)\bPhusion Passenger"},
     "cookie": {"_rails_session": "", "_session_id": ""}},
    {"name": "Laravel", "cpe": "laravel:laravel", "categories": ["Web frameworks"],
     "cookie": {"laravel_session": "", "XSRF-TOKEN": ""}},
    {"name": "Flask", "cpe": "palletsprojects:flask", "categories": ["Web frameworks"],
     "cookie": {"session": r"^\.?eJ"}},

    # ---- JavaScript frameworks ---------------------------------------------
    {"name": "Next.js", "cpe": "vercel:next.js",
     "categories": ["JavaScript frameworks", "Web frameworks", "Static site generator"],
     "header": {"X-Powered-By": r"(?i)\bNext\.js(?:\s*(?P<version>[\d.]+))?"},
     "html": [r'<script[^>]+id="__NEXT_DATA__"', r'"buildId"\s*:', r'/_next/static/'],
     "implies": ["React"]},
    {"name": "Next.js App Router", "categories": ["JavaScript frameworks", "Web servers"],
     "html": [r'self\.__next_f', r'/_next/static/chunks/app/']},
    {"name": "Nuxt.js", "categories": ["JavaScript frameworks"],
     "html": [r'window\.__NUXT__', r'/_nuxt/'], "implies": ["Vue.js"]},
    {"name": "React", "cpe": "facebook:react", "categories": ["JavaScript frameworks"],
     "html": [r'data-reactroot', r'data-reactid', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
     "script": [r'/react(?:-dom)?[.@-](?P<version>[\d.]+)?[.\-]?(?:production|development|min)?\.js']},
    {"name": "Vue.js", "cpe": "vuejs:vue", "categories": ["JavaScript frameworks"],
     "html": [r'data-v-[0-9a-f]{8}', r'<div[^>]+id="app"[^>]*data-server-rendered'],
     "script": [r'/vue@?(?P<version>[\d.]+)?[./]']},
    {"name": "Angular", "cpe": "angular:angular", "categories": ["JavaScript frameworks"],
     "html": [r'ng-version="(?P<version>[\d.]+)"', r'<app-root', r'\bng-app\b']},
    {"name": "Svelte", "categories": ["JavaScript frameworks"],
     "html": [r'svelte-[0-9a-z]{6}', r'/_app/immutable/']},
    {"name": "jQuery", "cpe": "jquery:jquery", "categories": ["JavaScript libraries"],
     "script": [r'jquery[.\-]?(?P<version>\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js'],
     "html": [r'jQuery v?(?P<version>[\d.]+)']},
    {"name": "Bootstrap", "cpe": "getbootstrap:bootstrap", "categories": ["UI frameworks"],
     "script": [r'bootstrap[.\-]?(?P<version>\d+\.\d+(?:\.\d+)?)?(?:\.bundle)?(?:\.min)?\.js'],
     "html": [r'Bootstrap v(?P<version>[\d.]+)']},
    {"name": "Webpack", "categories": ["Miscellaneous"],
     "html": [r'webpackJsonp', r'__webpack_require__', r'/static/chunks/webpack-']},
    {"name": "Tailwind CSS", "categories": ["UI frameworks"],
     "html": [r'(?:class="[^"]*\b(?:flex|grid)\b[^"]*\b(?:items-center|justify-between)\b)']},

    # ---- CMS ----------------------------------------------------------------
    {"name": "WordPress", "cpe": "wordpress:wordpress", "categories": ["CMS", "Blogs"],
     "html": [r'/wp-content/', r'/wp-includes/'],
     "meta": {"generator": r"(?i)WordPress(?:\s+(?P<version>[\d.]+))?"}},
    {"name": "Drupal", "cpe": "drupal:drupal", "categories": ["CMS"],
     "html": [r'/sites/(?:all|default)/', r'Drupal\.settings'],
     "meta": {"generator": r"(?i)Drupal(?:\s+(?P<version>[\d.]+))?"},
     "header": {"X-Generator": r"(?i)Drupal(?:\s+(?P<version>[\d.]+))?"}},
    {"name": "Joomla", "cpe": "joomla:joomla", "categories": ["CMS"],
     "html": [r'/media/jui/', r'/components/com_'],
     "meta": {"generator": r"(?i)Joomla!?(?:\s+(?P<version>[\d.]+))?"}},
    {"name": "Shopify", "categories": ["Ecommerce"],
     "html": [r'cdn\.shopify\.com', r'Shopify\.theme'],
     "header": {"X-ShopId": r".+"}},
    {"name": "Ghost", "categories": ["CMS"],
     "meta": {"generator": r"(?i)Ghost(?:\s+(?P<version>[\d.]+))?"}},

    # ---- Hosting / platform -------------------------------------------------
    {"name": "Vercel", "categories": ["PaaS"],
     "header": {"X-Vercel-Id": r".+", "Server": r"(?i)^Vercel"}},
    {"name": "Netlify", "categories": ["PaaS"],
     "header": {"Server": r"(?i)^Netlify", "X-Nf-Request-Id": r".+"}},
    {"name": "Amazon CloudFront", "categories": ["CDN"],
     "header": {"X-Amz-Cf-Id": r".+", "Via": r"(?i)cloudfront"}},
    {"name": "Amazon S3", "categories": ["PaaS"],
     "header": {"Server": r"(?i)^AmazonS3"}},
    {"name": "Google Cloud", "categories": ["PaaS"],
     "header": {"Server": r"(?i)^(?:Google Frontend|gws)"}},
    {"name": "Fastly", "categories": ["CDN"],
     "header": {"X-Served-By": r"(?i)cache-", "Via": r"(?i)varnish.*fastly"}},

    # ---- Analytics / marketing ---------------------------------------------
    {"name": "Google Analytics", "categories": ["Analytics"],
     "html": [r'google-analytics\.com/(?:ga|analytics)\.js', r'gtag\(\s*[\'"]config'],
     "script": [r'googletagmanager\.com/gtag/js']},
    {"name": "Google Tag Manager", "categories": ["Tag managers"],
     "html": [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]{4,}']},
    {"name": "Open Graph", "categories": ["Miscellaneous"],
     "html": [r'<meta[^>]+property=["\']og:']},

    # ---- Security / performance signals ------------------------------------
    {"name": "HSTS", "categories": ["Security"],
     "header": {"Strict-Transport-Security": r".+"}},
    {"name": "Basic Security", "categories": ["Security"],
     "header": {"X-Content-Type-Options": r".+", "X-Frame-Options": r".+"}},
    {"name": "Priority Hints", "categories": ["Performance"],
     "html": [r'<(?:link|img|script)[^>]+fetchpriority=']},
    {"name": "HTTP/3", "categories": ["Performance"],
     "header": {"Alt-Svc": r"(?i)h3"}},
    {"name": "PWA", "categories": ["Miscellaneous"],
     "html": [r'<link[^>]+rel=["\']manifest["\']']},
]
