"""Small built-in wordlists. A user list (--wordlist) overrides these."""
from __future__ import annotations

from pathlib import Path

SUBDOMAINS = """www mail ftp webmail smtp pop imap ns1 ns2 dns admin portal api
api-dev dev test staging stage qa uat demo beta app apps m mobile shop store blog
news cdn static assets img images media video vpn remote gateway gw secure login
auth sso account accounts dashboard panel cpanel whm plesk phpmyadmin db database
mysql sql git gitlab jenkins ci docker registry k8s kube grafana kibana prometheus
status monitor monitoring metrics logs elastic search solr redis cache mq rabbit
support help docs wiki kb forum community chat mail2 mx mx1 mx2 relay backup old
new internal intranet extranet partner partners crm erp hr finance billing pay
payment payments checkout ftp2 sftp ssh proxy edge origin lb node1 node2 web web1
web2 srv server1 server2 host cloud aws azure gcp s3 storage files download uploads
""".split()

DIRECTORIES = """admin administrator login wp-admin wp-login.php wp-content wp-includes
backup backups bak old test tmp temp dev config configuration settings setup install
uploads files download downloads assets static images img js css api api/v1 api/v2
graphql swagger swagger-ui.html openapi.json api-docs docs documentation phpinfo.php
info.php server-status server-info .git .git/config .svn .env .env.local .htaccess
.htpasswd web.config robots.txt sitemap.xml crossdomain.xml .well-known composer.json
composer.lock package.json yarn.lock Dockerfile docker-compose.yml .DS_Store
readme.md README.md CHANGELOG.md LICENSE db database dump.sql backup.sql data
private secret secrets internal debug console shell cmd portal dashboard panel
cpanel user users account accounts profile register signup logout admin.php
config.php configuration.php settings.php wp-config.php.bak error_log access_log
""".split()

# Fingerprints for dangling-resource subdomain takeover. Each entry maps a service
# to the CNAME markers and the response body/error that indicates an unclaimed
# resource. Sourced from the widely used can-i-take-over-xyz research.
TAKEOVER_SIGNATURES = [
    ("GitHub Pages", ["github.io"], ["There isn't a GitHub Pages site here",
                                      "For root URLs (like http://example.com/) you must provide an index.html file"]),
    ("Amazon S3", ["amazonaws.com"], ["NoSuchBucket", "The specified bucket does not exist"]),
    ("Heroku", ["herokuapp.com", "herokudns.com"], ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    ("Amazon CloudFront", ["cloudfront.net"], ["The request could not be satisfied", "ERROR: The request could not be satisfied"]),
    ("Fastly", ["fastly.net"], ["Fastly error: unknown domain"]),
    ("Shopify", ["myshopify.com"], ["Sorry, this shop is currently unavailable", "Only one step left!"]),
    ("Zendesk", ["zendesk.com"], ["Help Center Closed"]),
    ("GitLab Pages", ["gitlab.io"], ["The page you're looking for could not be found"]),
    ("Pantheon", ["pantheonsite.io"], ["The gods are wise, but do not know of the site which you seek"]),
    ("Tumblr", ["domains.tumblr.com"], ["Whatever you were looking for doesn't currently exist at this address"]),
    ("Wordpress", ["wordpress.com"], ["Do you want to register"]),
    ("Ghost", ["ghost.io"], ["The thing you were looking for is no longer here, or never was"]),
    ("Surge.sh", ["surge.sh"], ["project not found"]),
    ("Bitbucket", ["bitbucket.io"], ["Repository not found"]),
    ("Netlify", ["netlify.app", "netlify.com"], ["Not Found - Request ID"]),
    ("Vercel", ["vercel.app", "vercel-dns.com"], ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"]),
    ("Readthedocs", ["readthedocs.io"], ["unknown to Read the Docs"]),
    ("Azure", ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"],
     ["404 Web Site not found", "The specified blob does not exist"]),
]


def load_words(builtin: list[str], path: str = "") -> list[str]:
    if not path:
        return builtin
    lines = Path(path).read_text(errors="replace").splitlines()
    words = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    return words or builtin
