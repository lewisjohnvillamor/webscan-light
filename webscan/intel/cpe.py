"""Detected technology name -> candidate CPE vendor:product identifiers.

A product can live under more than one vendor in the NVD dictionary (nginx is
published under both ``f5`` and ``nginx``), so each entry is a list and every
candidate is queried.
"""
from __future__ import annotations

CPE_CANDIDATES: dict[str, list[str]] = {
    "Nginx": ["f5:nginx", "nginx:nginx"],
    "Apache": ["apache:http_server"],
    "Microsoft IIS": ["microsoft:internet_information_services"],
    "LiteSpeed": ["litespeedtech:litespeed_web_server"],
    "OpenResty": ["openresty:openresty"],
    "Apache Tomcat": ["apache:tomcat"],
    "Jetty": ["eclipse:jetty"],
    "Gunicorn": ["gunicorn:gunicorn", "benoitc:gunicorn"],
    "Werkzeug": ["palletsprojects:werkzeug", "pocoo:werkzeug"],
    "PHP": ["php:php"],
    "Node.js": ["nodejs:node.js"],
    "Express": ["expressjs:express", "openjsf:express"],
    "ASP.NET": ["microsoft:asp.net"],
    "Django": ["djangoproject:django"],
    "Ruby on Rails": ["rubyonrails:rails"],
    "Laravel": ["laravel:laravel"],
    "Flask": ["palletsprojects:flask"],
    "Next.js": ["vercel:next.js"],
    "React": ["facebook:react"],
    "Vue.js": ["vuejs:vue"],
    "Angular": ["angular:angular"],
    "jQuery": ["jquery:jquery"],
    "Bootstrap": ["getbootstrap:bootstrap"],
    "WordPress": ["wordpress:wordpress"],
    "Drupal": ["drupal:drupal"],
    "Joomla": ["joomla:joomla"],
    "Ghost": ["ghost:ghost"],
}


def candidates_for(name: str, declared: str | None = None) -> list[str]:
    if name in CPE_CANDIDATES:
        return CPE_CANDIDATES[name]
    return [declared] if declared else []


def cpe_uri(vendor_product: str, version: str) -> str:
    vendor, _, product = vendor_product.partition(":")
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
