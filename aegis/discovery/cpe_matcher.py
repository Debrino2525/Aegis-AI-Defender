"""
Common Platform Enumeration (CPE 2.3) standardizer and generator.
Enhanced with fuzzy product name matching.
"""

from typing import Optional, Tuple
from difflib import SequenceMatcher

# Mapping of detected product names to official NVD vendor:product pairs
CPE_LOOKUP = {
    "apache": ("apache", "http_server"),
    "http_server": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "redis": ("redis", "redis"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "mongo": ("mongodb", "mongodb"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "k8s": ("kubernetes", "kubernetes"),
    "nodejs": ("nodejs", "nodejs"),
    "node.js": ("nodejs", "nodejs"),
    "express": ("expressjs", "express"),
    "spring": ("vmware", "spring_framework"),
    "spring boot": ("vmware", "spring_boot"),
    "springframework": ("vmware", "spring_framework"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "logstash": ("elastic", "logstash"),
    "kibana": ("elastic", "kibana"),
    "rabbitmq": ("rabbitmq", "rabbitmq"),
    "rabbit": ("rabbitmq", "rabbitmq"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "dovecot": ("dovecot", "dovecot"),
    "samba": ("samba", "samba"),
    "bind": ("isc", "bind"),
    "named": ("isc", "bind"),
    "powerdns": ("powerdns", "powerdns"),
    "pdns": ("powerdns", "powerdns"),
    "squid": ("squid-cache", "squid"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-cache", "varnish_cache"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddy", "caddy"),
    "traefik": ("traefik", "traefik"),
    "envoy": ("envoyproxy", "envoy"),
    "openssl": ("openssl", "openssl"),
    "libressl": ("openbsd", "libressl"),
    "golang": ("golang", "go"),
    "go": ("golang", "go"),
    "python": ("python", "python"),
    "php": ("php", "php"),
    "perl": ("perl", "perl"),
    "ruby": ("ruby", "ruby"),
    "java": ("oracle", "java_se"),
    "jdk": ("oracle", "java_se"),
    "jre": ("oracle", "java_se"),
    "openjdk": ("oracle", "openjdk"),
}


class CPEMatcher:
    """Normalizes detected software names and versions into standard CPE 2.3 strings."""

    @staticmethod
    def fuzzy_match_product(product: str, threshold: float = 0.6) -> Tuple[str, str]:
        """Performs fuzzy matching to find the best vendor:product pair."""
        product_lower = product.lower().strip()

        # Direct match first
        if product_lower in CPE_LOOKUP:
            return CPE_LOOKUP[product_lower]

        # Try fuzzy matching
        best_match = None
        best_ratio = 0.0

        for known_product, (vendor, cpe_product) in CPE_LOOKUP.items():
            # Calculate similarity ratio
            ratio = SequenceMatcher(None, product_lower, known_product).ratio()
            if ratio > best_ratio and ratio >= threshold:
                best_ratio = ratio
                best_match = (vendor, cpe_product)

        if best_match:
            return best_match

        # Fallback: use the product name as both vendor and product
        # Clean common suffixes/prefixes
        clean_product = product_lower
        clean_product = clean_product.replace(" ", "_")
        clean_product = clean_product.replace("-", "_")
        clean_product = clean_product.replace("/", "_")

        return clean_product, clean_product

    @staticmethod
    def generate_cpe(product: Optional[str], version: Optional[str]) -> Optional[str]:
        """Generates a CPE 2.3 URI string from product and version.

        Example:
            product='apache', version='2.4.49'
            -> 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*'
        """
        if not product:
            return None

        clean_prod = product.lower().strip()
        vendor, cpe_prod = CPEMatcher.fuzzy_match_product(clean_prod)

        cpe_ver = version.strip() if version else "*"
        # Clean any trailing patch notes for standard matching
        cpe_ver = cpe_ver.replace("~", "-")

        return f"cpe:2.3:a:{vendor}:{cpe_prod}:{cpe_ver}:*:*:*:*:*:*:*"

    @staticmethod
    def parse_cpe(cpe_str: str) -> Tuple[str, str, str, str]:
        """Parses CPE 2.3 string into (part, vendor, product, version)."""
        parts = cpe_str.split(":")
        if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
            return parts[2], parts[3], parts[4], parts[5]
        return "", "", "", ""
