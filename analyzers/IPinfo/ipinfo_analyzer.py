#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from ipinfo import IPinfoException, IPinfo


class IPinfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "IPinfo service is missing")

        self.api_key = self.get_param(
            "config.api_key", None, "IPinfo API key is missing")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "IPinfo"

        if self.service == "details":
            geo = raw.get("geo", {})
            country = geo.get("country")
            if country:
                taxonomies.append(
                    self.build_taxonomy(level, namespace, "Country", country)
                )

            asn = raw.get("asn", {})
            if asn and asn.get("asn"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "ASN", asn.get("asn"))
                )
            if asn and asn.get("type"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "ASNType", asn.get("type"))
                )
            company = raw.get("company")
            if company and company.get("name"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "Company", company.get("name"))
                )
            anonymous = raw.get("anonymous")
            if anonymous and anonymous.get("is_vpn"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, 'suspicious', "VPN", anonymous.get("is_vpn"))
                )
            if anonymous and anonymous.get("is_tor"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, 'malicious', "TOR", anonymous.get("is_tor"))
                )
            if anonymous and anonymous.get("is_proxy"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, 'suspicious', "Proxy", anonymous.get("is_proxy"))
                )
            if anonymous and anonymous.get("is_res_proxy"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, 'malicious', "Res-Proxy", anonymous.get("is_res_proxy"))
                )
            if anonymous and anonymous.get("is_relay"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, 'suspicious', "Relay", anonymous.get("is_relay"))
                )
            if raw.get("is_hosting"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "Hosting", anonymous.get("is_hosting"))
                )
            if anonymous and anonymous.get("name"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "PrivacyService", anonymous.get("name"))
                )

        elif self.service == "hosted_domains":
            total = 0
            if "domains" in raw:
                total = len(raw["domains"])

            if total < 2:
                value = "{} record".format(total)
            else:
                value = "{} records".format(total)

            taxonomies.append(
                self.build_taxonomy(level, namespace, "HostedDomains", value)
            )

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            ipinfo = IPinfo(api_key=self.api_key)

            if self.service == "details":
                result = ipinfo.details(data)
                self.report(result)
            elif self.service == "hosted_domains":
                result = ipinfo.hosted_domains(data)
                self.report(result)
            else:
                self.error("Unknown IPinfo service")

        except IPinfoException as e:
            self.error(str(e))


if __name__ == "__main__":
    IPinfoAnalyzer().run()
