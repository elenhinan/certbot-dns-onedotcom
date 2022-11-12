"""DNS Authenticator for One.com"""
#import json
import logging

import requests

from certbot import errors
from certbot.plugins import dns_common
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for One.com
    This Authenticator uses the One.com Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using One.com for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="One.com credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the One.com Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "One.com credentials INI file",
            {
                "username": "Username for One.com",
                "password": "Password for One.com",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_onedotcom_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_onedotcom_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_onedotcom_client(self):
        return _OneDotComClient(
            self.credentials.conf("username"),
            self.credentials.conf("password"),
        )


class _OneDotComClient(object):
    """
    Encapsulates all communication with the One.com Remote REST API.
    """

    def __init__(self, username, password):
        logger.debug("creating onedotcomclient")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.logged_in = False

    def _login(self):
        if self.logged_in:
            return
        logger.debug("logging in")
        login_url = "https://www.one.com/admin/login.do"
        logindata = {
            "username": self.username,
            "password": self.password,
            "credentialId": ""
        }
        resp = self.session.get(login_url)
        parsed_html = BeautifulSoup(resp.content, features="html.parser")
        login_url_post = parsed_html.body.find('form', attrs={'class':'login'}).attrs['action']
        resp = self.session.post(login_url_post, data=logindata)
        if resp.ok:
            logger.debug("logged in")
            self.logged_in = True
        else:
            raise errors.PluginError('Could not log in')

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        self._login()
        logger.info("insert new txt record for domain %s", domain)
        dns_url = f"https://www.one.com/admin/api/domains/{domain}/dns/custom_records"
        
        # strip domain from record name
        prefix = record_name[:-len('.'+domain)]

        id = self._get_record_id(domain, record_name)
        record_ttl = max(record_ttl,600) # One.com mimunium 600s ttl

        record_data = {
            "attributes": {
                "content": record_content,
                "prefix": prefix,
                "priority": 0,
                "ttl": record_ttl,
                "type": "TXT"
            },
            "type": "dns_custom_records"
        }
        
        # if already in records, update
        if id:
            record_data['id'] = id
            resp = self.session.patch(f"{dns_url}/{id}",json=record_data)
            if resp.ok:
                logger.debug("updated TXT record %s", id)
            else:
                raise errors.PluginError(f'Could not update record {record_data}')
        # if not in records, create new
        else:
            resp = self.session.post(dns_url,json=record_data)
            if resp.ok:
                id = resp.json()['result']['data']['id']
                logger.info("added TXT record %s", id)
            else:
                raise errors.PluginError(f'Could not add record {record_data}')

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Delete a TXT record using the supplied information.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the ISPConfig API
        """
        self._login()
        dns_url = f"https://www.one.com/admin/api/domains/{domain}/dns/custom_records"
        id = self._get_record_id(domain, record_name)
        if id:
            record_url = f"{dns_url}/{id}"
            resp = self.session.delete(record_url)
            if resp.ok:
                logger.debug("deleted TXT record: %s", id)

    def _get_record_id(self, domain, record_name):
        """
        Find One.com record ID, if it exist.
        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :return ID or None
        """
        self._login()

        # strip domain from record name
        prefix = record_name[:-len('.'+domain)]

        dns_url = f"https://www.one.com/admin/api/domains/{domain}/dns/custom_records"
        resp = self.session.get(dns_url)

        if resp.ok:
            logger.debug('fetched dns records')
            dns_records = resp.json()['result']['data']
            for dns_record in dns_records:
                if dns_record['attributes']['prefix'] == prefix:
                    self.acme_key = dns_record
                    id = dns_record['id']
                    logger.debug('Record id %s', id)
                    return id
        logger.debug('Record not found')
        return None
