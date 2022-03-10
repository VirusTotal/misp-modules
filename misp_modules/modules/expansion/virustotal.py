import json
import requests
from urllib.parse import urlparse
from . import check_input_attribute, standard_error_message
from pymisp import MISPAttribute, MISPEvent, MISPObject

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain', "ip-src", "ip-dst", "md5", "sha1", "sha256", "url"],
                  'format': 'misp_standard'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '4', 'author': 'Hannah Ward',
              'description': 'Get information from VirusTotal',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["apikey", "event_limit", 'proxy_host', 'proxy_port', 'proxy_username', 'proxy_password']


class VTClient(object):
    class VTApiError(Exception):
        pass

    def __init__(self, api_key: str, base_url: str, proxies: dict = None) -> None:
        self.base_url = base_url
        self.headers = {
            'x-apikey': api_key,
            'x-tool': 'MISPModuleVirusTotalExpansion',
        }
        self.proxies = proxies

    @staticmethod
    def _object(cls, endpoint: str, tail: str) -> dict:
        response = requests.get(cls.base_url + endpoint + '/' + tail, headers=cls.headers, proxies=cls.proxies)
        data = response.json()
        if response.status_code is not 200:
            raise cls.VTApiError(data['error']['message'])
        return data

    @staticmethod
    def _list(cls, endpoint: str, tail: str, limit: int = 5) -> dict:
        response = requests.get(cls.base_url + endpoint + '/' + tail,
                                headers=cls.headers, proxies=cls.proxies, params={'limit': limit})
        data = response.json()
        if response.status_code is not 200:
            raise cls.VTApiError(data['error']['message'])
        return data

    def get_file_report(self, resource: str) -> dict:
        return self._object('/files', resource)

    def get_url_report(self, resource: str) -> dict:
        return self._object('/urls', resource)

    def get_domain_report(self, resource: str) -> dict:
        return self._object('/domains', resource)

    def get_ip_report(self, resource: str) -> dict:
        return self._object('/ip_addresses', resource)

    def get_file_relationship(self, resource: str, relationship: str, limit: int = None):
        return self._list('/files', resource + '/' + relationship, limit=limit)

    def get_url_relationship(self, resource: str, relationship: str, limit: int = None):
        return self._list('/urls', resource + '/' + relationship, limit=limit)

    def get_domain_relationship(self, resource: str, relationship: str, limit: int = None):
        return self._list('/domains', resource + '/' + relationship, limit=limit)

    def get_ip_relationship(self, resource: str, relationship: str, limit: int = None):
        return self._list('/ip_addresses', resource + '/' + relationship, limit=limit)


class VirusTotalParser(object):
    def __init__(self, client: VTClient, limit: int) -> None:
        self.client = client
        self.limit = limit
        self.misp_event = MISPEvent()
        self.attribute = MISPAttribute()
        self.parsed_objects = {}
        self.input_types_mapping = {'ip-src': self.parse_ip, 'ip-dst': self.parse_ip,
                                    'domain': self.parse_domain, 'hostname': self.parse_domain,
                                    'md5': self.parse_hash, 'sha1': self.parse_hash,
                                    'sha256': self.parse_hash, 'url': self.parse_url}
        self.proxies = None

    @staticmethod
    def get_total_analysis(_, analysis: dict, verdict: str) -> int:
        if not analysis:
            return 0

        count = sum([analysis.get('undetected'), analysis.get('suspicious'), analysis.get('harmless')])
        file_is_trusted = verdict == 'goodware'

        return count if file_is_trusted else count + analysis.get('malicious')

    def query_api(self, attribute: dict) -> None:
        self.attribute.from_dict(**attribute)
        self.input_types_mapping[self.attribute.type](self.attribute.value)

    def get_result(self) -> dict:
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    def add_vt_report(self, response) -> str:
        data = response['data']['attributes']
        analysis = data['last_analysis_results']

        vt_object = MISPObject('virustotal-report')
        vt_object.add_attribute('permalink', type='link', value=response['data']['links']['self'])
        malicious = analysis['malicious']
        total = self.get_total_analysis(analysis, data.get('trusted_verdict'))
        detection_ratio = f'{malicious}/{total}'
        vt_object.add_attribute('detection-ratio', type='text', value=detection_ratio, disable_correlation=True)
        self.misp_event.add_object(**vt_object)
        return vt_object.uuid

    def create_file_object(self, response: dict) -> MISPObject:
        vt_uuid = self.add_vt_report(response)
        data = response['data']['attributes']
        file_object = MISPObject('file')

        for hash_type in ('md5', 'sha1', 'sha256'):
            file_object.add_attribute(**{'type': hash_type,
                                         'object_relation': hash_type,
                                         'value': data[hash_type]})
        file_object.add_reference(vt_uuid, 'analyzed-with')
        return file_object

    ################################################################################
    ####                         Main parsing functions                         #### # noqa
    ################################################################################

    def parse_domain(self, domain: str) -> str:
        response = self.client.get_domain_report(domain)
        data = response['data']['attributes']

        # DOMAIN
        domain_object = MISPObject('domain-ip')
        domain_object.add_attribute('domain', type='domain', value=self.attribute.value)

        # WHOIS
        whois = 'whois'
        if data.get(whois):
            whois_object = MISPObject(whois)
            whois_object.add_attribute('text', type='text', value=data[whois])
            self.misp_event.add_object(**whois_object)

        # SIBLINGS
        siblings = self.client.get_domain_relationship(domain, 'siblings')
        for sibling in siblings['data']:
            attr = MISPAttribute()
            attr.from_dict(**dict(type='domain', value=sibling['id']))
            self.misp_event.add_attribute(**attr)
            domain_object.add_reference(attr.uuid, 'sibling-of')

        # RESOLUTIONS
        resolutions = self.client.get_domain_relationship(domain, 'resolutions')
        for resolution in resolutions['data']:
            domain_object.add_attribute('ip', type='ip-dst', value=resolution['attributes']['ip_address'])

        # COMMUNICATING FILES
        communicating_files = self.client.get_domain_relationship(domain, 'communicating_files')
        for communicating_file in communicating_files['data']:
            file_object = self.create_file_object(communicating_file)
            file_object.add_reference(domain_object.uuid, 'communicates-with')
            self.misp_event.add_object(**file_object)

        # DOWNLOADED FILES
        downloaded_files = self.client.get_domain_relationship(domain, 'downloaded_files')
        for downloaded_file in downloaded_files['data']:
            file_object = self.create_file_object(downloaded_file)
            file_object.add_reference(domain_object.uuid, 'downloaded-from')
            self.misp_event.add_object(**file_object)

        # REFERRER FILES
        referrer_files = self.client.get_domain_relationship(domain, 'referrer_files')
        for referrer_file in referrer_files['data']:
            file_object = self.create_file_object(referrer_file)
            file_object.add_reference(domain_object.uuid, 'referring')
            self.misp_event.add_object(**file_object)

        # URLS
        urls = self.client.get_domain_relationship(domain, 'urls')
        for url in urls['data']:
            vt_uuid = self.add_vt_report(url)
            url_object = MISPObject('url')
            url_object.add_attribute('url', type='url', value=url['attributes']['url'])
            url_object.add_reference(vt_uuid, 'analyzed-with')
            url_object.add_reference(domain_object.uuid, 'hosted-in')
            self.misp_event.add_object(**url_object)

        self.misp_event.add_object(**domain_object)
        return domain_object.uuid

    def parse_hash(self, file_hash: str) -> str:
        response = self.client.get_file_report(file_hash)
        file_object = self.create_file_object(response)
        self.misp_event.add_object(**file_object)
        return file_object.uuid

    def parse_ip(self, ip: str) -> str:
        response = self.client.get_ip_report(ip)
        data = response['data']['attributes']

        # DOMAIN
        ip_object = MISPObject('domain-ip')
        ip_object.add_attribute('ip', type='ip-dst', value=self.attribute.value)

        # ASN
        asn_object = MISPObject('asn')
        asn_object.add_attribute('asn', type='AS', value=data['asn'])
        asn_object.add_attribute('subnet-announced', type='ip-src', value=data['network'])
        asn_object.add_attribute('country', type='text', value=data['country'])
        self.misp_event.add_object(**asn_object)

        # RESOLUTIONS
        resolutions = self.client.get_ip_relationship(ip, 'resolutions')
        for resolution in resolutions['data']:
            ip_object.add_attribute('domain', type='domain', value=resolution['attributes']['host_name'])

        # URLS
        urls = self.client.get_ip_relationship(ip, 'urls')
        for url in urls['data']:
            vt_uuid = self.add_vt_report(url)
            url_object = MISPObject('url')
            url_object.add_attribute('url', type='url', value=url['attributes']['url'])
            url_object.add_reference(vt_uuid, 'analyzed-with')
            url_object.add_reference(ip_object.uuid, 'hosted-in')
            self.misp_event.add_object(**url_object)

        self.misp_event.add_object(**ip_object)
        return ip_object.uuid

    def parse_url(self, url: str) -> None:
        response = self.client.get_url_report(url)
        self.add_vt_report(response)
        return None


def get_proxy_settings(config: dict) -> dict:
    """Returns proxy settings in the requests format.
    If no proxy settings are set, return None."""
    proxies = None
    host = config.get('proxy_host')
    port = config.get('proxy_port')
    username = config.get('proxy_username')
    password = config.get('proxy_password')

    if host:
        if not port:
            misperrors['error'] = 'The virustotal_proxy_host config is set, ' \
                                'please also set the virustotal_proxy_port.'
            raise KeyError
        parsed = urlparse(host)
        if 'http' in parsed.scheme:
            scheme = 'http'
        else:
            scheme = parsed.scheme
        netloc = parsed.netloc
        host = f'{netloc}:{port}'

        if username:
            if not password:
                misperrors['error'] = 'The virustotal_proxy_username config is set, ' \
                                    'please also set the virustotal_proxy_password.'
                raise KeyError
            auth = f'{username}:{password}'
            host = auth + '@' + host

        proxies = {
            'http': f'{scheme}://{host}',
            'https': f'{scheme}://{host}'
        }
    return proxies


def parse_error(status_code: int) -> str:
    status_mapping = {204: 'VirusTotal request rate limit exceeded.',
                      400: 'Incorrect request, please check the arguments.',
                      403: 'You don\'t have enough privileges to make the request.'}
    if status_code in status_mapping:
        return status_mapping[status_code]
    return "VirusTotal may not be accessible."


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'A VirusTotal api key is required for this module.'
        return misperrors
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    event_limit = request['config'].get('event_limit')
    attribute = request['attribute']

    try:
        client = VTClient(request['config']['apikey'],
                          'https://www.virustotal.com/api/v3',
                          proxies=get_proxy_settings(request.get('config')))
        parser = VirusTotalParser(client, event_limit)
        parser.query_api(attribute)
    except VTClient.VTApiError as ex:
        misperrors['error'] = str(ex)
        return misperrors

    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
