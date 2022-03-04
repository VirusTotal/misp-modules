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

    def __init__(self, api_key, proxies=None):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            'x-apikey': api_key,
            'x-tool': 'MISPModuleVirusTotalExpansion',
        }
        self.proxies = proxies

    @staticmethod
    def _object(cls, endpoint, tail):
        response = requests.get(cls.base_url + endpoint + '/' + tail, headers=cls.headers, proxies=cls.proxies)
        data = response.json()
        if response.status_code is not 200:
            raise cls.VTApiError(data['error']['message'])
        return data

    @staticmethod
    def _list(cls, endpoint, tail, limit=5):
        return requests.get(cls.base_url + endpoint + '/' + tail,
                            headers=cls.headers, proxies=cls.proxies, params={'limit': limit})

    def get_file_report(self, resource):
        return self._object('/files', resource)

    def get_url_report(self, resource):
        return self._object('/urls', resource)

    def get_domain_report(self, resource):
        return self._object('/domains', resource)

    def get_ip_report(self, resource):
        return self._object('/ip_addresses', resource)

    def get_file_relationship(self, resource, relationship, limit=None):
        return self._list('/files', resource + '/' + relationship, limit=limit)

    def get_url_relationship(self, resource, relationship, limit=None):
        return self._list('/urls', resource + '/' + relationship, limit=limit)

    def get_domain_relationship(self, resource, relationship, limit=None):
        return self._list('/domains', resource + '/' + relationship, limit=limit)

    def get_ip_relationship(self, resource, relationship, limit=None):
        return self._list('/ip_addresses', resource + '/' + relationship, limit=limit)


class VirusTotalParser(object):
    def __init__(self, client, limit):
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

    def query_api(self, attribute):
        self.attribute.from_dict(**attribute)
        misp_object = self.input_types_mapping[self.attribute.type](self.attribute.value)
        self.misp_event.add_object(**misp_object)

    def get_result(self):
        event = json.loads(self.misp_event.to_json())
        results = {key: event[key] for key in ('Attribute', 'Object') if (key in event and event[key])}
        return {'results': results}

    @staticmethod
    def get_total_analysis(_, analysis, verdict):
        if not analysis:
            return 0

        count = sum([analysis.get('undetected'), analysis.get('suspicious'),
                     analysis.get('harmless')])
        file_is_trusted = verdict == 'goodware'

        return count if file_is_trusted else count + analysis.get('malicious')

    @staticmethod
    def create_misp_attribute(_, value, attr_type):
        attribute = MISPAttribute()
        attribute.from_dict(**dict(type=attr_type, value=value))
        return attribute

    ################################################################################
    ####                         Main parsing functions                         #### # noqa
    ################################################################################

    def parse_domain_new(self, domain):
        response = self.client.get_domain_report(domain)
        data = response['data']['attributes']

        # DOMAIN
        domain_ip_object = MISPObject('domain-ip')
        domain_ip_object.add_attribute('domain', type='domain', value=self.attribute.value)

        # WHOIS
        whois = 'whois'
        if data.get(whois):
            whois_object = MISPObject(whois)
            whois_object.add_attribute('text', type='text', value=data[whois])
            self.misp_event.add_object(**whois_object)

        # SIBLINGS
        siblings = self.client.get_domain_relatioship(domain, 'siblings')
        for sibling in siblings:
            attr = self.create_misp_attribute(sibling)
            self.misp_event.add_attribute(**attr)
            domain_ip_object.add_reference(attr.uuid, 'sibling-of')

        # RESOLUTIONS
        resolutions = self.client.get_domain_relatioship(domain, 'resolutions')
        for resolution in resolutions['data']:
            domain_ip_object.add_attribute('ip', type='ip-dst', value=resolution['attributes']['ip_address'])

        # COMMUNICATING FILES
        communicating_files = self.client.get_domain_relatioship(domain, 'communicating_files')
        for communicating_file in communicating_files['data']:
            file_object = self.parse_hash_new(communicating_file['sha256'])
            file_object.add_reference(domain_ip_object.uuid, 'communicates-with')
            self.misp_event.add_object(**file_object)

        # DOWNLOADED FILES
        downloaded_files = self.client.get_domain_relatioship(domain, 'downloaded_files')
        for downloaded_file in downloaded_files['data']:
            file_object = self.parse_hash_new(downloaded_file['sha256'])
            file_object.add_reference(domain_ip_object.uuid, 'downloaded-from')
            self.misp_event.add_object(**file_object)

        # REFERRER FILES
        referrer_files = self.client.get_domain_relatioship(domain, 'referrer_files')
        for referrer_file in referrer_files['data']:
            file_object = self.parse_hash_new(referrer_file['sha256'])
            file_object.add_reference(domain_ip_object.uuid, 'referring')
            self.misp_event.add_object(**file_object)

        # URLS
        urls = self.client.get_domain_relatioship(domain, 'urls')
        for url in urls['data']:
            vt_uuid = self.parse_vt_object(url['attributes'])
            url_object = MISPObject('url')
            url_object.add_attribute('url', type='url', value=url['attributes']['url'])
            url_object.add_reference(vt_uuid, 'analyzed-with')
            url_object.add_reference(domain_ip_object.uuid, 'hosted-in')
            self.misp_event.add_object(**url_object)

        self.misp_event.add_object(**domain_ip_object)

    def parse_hash_new(self, file_hash):
        response = self.client.get_file_report(file_hash)
        data = response['data']['attributes']
        vt_uuid = self.parse_vt_object(response)
        file_object = MISPObject('file')

        for hash_type in ('md5', 'sha1', 'sha256'):
            file_object.add_attribute(**{'type': hash_type, 'object_relation': hash_type, 'value': data[hash_type]})
        file_object.add_reference(vt_uuid, 'analyzed-with')

        return file_object

    def parse_domain(self, domain, recurse=False):
        req = requests.get(self.base_url.format('domain'), params={'apikey': self.apikey, 'domain': domain}, proxies=self.proxies)
        if req.status_code != 200:
            return req.status_code
        req = req.json()
        hash_type = 'sha256'
        whois = 'whois'
        feature_types = {'communicating': 'communicates-with',
                         'downloaded': 'downloaded-from',
                         'referrer': 'referring'}
        siblings = (self.parse_siblings(domain) for domain in req['domain_siblings'])
        uuid = self.parse_resolutions(req['resolutions'], req['subdomains'] if 'subdomains' in req else None, siblings)
        for feature_type, relationship in feature_types.items():
            for feature in ('undetected_{}_samples', 'detected_{}_samples'):
                for sample in req.get(feature.format(feature_type), [])[:self.limit]:
                    status_code = self.parse_hash(sample[hash_type], False, uuid, relationship)
                    if status_code != 200:
                        return status_code
        if req.get(whois):
            whois_object = MISPObject(whois)
            whois_object.add_attribute('text', type='text', value=req[whois])
            self.misp_event.add_object(**whois_object)
        return self.parse_related_urls(req, recurse, uuid)

    def parse_hash(self, sample, recurse=False, uuid=None, relationship=None):
        req = requests.get(self.base_url.format('file'), params={'apikey': self.apikey, 'resource': sample}, proxies=self.proxies)
        status_code = req.status_code
        if req.status_code == 200:
            req = req.json()
            vt_uuid = self.parse_vt_object(req)
            file_attributes = []
            for hash_type in ('md5', 'sha1', 'sha256'):
                if req.get(hash_type):
                    file_attributes.append({'type': hash_type, 'object_relation': hash_type,
                                            'value': req[hash_type]})
            if file_attributes:
                file_object = MISPObject('file')
                for attribute in file_attributes:
                    file_object.add_attribute(**attribute)
                file_object.add_reference(vt_uuid, 'analyzed-with')
                if uuid and relationship:
                    file_object.add_reference(uuid, relationship)
                self.misp_event.add_object(**file_object)
        return status_code

    def parse_ip(self, ip, recurse=False):
        req = requests.get(self.base_url.format('ip-address'), params={'apikey': self.apikey, 'ip': ip}, proxies=self.proxies)
        if req.status_code != 200:
            return req.status_code
        req = req.json()
        if req.get('asn'):
            asn_mapping = {'network': ('ip-src', 'subnet-announced'),
                           'country': ('text', 'country')}
            asn_object = MISPObject('asn')
            asn_object.add_attribute('asn', type='AS', value=req['asn'])
            for key, value in asn_mapping.items():
                if req.get(key):
                    attribute_type, relation = value
                    asn_object.add_attribute(relation, type=attribute_type, value=req[key])
            self.misp_event.add_object(**asn_object)
        uuid = self.parse_resolutions(req['resolutions']) if req.get('resolutions') else None
        return self.parse_related_urls(req, recurse, uuid)

    def parse_url(self, url, recurse=False, uuid=None):
        req = requests.get(self.base_url.format('url'), params={'apikey': self.apikey, 'resource': url}, proxies=self.proxies)
        status_code = req.status_code
        if req.status_code == 200:
            req = req.json()
            vt_uuid = self.parse_vt_object(req)
            if not recurse:
                feature = 'url'
                url_object = MISPObject(feature)
                url_object.add_attribute(feature, type=feature, value=url)
                url_object.add_reference(vt_uuid, 'analyzed-with')
                if uuid:
                    url_object.add_reference(uuid, 'hosted-in')
                self.misp_event.add_object(**url_object)
        return status_code

    ################################################################################
    ####                      Additional parsing functions                      #### # noqa
    ################################################################################

    def parse_related_urls(self, query_result, recurse, uuid=None):
        if recurse:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        status_code = self.parse_url(value, False, uuid)
                        if status_code != 200:
                            return status_code
        else:
            for feature in ('detected_urls', 'undetected_urls'):
                if feature in query_result:
                    for url in query_result[feature]:
                        value = url['url'] if isinstance(url, dict) else url[0]
                        self.misp_event.add_attribute('url', value)
        return 200

    def parse_resolutions(self, resolutions, subdomains=None, uuids=None):
        domain_ip_object = MISPObject('domain-ip')
        if self.attribute.type in ('domain', 'hostname'):
            domain_ip_object.add_attribute('domain', type='domain', value=self.attribute.value)
            attribute_type, relation, key = ('ip-dst', 'ip', 'ip_address')
        else:
            domain_ip_object.add_attribute('ip', type='ip-dst', value=self.attribute.value)
            attribute_type, relation, key = ('domain', 'domain', 'hostname')
        for resolution in resolutions:
            domain_ip_object.add_attribute(relation, type=attribute_type, value=resolution[key])
        if subdomains:
            for subdomain in subdomains:
                attribute = MISPAttribute()
                attribute.from_dict(**dict(type='domain', value=subdomain))
                self.misp_event.add_attribute(**attribute)
                domain_ip_object.add_reference(attribute.uuid, 'subdomain')
        if uuids:
            for uuid in uuids:
                domain_ip_object.add_reference(uuid, 'sibling-of')
        self.misp_event.add_object(**domain_ip_object)
        return domain_ip_object.uuid

    def parse_siblings(self, domain):
        attribute = MISPAttribute()
        attribute.from_dict(**dict(type='domain', value=domain))
        self.misp_event.add_attribute(**attribute)
        return attribute.uuid

    def parse_vt_object(self, query_result):
        data = query_result['data']['attributes']
        analysis = data['last_analysis_results']

        vt_object = MISPObject('virustotal-report')
        vt_object.add_attribute('permalink', type='link', value=query_result['data']['links']['self'])
        detection_ratio = '{}/{}'.format(analysis['malicious'],
                                         self.get_total_analysis(analysis, data.get('trusted_verdict')))
        vt_object.add_attribute('detection-ratio', type='text', value=detection_ratio, disable_correlation=True)
        self.misp_event.add_object(**vt_object)
        return vt_object.uuid


def get_proxy_settings(self, config: dict) -> dict:
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


def parse_error(status_code):
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
        misperrors['error'] = "A VirusTotal api key is required for this module."
        return misperrors
    if not request.get('attribute') or not check_input_attribute(request['attribute']):
        return {'error': f'{standard_error_message}, which should contain at least a type, a value and an uuid.'}
    if request['attribute']['type'] not in mispattributes['input']:
        return {'error': 'Unsupported attribute type.'}

    event_limit = request['config'].get('event_limit')
    attribute = request['attribute']

    try:
        client = VTClient(request['config']['apikey'], proxies=get_proxy_settings(request.get('config')))
        parser = VirusTotalParser(client, event_limit)
        parser.query_api(attribute)
    except VTClient.VTApiError as ex:
        misperrors['error'] = ex
        return misperrors

    return parser.get_result()


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
