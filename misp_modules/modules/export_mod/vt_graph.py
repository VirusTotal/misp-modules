'''Export MISP event to VirusTotal Graph.'''


import base64
import json
from lib.vt_graph_parser import from_pymisp_response


misperrors = {
    'error': 'Error'
}
moduleinfo = {
    'version': '0.1',
    'author': 'VirusTotal',
    'description': 'Send event to VirusTotal Graph',
    'module-type': ['export']
}
mispattributes = {
    'input': [
        'hostname',
        'domain',
        'ip-src',
        'ip-dst',
        'md5',
        'sha1',
        'sha256',
        'url',
        'filename|md5',
        'filename'
    ]
}
moduleconfig = [
    'vt_api_key',
    'fetch_information',
    'private',
    'fetch_vt_enterprise',
    'expand_one_level',
    'user_editors',
    'user_viewers',
    'group_editors',
    'group_viewers'
]


def handler(q=False):
  """Expansion handler.

  Args:
    q (bool, optional): module data. Defaults to False.

  Returns:
    [str]: VirusTotal graph links
  """
  if not q:
    return False
  request = json.loads(q)

  if not request.get('config') or not request['config'].get('vt_api_key'):
    misperrors['error'] = 'A VirusTotal api key is required for this module.'
    return misperrors

  config = request['config']

  api_key = config.get('vt_api_key')
  fetch_information = config.get('fetch_information') or False
  private = config.get('private') or False
  fetch_vt_enterprise = config.get('fetch_vt_enterprise') or False
  expand_one_level = config.get('expand_one_level') or False

  user_editors = config.get('user_editors')
  if user_editors:
    user_editors = user_editors.split(',')
  user_viewers = config.get('user_viewers')
  if user_viewers:
    user_viewers = user_viewers.split(',')
  group_editors = config.get('group_editors')
  if group_editors:
    group_editors = group_editors.split(',')
  group_viewers = config.get('group_viewers')
  if group_viewers:
    group_viewers = group_viewers.split(',')
  

  graphs = from_pymisp_response(
      request, api_key, fetch_information=fetch_information,
      private=private, fetch_vt_enterprise=fetch_vt_enterprise,
      user_editors=user_editors, user_viewers=user_viewers,
      group_editors=group_editors, group_viewers=group_viewers,
      expand_node_one_level=expand_one_level)
  links = []

  for graph in graphs:
    graph.save_graph()
    links.append(graph.get_ui_link())

  # This file will contains one VirusTotal graph link for each exported event
  file_data = str(base64.b64encode(bytes('\n'.join(links), 'utf-8')), 'utf-8')
  return {'response': [], 'data': file_data}


def introspection():
  modulesetup = {
      'responseType': 'application/txt',
      'outputFileExtension': 'txt',
      'userConfig': {},
      'inputSource': []
  }
  return modulesetup


def version():
  moduleinfo['config'] = moduleconfig
  return moduleinfo
