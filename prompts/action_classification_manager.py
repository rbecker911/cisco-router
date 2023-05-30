import requests
import xmltodict
from urllib.parse import urljoin

from QualysVMParser import QualysVMParser
from UtilsManager import filter_old_alerts
from constants import ENDPOINTS
from QualysVMExceptions import QualysVMManagerError

# ============================== CONSTS ===================================== #

HEADERS = {
    'X-Requested-With': 'Siemplify'
}
COMPLETED = "finished"
ERROR_STATES = ["error", "canceled", "paused"]

# ============================= CLASSES ===================================== #


class QualysVMManager(object):
    """
    QualysVM Manager
    """
    def __init__(self, server_address, username, password, use_ssl=False, siemplify_logger=None):
        self.server_address = server_address
        self.session = requests.Session()
        self.session.verify = use_ssl
        self.session.auth = (username, password)
        self.session.headers.update(HEADERS)
        self.parser = QualysVMParser()
        self.logger = siemplify_logger

    def test_connectivity(self):
        """
        Test connectivity to QualysVM
        :return: {bool} True if successful, exception otherwise.
        """
        self.list_reports()
        return True
        
    def get_vulnerabilities(self, existing_ids, include_ignored, include_disabled, status_filter):
        """
        Get vulnerabilities.
        :param existing_ids: {list} The list of existing ids
        :param include_ignored: {bool} If enabled, will ingest ignored detections
        :param include_disabled: {bool} If enabled, will ingest disabled detections
        :param status_filter: {str} To filter detections by status
        :return: {list} The list of filtered Detection objects
        """
        request_url = self._get_full_url('get_detections')
        payload = {
            "action": "list",
            "truncation_limit": 0,
            "include_ignored": int(include_ignored),
            "include_disabled": int(include_disabled),
            "output_format": "CSV_NO_METADATA"
        }

        if status_filter:
            payload["status"] = status_filter

        response = self.session.post(request_url, data=payload)
        self.validate_response(response, 'Unable to get vulnerabilities')

        detections = self.parser.build_detections_list(raw_data=response.content.decode('utf-8'))
        filtered_alerts = filter_old_alerts(logger=self.logger, alerts=detections, existing_ids=existing_ids)
        return filtered_alerts

    def get_host_details(self, ip):
        """
        Get host details
        :param ip :{str} The ip of the host to get details about.
        :return: {dict} The host details
        """
        url = "{}/api/2.0/fo/asset/host/".format(self.server_address)
        params = {
            'action': 'list',
            'details': 'All',
            'ips': ip,
            'show_tags':1,
            'host_metadata':"all",
            'show_cloud_tags':1,
            'truncation_limit':1000
            
        }

        params = {k: v for k, v in params.items() if v}
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to host {} details".format(ip))

        hosts = xmltodict.parse(response.content, dict_constructor=dict).get(
            'HOST_LIST_OUTPUT', {}).get('RESPONSE', {}).get('HOST_LIST', [])

        if hosts:
            return self.parser.build_host_object(hosts.get("HOST"))

        raise QualysVMManagerError("Host {} was not found".format(ip))

    def fetch_report(self, report_id):
        """
        Download a report
        :param report_id: {str} The id of the report to download
        :return: {str} The content of the report file
        """
        report = self.get_report(report_id)

        url = "{}/api/2.0/fo/report/".format(self.server_address)
        params = {
            'action': 'fetch',
            'id': report_id,
        }
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to fetch report {}".format(report_id))

        return {
            "name": "{}.{}".format(report["TITLE"], report["OUTPUT_FORMAT"]),
            "content": response.content
        }

    def launch_vm_scan(self, scan_title, priority=0, option_id=None,
                       option_title=None, ip=None,
                       asset_group_ids=None, asset_groups=None,
                       exclude_ip_per_scan=None,
                       iscanner_name="External", scanners_in_ag=None,
                       target_from="assets",
                       tag_include_selector="any", tag_exclude_selector="any",
                       tag_set_by="id", tag_set_include=None,
                       tag_set_exclude=None,
                       use_ip_nt_range_tags=0, ip_network_id=0,
                       runtime_http_header=None
                       ):

        url = "{}/api/2.0/fo/scan/".format(self.server_address)
        data = {
            'scan_title': scan_title,
            'priority': priority,
            'option_id': option_id,
            'option_title': option_title,
            'iscanner_name': iscanner_name,
            'scanners_in_ag': scanners_in_ag,
            'target_from': target_from,
            'runtime_http_header': runtime_http_header,
        }

        if target_from == "tags":
            data.update({
                'tag_include_selector': tag_include_selector,
                'tag_exclude_selector': tag_exclude_selector,
                'tag_set_by': tag_set_by,
                'tag_set_include': tag_set_include,
                'tag_set_exclude': tag_set_exclude,
                'use_ip_nt_range_tags': use_ip_nt_range_tags,
            })

        elif target_from == 'assets':
            data.update({
                'ip': ip,
                'asset_group_ids': asset_group_ids,
                'asset_groups': asset_groups,
                'exclude_ip_per_scan': exclude_ip_per_scan,
                'ip_network_id': ip_network_id,
            })

            data = {k: v for k, v in data.items() if v}
        response = self.session.post(url, params={'action': 'launch'}, data=data)
        self.validate_response(response, "Unable to launch vm scan")

        try:
            items = xmltodict.parse(
                response.content,
                dict_constructor=dict
            ).get('SIMPLE_RETURN', {}).get('RESPONSE', {}).get('ITEM_LIST', {}).get('ITEM', [])

            if items:
                return items[1].get('VALUE')
        except Exception:
            if xmltodict.parse(
                    response.content,
                    dict_constructor=dict
            ).get('SIMPLE_RETURN', {}).get('RESPONSE', {}).get('TEXT'):

                raise QualysVMManagerError(
                    "Unable to perform scan: {}".format(
                        xmltodict.parse(
                            response.content,
                            dict_constructor=dict
                        ).get('SIMPLE_RETURN', {}).get('RESPONSE', {}).get('TEXT')))

        raise QualysVMManagerError("Unable to perform scan: {}".format(response.content))
