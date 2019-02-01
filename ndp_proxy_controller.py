import json

from ryu.app.wsgi import ControllerBase, route
from webob import Response

from config import rest_base_url, ndp_proxy_instance_name


class NdpProxyController(ControllerBase):
    """
    Rest controller class for the NDP proxy. Exposes some URLs providing information
    and allowing to toggle PCAP writing. URLs are specified in the @route decorator.
    """

    def __init__(self, req, link, data, **config):
        super(NdpProxyController, self).__init__(req, link, data, **config)
        self.ndp_proxy_app = data[ndp_proxy_instance_name]

    @route('ndp_proxy', rest_base_url + '/all-hosts', methods=['GET'])
    def list_all_hosts(self, req, **kwargs):
        ndp_proxy = self.ndp_proxy_app
        table = json.dumps(ndp_proxy.neighbor_cache.get_all_dict())
        return Response(content_type='application/json', text=table)

    @route('ndp_proxy', rest_base_url + '/active-hosts', methods=['GET'])
    def list_active_hosts(self, req, **kwargs):
        ndp_proxy = self.ndp_proxy_app
        table = json.dumps(ndp_proxy.neighbor_cache.get_active_dict())
        return Response(content_type='application/json', text=table)

    @route('ndp_proxy', rest_base_url + '/flood-info', methods=['GET'])
    def list_flood_info(self, req, **kwargs):
        ndp_proxy = self.ndp_proxy_app
        d = ndp_proxy.get_port_requests_dict()
        table = json.dumps(d)
        return Response(content_type='application/json', text=table)

    @route('ndp_proxy', rest_base_url + '/write-pcap', methods=['PUT'])
    def set_write_pcap(self, req, **kwargs):
        ndp_proxy = self.ndp_proxy_app
        try:
            req_dict = dict(req.json) if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            ndp_proxy.pcap_writer.toggle_write_pcap(req_dict)
        except KeyError:
            raise Response(status=400)

        return Response(content_type='application/json', text=json.dumps(req.json))

    @route('ndp_proxy', rest_base_url + '/statistics', methods=['GET'])
    def list_stats(self, req, **kwargs):
        ndp_proxy = self.ndp_proxy_app
        d = ndp_proxy.get_stats_dict()
        table = json.dumps(d)
        return Response(content_type='application/json', text=table)