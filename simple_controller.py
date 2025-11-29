# simple_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp
from ryu.lib.packet import ether_types

from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
import json

REST_INSTANCE = "simple_switch_rest"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

        # Learned MAC -> port per dpid
        self.mac_to_port = {}     # { dpid: { mac: port, ... }, ... }

        # Installed flows recorded for dashboard: list of dicts
        self.installed_flows = []

        # register REST app
        wsgi = kwargs["wsgi"]
        wsgi.register(SimpleSwitchREST, {REST_INSTANCE: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        self.logger.info("Switch %s connected (table-miss installed)", dp.id)

    def add_flow(self, dp, priority, match, actions, buffer_id=None):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=dp,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=dp,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst
        in_port = msg.match.get("in_port", None)
        if in_port is None:
            try:
                in_port = msg.match["in_port"]
            except Exception:
                in_port = 0

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            self.installed_flows.append({
                "switch": dpid,
                "eth_src": src,
                "eth_dst": dst
            })
            self.add_flow(dp, 1, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(dp, msg.buffer_id, in_port, actions, data)
        dp.send_msg(out)

##############################################################################
# REST API
##############################################################################
class SimpleSwitchREST(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SimpleSwitchREST, self).__init__(req, link, data, **config)
        self.switch_app = data[REST_INSTANCE]

    @route("flows", "/flows", methods=["GET"])
    def list_flows(self, req, **kwargs):
        payload = {
            "switches": [],
            "installed_flows": self.switch_app.installed_flows
        }
        for dpid, mac_table in self.switch_app.mac_to_port.items():
            payload["switches"].append({
                "switch": dpid,
                "learned_table": mac_table
            })

        body = json.dumps(payload)
        return Response(
            body,
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    @route("topo", "/topology", methods=["GET"])
    def topology(self, req, **kwargs):
        topo = {"switches": []}
        for dpid, mac_table in self.switch_app.mac_to_port.items():
            topo["switches"].append({
                "switch": dpid,
                "hosts": [{"mac": m, "port": p} for m, p in mac_table.items()]
            })

        body = json.dumps(topo)
        return Response(
            body,
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    # New endpoint: /pingall
    @route("pingall", "/pingall", methods=["POST"])
    def ping_all(self, req, **kwargs):
        # For each switch, send a packet-out to "ping" every host pair
        app = self.switch_app
        for dpid, mac_table in app.mac_to_port.items():
            dp = None
            # find datapath object
            for dpobj in app.mac_to_port.keys():
                if dpobj == dpid:
                    # Ryu does not store datapath in mac_to_port; in real apps you'd store it on connect
                    # For demo purposes we just log
                    app.logger.info("Would ping hosts on switch %s: %s", dpid, list(mac_table.keys()))
        # After "pinging", you can refresh the dashboard
        return Response(
            json.dumps({"status": "pingall triggered"}),
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )
