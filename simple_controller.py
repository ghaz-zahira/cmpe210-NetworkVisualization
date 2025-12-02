# simple_controller.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp
from ryu.lib.packet import ether_types
import time

from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
import json
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link

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
        # internal set for quick duplicate checks (keys: "dpid|src|dst")
        self._installed_flow_keys = set()
 
        # Track datapaths and discovered links for topology
        self.datapaths = {}   # { dpid: datapath, ... }
        self.links = []       # list of {src_dpid, src_port, dst_dpid, dst_port}
 
        # latest flow stats collected from switches (populated by EventOFPFlowStatsReply)
        # structure: { dpid: [ { switch, eth_src, eth_dst, packets, bytes, ... }, ... ], ... }
        self._flow_stats = {}
 
         # simple IP -> MAC mapping learned from ARP/IPv4 packets
        self.ip_to_mac = {}   # { "10.0.0.1": "00:00:00:00:00:01", ... }
 
        # probe identity used by /pingall (controller-generated ARP)
        self.probe_mac = "02:00:00:00:00:fe"
        self.probe_ip = "10.0.0.254"
 
        # register REST app
        wsgi = kwargs["wsgi"]
        wsgi.register(SimpleSwitchREST, {REST_INSTANCE: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # store datapath for later use / topology mapping
        self.datapaths[dp.id] = dp

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

    # request flow stats from all connected datapaths
    def request_flow_stats(self):
        for dp in list(self.datapaths.values()):
            try:
                parser = dp.ofproto_parser
                ofp = dp.ofproto
                match = parser.OFPMatch()  # request all flows
                req = parser.OFPFlowStatsRequest(dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY,
                                                 ofp.OFPG_ANY, 0, 0, match)
                dp.send_msg(req)
            except Exception:
                self.logger.exception("failed to send flow stats request to %s", getattr(dp, "id", None))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        msg = ev.msg
        dp = msg.datapath
        # dp.id is used elsewhere in this app; fall back to datapath_id if needed
        dpid = getattr(dp, "id", None) or getattr(dp, "datapath_id", None) or getattr(dp, "dpid", None)
        stats = []
        for stat in msg.body:
            eth_src = None
            eth_dst = None
            try:
                # stat.match behaves like a dict in typical ryu versions
                eth_src = stat.match.get('eth_src')
                eth_dst = stat.match.get('eth_dst')
            except Exception:
                # fallback: iterate items if match is different type
                try:
                    for k, v in getattr(stat.match, 'items', lambda: [])():
                        if k in ('eth_src', 'dl_src'):
                            eth_src = v
                        if k in ('eth_dst', 'dl_dst'):
                            eth_dst = v
                except Exception:
                    pass

            stats.append({
                "switch": dpid,
                "eth_src": eth_src,
                "eth_dst": eth_dst,
                "packets": getattr(stat, "packet_count", 0),
                "bytes": getattr(stat, "byte_count", 0),
                "duration_sec": getattr(stat, "duration_sec", 0),
                "duration_nsec": getattr(stat, "duration_nsec", 0)
            })
        # store latest stats for this datapath
        try:
            self._flow_stats[dpid] = stats
        except Exception:
            # ensure dict exists
            self._flow_stats = {dpid: stats}

    # record an installed flow only once to avoid duplicates shown by the dashboard
    def add_installed_flow(self, dpid, eth_src, eth_dst):
        # dedupe per-switch, but still treat src/dst as an unordered pair
        # so a flow src<->dst installed multiple times on the same switch
        # won't be appended repeatedly, while the same pair on different
        # switches will be shown separately.
        host_pair = "|".join(sorted([eth_src, eth_dst]))
        key = f"{dpid}|{host_pair}"
        if key in self._installed_flow_keys:
            return
        self._installed_flow_keys.add(key)
        self.installed_flows.append({
            "switch": dpid,
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "first_seen": time.time()
        })

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

        # only treat ARP or IPv4 frames as host-originated for learning
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        is_host_frame = (arp_pkt is not None) or (ip_pkt is not None)

        src = eth.src
        dst = eth.dst
        in_port = msg.match.get("in_port", None)
        if in_port is None:
            try:
                in_port = msg.match["in_port"]
            except Exception:
                in_port = 0

        # ignore controller's own probe MAC so it doesn't appear as a host
        if src == self.probe_mac:
            self.logger.debug("Ignoring controller probe MAC seen on sw%s port %s", dpid, in_port)
            # still forward as usual (don't learn), but we can skip learning-only behavior
            # fall through to forwarding logic without registering src in mac_to_port
        else:
            # learn MAC -> port only for host frames (ARP/IPv4)
            if is_host_frame:
                self.mac_to_port[dpid][src] = in_port

                # also learn IP->MAC mapping when available
                if arp_pkt is not None:
                    try:
                        self.ip_to_mac[arp_pkt.src_ip] = src
                    except Exception:
                        pass
                if ip_pkt is not None:
                    try:
                        self.ip_to_mac[ip_pkt.src] = src
                    except Exception:
                        pass
            else:
                self.logger.debug("Ignoring non-host frame for learning: ethertype=%s src=%s on sw%s",
                                  hex(eth.ethertype), src, dpid)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(eth_src=src, eth_dst=dst)
            # only add flow if it's not a duplicate (based on key)
            # use helper to avoid duplicate entries
            self.add_installed_flow(dpid, src, dst)
            self.add_flow(dp, 1, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(dp, msg.buffer_id, in_port, actions, data)
        dp.send_msg(out)

    # topology discovery handlers
    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter(self, ev):
        # register datapath when switch enters
        try:
            dp = ev.switch.dp
            self.datapaths[dp.id] = dp
            self.logger.info("SwitchEnter: %s", dp.id)
        except Exception:
            pass

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add(self, ev):
        l = ev.link
        src = l.src
        dst = l.dst
        link_info = {
            "src_dpid": src.dpid,
            "src_port": src.port_no,
            "dst_dpid": dst.dpid,
            "dst_port": dst.port_no
        }
        # avoid duplicates
        if link_info not in self.links:
            self.links.append(link_info)
            self.logger.info("Link added: %s:%s -> %s:%s",
                             src.dpid, src.port_no, dst.dpid, dst.port_no)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_del(self, ev):
        l = ev.link
        src = l.src
        dst = l.dst
        self.links = [lk for lk in self.links
                      if not (lk["src_dpid"] == src.dpid and lk["dst_dpid"] == dst.dpid
                              and lk["src_port"] == src.port_no and lk["dst_port"] == dst.port_no)]

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
        topo = {"switches": [], "links": []}
        for dpid, mac_table in self.switch_app.mac_to_port.items():
            topo["switches"].append({
                "switch": dpid,
                "hosts": [{"mac": m, "port": p} for m, p in mac_table.items()]
            })

        # include discovered links between switches (if any)
        topo["links"] = list(self.switch_app.links)

        body = json.dumps(topo)
        return Response(
            body,
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    # New endpoint: /pingall
    @route("pingall", "/pingall", methods=["POST", "OPTIONS"])
    def ping_all(self, req, **kwargs):
        # respond to CORS preflight
        if req.method == 'OPTIONS':
            return Response(status=200,
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Methods": "POST, OPTIONS",
                                "Access-Control-Allow-Headers": "Content-Type"
                            })
        app = self.switch_app

        # --- ARP probe phase: try to make hosts reply so controller learns MAC->port ---
        probe_mac = app.probe_mac
        probe_ip = app.probe_ip
        # probe the usual Mininet range (adjust upper bound if you have more hosts)
        target_ips = ["10.0.0.%d" % i for i in range(1, 5)]

        for dp in list(app.datapaths.values()):
            try:
                parser = dp.ofproto_parser
                ofp = dp.ofproto
                # gather all ports known on this datapath
                try:
                    all_ports = set(dp.ports.keys())
                except Exception:
                    # fallback: if dp.ports not available, skip this dp
                    continue

                # gather ports that are used for switch-to-switch links
                link_ports = set()
                for l in app.links:
                    if l.get("src_dpid") == dp.id:
                        link_ports.add(l.get("src_port"))
                    if l.get("dst_dpid") == dp.id:
                        link_ports.add(l.get("dst_port"))

                # candidate host-facing ports = all_ports - link_ports
                host_ports = [p for p in all_ports if p not in link_ports and p > 0]

                for port in host_ports:
                    for tip in target_ips:
                        eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff",
                                                src=probe_mac,
                                                ethertype=ether_types.ETH_TYPE_ARP)
                        arp_req = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4,
                                          opcode=1,
                                          src_mac=probe_mac, src_ip=probe_ip,
                                          dst_mac="00:00:00:00:00:00", dst_ip=tip)
                        pkt = packet.Packet()
                        pkt.add_protocol(eth)
                        pkt.add_protocol(arp_req)
                        pkt.serialize()

                        actions = [parser.OFPActionOutput(port)]
                        out = parser.OFPPacketOut(dp, ofp.OFP_NO_BUFFER,
                                                  ofp.OFPP_CONTROLLER,
                                                  actions, pkt.data)
                        try:
                            dp.send_msg(out)
                        except Exception:
                            pass
            except Exception:
                continue

        # give hosts a short time to reply and controller to learn
        time.sleep(1.0)

        # --- build reverse lookup from learned mac_to_port (after ARP replies) ---
        sent = 0
        mac_loc = {}
        # remove any leftover probe_mac entries first
        for dpid, table in app.mac_to_port.items():
            if probe_mac in table:
                try:
                    del table[probe_mac]
                except Exception:
                    pass

        for dpid, table in app.mac_to_port.items():
            for mac, port in table.items():
                mac_loc[mac] = (dpid, port)

        # helper: try to get IP for MAC (learned) or infer from MAC low byte
        def ip_for_mac(mac):
            for ip, m in app.ip_to_mac.items():
                if m == mac:
                    return ip
            try:
                last = int(mac.split(":")[-1], 16)
                return "10.0.0.%d" % last
            except Exception:
                return "10.0.0.1"

        macs = list(mac_loc.keys())
        if not macs:
            return Response(
                json.dumps({"status": "no hosts learned; ARP probe sent"}),
                content_type="application/json",
                charset="utf-8",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # send an ICMP echo (controller-injected) from each src->dst pair (src!=dst)
        for i in range(len(macs)):
            for j in range(len(macs)):
                if i == j:
                    continue
                src_mac = macs[i]
                dst_mac = macs[j]
                dpid_src, port_src = mac_loc[src_mac]
                dp = app.datapaths.get(dpid_src)
                if dp is None:
                    continue
                parser = dp.ofproto_parser
                ofp = dp.ofproto

                src_ip = ip_for_mac(src_mac)
                dst_ip = ip_for_mac(dst_mac)

                echo_payload = b'ping'
                icmp_obj = icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, code=0,
                                     csum=0,
                                     data=icmp.echo(0, sent, echo_payload))
                ip_obj = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=ipv4.inet.IPPROTO_ICMP)
                eth = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IP)

                pkt = packet.Packet()
                pkt.add_protocol(eth)
                pkt.add_protocol(ip_obj)
                pkt.add_protocol(icmp_obj)
                pkt.serialize()

                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = parser.OFPPacketOut(dp, ofp.OFP_NO_BUFFER, port_src, actions, pkt.data)
                try:
                    dp.send_msg(out)
                    sent += 1
                except Exception:
                    pass

        return Response(
            json.dumps({"status": "pingall injected", "packets_sent": sent}),
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    @route("flow_stats", "/flow_stats", methods=["GET"])
    def flow_stats(self, req, **kwargs):
        """
        Request flow stats from datapaths, wait briefly for replies,
        then return a normalized JSON array where eth_src/eth_dst are
        always strings ('' when unknown) and packets/bytes are integers.
        """
        app = self.switch_app
        try:
            # trigger requests to datapaths (handler populates app._flow_stats)
            app.request_flow_stats()
        except Exception:
            self.logger.exception("request_flow_stats failed")

        # allow a short time for switches to reply; increase if your topology is slow
        time.sleep(0.25)

        stats = []
        for dpid, s_list in getattr(app, "_flow_stats", {}).items():
            for s in (s_list or []):
                # s may be a dict (from _flow_stats reply code) — be defensive
                if isinstance(s, dict):
                    eth_src = s.get("eth_src") or ""
                    eth_dst = s.get("eth_dst") or ""
                    packets = s.get("packets", s.get("packet_count", 0)) or 0
                    bytes_ = s.get("bytes", s.get("byte_count", 0)) or 0
                    dur_s = s.get("duration_sec", 0) or 0
                    dur_ns = s.get("duration_nsec", 0) or 0
                else:
                    # fallback for object-like entries
                    eth_src = getattr(s, "eth_src", "") or ""
                    eth_dst = getattr(s, "eth_dst", "") or ""
                    packets = getattr(s, "packets", getattr(s, "packet_count", 0)) or 0
                    bytes_ = getattr(s, "bytes", getattr(s, "byte_count", 0)) or 0
                    dur_s = getattr(s, "duration_sec", 0) or 0
                    dur_ns = getattr(s, "duration_nsec", 0) or 0

                stats.append({
                    "switch": str(dpid),
                    "eth_src": str(eth_src),
                    "eth_dst": str(eth_dst),
                    "packets": int(packets),
                    "bytes": int(bytes_),
                    "duration_sec": int(dur_s),
                    "duration_nsec": int(dur_ns)
                })

        body = json.dumps(stats)
        return Response(
            body,
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    # POST /generate_traffic { "count": 200, "size": 120 } -> injects controller-generated ICMP packets
    @route("gen_traffic", "/generate_traffic", methods=["POST", "OPTIONS"])
    def generate_traffic(self, req, **kwargs):
        # handle CORS preflight
        if req.method == 'OPTIONS':
            return Response(status=200,
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Methods": "POST, OPTIONS",
                                "Access-Control-Allow-Headers": "Content-Type"
                            })
        app = self.switch_app
        params = {}
        try:
            params = req.json_body or {}
        except Exception:
            pass
        count = int(params.get("count", 100))
        size = int(params.get("size", 64))

        # build reverse lookup of mac -> (dpid, port)
        mac_loc = {}
        for dpid, table in app.mac_to_port.items():
            for mac, port in table.items():
                if mac == app.probe_mac:
                    continue
                mac_loc[mac] = (dpid, port)

        macs = list(mac_loc.keys())
        if not macs:
            return Response(json.dumps({"status": "no hosts learned"}), content_type="application/json",
                            charset="utf-8", headers={"Access-Control-Allow-Origin": "*"})

        import random
        sent = 0

        # helper: try to get IP for MAC (learned) or infer from MAC low byte
        def ip_for_mac(mac):
            for ip, m in app.ip_to_mac.items():
                if m == mac:
                    return ip
            try:
                last = int(mac.split(":")[-1], 16)
                return "10.0.0.%d" % last
            except Exception:
                return "10.0.0.1"

        # prepare all ordered src->dst pairs (src != dst)
        pairs = [(a, b) for a in macs for b in macs if a != b]
        if not pairs:
            return Response(json.dumps({"status": "no pairs"}),
                            content_type="application/json",
                            charset="utf-8",
                            headers={"Access-Control-Allow-Origin": "*"})

        for n in range(count):
            src_mac, dst_mac = random.choice(pairs)
            dpid_src, port_src = mac_loc[src_mac]
            dp = app.datapaths.get(dpid_src)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            ofp = dp.ofproto

            src_ip = ip_for_mac(src_mac)
            dst_ip = ip_for_mac(dst_mac)

            # build a small ICMP echo payload sized roughly to `size` bytes (subtract headers)
            payload_len = max(0, size - 28)
            echo_payload = b'X' * payload_len
            try:
                icmp_obj = icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, code=0,
                                     csum=0,
                                     data=icmp.echo(0, n, echo_payload))
                ip_obj = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=ipv4.inet.IPPROTO_ICMP)
                eth = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_IP)

                pkt = packet.Packet()
                pkt.add_protocol(eth)
                pkt.add_protocol(ip_obj)
                pkt.add_protocol(icmp_obj)
                pkt.serialize()

                actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                out = parser.OFPPacketOut(dp, ofp.OFP_NO_BUFFER, port_src, actions, pkt.data)
                try:
                    dp.send_msg(out)
                    sent += 1
                except Exception:
                    pass
            except Exception:
                # skip malformed packet construction
                pass

            # small throttle so controller doesn't get overloaded
            time.sleep(0.005)

        return Response(
            json.dumps({"status": "generated", "packets_sent": sent}),
            content_type="application/json",
            charset="utf-8",
            headers={"Access-Control-Allow-Origin": "*"}
        )
