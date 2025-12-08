<?php
// Minimal OpenFlow 1.3 LLDP controller in plain PHP (echo for logs)
// Run: php controller_of13.php

// ---- CONFIG: where to write the topology JSON for your web UI ----
// Prefer web root; fallback to current dir if web path is not writable.
$preferred = '/var/www/html/topology.json';
if (is_writable(dirname($preferred))) {
    $TOPO_JSON = $preferred;
} else {
    $TOPO_JSON = __DIR__ . '/topology.json';
}
echo "Topology JSON path: $TOPO_JSON\n";

// call this whenever topology changes
function save_topology_json($topology, $file) {
    // Collect unique switch IDs from link keys like "a:port->b"
    $nodesSet = [];
    $edges = [];

    foreach ($topology as $key => $ts) {
        // key format: "<src_dpid_hex>:<src_port>-><dst_dpid_hex>"
        $parts = explode('->', $key);
        if (count($parts) != 2) continue;
        $left = $parts[0];               // "srcHex:srcPort"
        $dstHex = $parts[1];             // "dstHex"

        $leftParts = explode(':', $left);
        if (count($leftParts) != 2) continue;
        $srcHex = $leftParts[0];
        $srcPort = $leftParts[1];

        $nodesSet[$srcHex] = true;
        $nodesSet[$dstHex] = true;

        // Edge ID stable across refreshes
        $eid = $srcHex . '-' . $srcPort . '-' . $dstHex;

        $edges[] = [
            'id'     => $eid,
            'from'   => $srcHex,
            'to'     => $dstHex,
            'label'  => "p$srcPort",   // show source port on the edge
            'arrows' => 'to'
        ];
    }

    $nodes = [];
    foreach (array_keys($nodesSet) as $hex) {
        $nodes[] = [
            'id'    => $hex,
            'label' => "DPID $hex",
            'shape' => 'box'
        ];
    }

    $payload = [
        'generated_at' => date('c'),
        'nodes' => $nodes,
        'edges' => $edges
    ];

    $json = json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    $result = @file_put_contents($file, $json, LOCK_EX);

    if ($result === false) {
        echo "ERROR: Failed to write topology JSON to $file\n";
    } else {
        echo "Saved topology: nodes=" . count($nodes) . " edges=" . count($edges) . " -> $file\n";
    }
}

/*

// call this whenever topology changes
function save_topology_json($topology, $file) {
    $nodesSet = [];
    $edges = [];

    foreach ($topology as $key => $ts) {
        // key format assumed: "<src>:<port>-><dst>"
        $parts = explode('->', $key);
        if (count($parts) != 2) continue;
        $left = $parts[0];    // "src:port"
        $dst = $parts[1];     // "dst"

        $leftParts = explode(':', $left);
        if (count($leftParts) != 2) continue;
        $src = $leftParts[0];
        $srcPort = $leftParts[1];

        // track nodes
        $nodesSet[$src] = true;
        $nodesSet[$dst] = true;

        // edge
        $eid = $src . '-' . $srcPort . '-' . $dst;
        $edges[] = [
            'id'    => $eid,
            'from'  => $src,
            'to'    => $dst,
            'label' => "p$srcPort",
            'arrows'=> 'to'
        ];
    }

    $nodes = [];
    foreach (array_keys($nodesSet) as $nodeId) {
        // Instead of DPID/shape, include MAC, serial number, IP
        $mac = isset($GLOBALS['switches'][$nodeId]['mac']) ? $GLOBALS['switches'][$nodeId]['mac'] : 'unknown';
        $serial = isset($GLOBALS['switches'][$nodeId]['serial']) ? $GLOBALS['switches'][$nodeId]['serial'] : 'unknown';
        $ip = isset($GLOBALS['switches'][$nodeId]['ip']) ? $GLOBALS['switches'][$nodeId]['ip'] : 'unknown';

        $nodes[] = [
            'id'     => $nodeId,
            'label'  => "MAC: $mac\nSN: $serial\nIP: $ip",
        ];
    }

    $payload = [
        'generated_at' => date('c'),
        'nodes' => $nodes,
        'edges' => $edges
    ];

    $json = json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    $result = @file_put_contents($file, $json, LOCK_EX);

    if ($result === false) {
        echo "ERROR: Failed to write topology JSON to $file\n";
    } else {
        echo "Saved topology: nodes=" . count($nodes) . " edges=" . count($edges) . " -> $file\n";
    }
}

*/

// optional: prune stale LLDP links (e.g., older than 20s) before saving
function prune_topology(&$topology, $ttlSeconds = 20) {
    $now = time();
    foreach ($topology as $k => $t) {
        if ($now - $t > $ttlSeconds) unset($topology[$k]);
    }
}

function build_set_config($miss_len = 0xffff, $xid = 20) {
    $OFP_VERSION = 0x04; $OFPT_SET_CONFIG = 9;
    $body = pack("nn", 0, $miss_len); // flags=0, miss_send_len
    return pack("CCnN", $OFP_VERSION, $OFPT_SET_CONFIG, 8 + strlen($body), $xid) . $body;
}

function build_flow_mod_table_miss_to_controller($priority = 0, $xid = 21) {
    $OFP_VERSION=0x04; $OFPT_FLOW_MOD=14; $OFP_NO_BUFFER=0xffffffff; $OFPP_CONTROLLER=0xfffffffd;

    // cookie(8) cookie_mask(8)
    $fm  = pack("NN", 0, 0) . pack("NN", 0, 0);
    // (pad + table + command + idle_timeout/hard_timeout + priority)
    $fm .= pack("C",0) . pack("C",0) . pack("n",0) . pack("n",0) . pack("n",$priority);
    // buffer_id, out_port, out_group, flags(2)
    $fm .= pack("N",$OFP_NO_BUFFER) . pack("N",0) . pack("N",0) . pack("n",0) . "\x00\x00";

    // Build ofp_match: header(2+2) + fields + padding to 8 bytes
    $match_body = ""; // empty match (table-miss)
    $match_len_without_pad = 0; // no OXM TLVs
    // ofp_match length field counts the match fields + padding (but NOT the 4-byte header)
    // here we'll use length = 0 (no fields), but we must still pad to a multiple of 8 (0 -> 0)
    $match_len = $match_len_without_pad;
    $pad = (8 - ($match_len % 8)) % 8;
    $match = pack("nn", 1, $match_len + $pad) . $match_body . str_repeat("\x00", $pad);

    // Action: output to controller (ofp_action_output len=16). Put it into an instruction.
    $action = pack("nnNn", 0, 16, $OFPP_CONTROLLER, 0xffff) . str_repeat("\x00", 6);
    $inst   = pack("nn", 4, 8 + strlen($action)) . $action;

    $payload = $fm . $match . $inst;
    return pack("CCnN", $OFP_VERSION, $OFPT_FLOW_MOD, 8 + strlen($payload), $xid) . $payload;
}

function build_flow_mod_eth_type_to_controller($eth_type = 0x88cc, $priority = 1000, $xid = 22) {
    $OFP_VERSION=0x04; $OFPT_FLOW_MOD=14; $OFP_NO_BUFFER=0xffffffff; $OFPP_CONTROLLER=0xfffffffd;

    // cookie / mask etc.
    $fm  = pack("NN", 0, 0) . pack("NN", 0, 0);
    $fm .= pack("C",0) . pack("C",0) . pack("n",0) . pack("n",0) . pack("n",$priority);
    $fm .= pack("N",$OFP_NO_BUFFER) . pack("N",0) . pack("N",0) . pack("n",0) . "\x00\x00";

    // Build proper OXM for eth_type:
    // OXM header: oxm_class(2) | field/hasmask (1) | length (1), then value (length bytes).
    // header (4 bytes) + value (2 bytes) => total 6
    $oxm_header = pack("nC C", 0x8000, (5<<1)|0, 2); // class, field<<1|hasmask, length
    $oxm_value  = pack("n", $eth_type);
    $oxm = $oxm_header . $oxm_value;

    // Now build ofp_match: type(2) + length(2) + OXM TLVs + padding to 8 bytes.
    $match_len_without_pad = strlen($oxm);         // OXM TLVs length
    $pad = (8 - (($match_len_without_pad + 0) % 8)) % 8;
    $match = pack("nn", 1, $match_len_without_pad + $pad) . $oxm . str_repeat("\x00", $pad);

    // action: output to controller
    $action = pack("nnNn", 0, 16, $OFPP_CONTROLLER, 0xffff) . str_repeat("\x00",6);
    $inst   = pack("nn", 4, 8+strlen($action)) . $action;

    $payload = $fm . $match . $inst;
    return pack("CCnN", $OFP_VERSION, $OFPT_FLOW_MOD, 8+strlen($payload), $xid) . $payload;
}



// ---- OpenFlow 1.3 constants ----
$OFP_VERSION              = 0x04;
$OFPT_HELLO               = 0;
$OFPT_ERROR               = 1;
$OFPT_ECHO_REQUEST        = 2;
$OFPT_ECHO_REPLY          = 3;
$OFPT_FEATURES_REQUEST    = 5;
$OFPT_FEATURES_REPLY      = 6;
$OFPT_PACKET_IN           = 10;
$OFPT_FLOW_MOD            = 14;
$OFPT_PACKET_OUT          = 13;
$OFPT_MULTIPART_REQUEST   = 18;
$OFPT_MULTIPART_REPLY     = 19;

$OFPMP_PORT_DESC          = 13;   // multipart type for port descriptions

$OFPP_MAX                 = 0xffffff00;
$OFPP_CONTROLLER          = 0xfffffffd;
$OFP_NO_BUFFER            = 0xffffffff;

// Ethernet/LLDP
$lldp_multicast           = "\x01\x80\xc2\x00\x00\x0e";
$ethertype_lldp           = "\x88\xcc";

// ---- State ----
$switches = []; // dpid => ['sock'=>resource, 'ports'=>[], 'last_lldp'=>0]
$clients  = []; // id => ['sock'=>resource, 'phase'=>'hello|wait_features|ready', 'dpid'=>null]
$topology = []; // "srcdpid:port->dstdpid" => ts

// ---- Helpers ----
function be64_to_str($x) {
    $hi = ($x >> 32) & 0xffffffff;
    $lo = $x & 0xffffffff;
    return pack("NN", $hi, $lo);
}
function str_to_be64($s8) {
    $a = unpack("Nhi/Nlo", $s8);
    return ($a['hi'] << 32) | $a['lo'];
}
function build_of_header($msg_type, $length, $xid = 1) {
    global $OFP_VERSION;
    return pack("CCnN", $OFP_VERSION, $msg_type, $length, $xid);
}
function build_hello($xid = 1) {
    return build_of_header(0, 8, $xid); // OFPT_HELLO
}
function build_features_request($xid = 1) {
    global $OFPT_FEATURES_REQUEST;
    return build_of_header($OFPT_FEATURES_REQUEST, 8, $xid);
}
function build_multipart_port_desc_request($xid = 2) {
    global $OFPT_MULTIPART_REQUEST, $OFPMP_PORT_DESC;
    // ofp_multipart_request: header(8) + type(2) + flags(2) + pad(4) + body(0)
    $len = 8 + 8;
    $msg  = build_of_header($OFPT_MULTIPART_REQUEST, $len, $xid);
    $msg .= pack("nnN", $OFPMP_PORT_DESC, 0, 0); // flags=0, pad=0
    return $msg;
}
function build_lldp_packet($dpid, $port_no) {
    global $lldp_multicast, $ethertype_lldp;
    $dpid8 = be64_to_str($dpid);
    $chassis_mac = substr($dpid8, 2, 6); // lower 6 bytes (6 bytes MAC)

    // Build TLVs using proper 2-byte TLV header (type << 9 | length)
    // Chassis ID TLV: type=1, length=1+6 (subtype + MAC)
    $chassis_subtype = chr(4); // 4 = MAC subtype
    $chassis_val = $chassis_subtype . $chassis_mac;
    $chassis_hdr = pack("n", (1 << 9) | strlen($chassis_val));
    $chassis_tlv = $chassis_hdr . $chassis_val;

    // Port ID TLV: type=2, length=1+2 (subtype + port (2 bytes))
    $port_subtype = chr(3); // 3 = local network port (numeric)
    $port_val = $port_subtype . pack("n", $port_no);
    $port_hdr = pack("n", (2 << 9) | strlen($port_val));
    $port_tlv = $port_hdr . $port_val;

    // TTL TLV: type=3, length=2
    $ttl_val = pack("n", 120); // 120 seconds
    $ttl_hdr = pack("n", (3 << 9) | 2);
    $ttl_tlv = $ttl_hdr . $ttl_val;

    // End TLV: type=0, length=0 -> two zero bytes
    $end_tlv = pack("n", 0);

    $lldp_payload = $chassis_tlv . $port_tlv . $ttl_tlv . $end_tlv;

    // Ethernet frame: dst mac (LLDP multicast) | src mac (chassis_mac) | ethertype + payload
    $eth = $lldp_multicast . $chassis_mac . $ethertype_lldp . $lldp_payload;
    return $eth;
}
function build_packet_out_of13($port_no, $data, $xid = 3) {
    // ofp_packet_out (1.3):
    // buffer_id(4) + in_port(4) + actions_len(2) + pad[6] + actions + data
    // Single OUTPUT action (ofp_action_output, len=16)
    global $OFPT_PACKET_OUT, $OFP_NO_BUFFER, $OFPP_CONTROLLER;

    $action = pack("nnNn", 0, 16, $port_no, 0) . str_repeat("\x00", 6); // type=0,len=16,port,max_len,pad[6]
    $actions_len = strlen($action);

    $header_and_po = build_of_header($OFPT_PACKET_OUT, 0, $xid);
    $body  = pack("NNn", $OFP_NO_BUFFER, $OFPP_CONTROLLER, $actions_len) . str_repeat("\x00", 6);
    $msg   = $header_and_po . $body . $action . $data;

    // fix total length in header
    $len = strlen($msg);
    $msg = substr($msg, 0, 2) . pack("n", $len) . substr($msg, 4);
    return $msg;
}
function parse_features_reply_of13($payload) {
    // ofp_switch_features (1.3) is 24 bytes; does NOT include port list.
    if (strlen($payload) < 24) return [null];
    $dpid = str_to_be64(substr($payload, 0, 8));
    return [$dpid];
}
function parse_multipart_port_desc_reply($payload) {
    // ofp_multipart_reply: type(2) flags(2) pad(4) + body...
    if (strlen($payload) < 8) return [];
    $ports = [];
    $off = 8;
    // Each ofp_port (1.3) = 64 bytes. First 4 bytes are port_no.
    while ($off + 64 <= strlen($payload)) {
        $port_raw = substr($payload, $off, 4);
        $u = unpack("Nport", $port_raw);
        $port_no = $u['port'];
        // IGNORE reserved ports (OFPP_MAX/OFPP_LOCAL/CONTROLLER/etc) >= 0xffffff00
        if ($port_no < 0xffffff00) {
            $ports[] = $port_no;
        }
        $off += 64;
    }
    return $ports;
}
function parse_lldp_tlvs($lldp_payload)
{
    $src_dpid = null;
    $src_port = null;
    $offset = 0;
    $len = strlen($lldp_payload);

    while ($offset + 2 <= $len) {
        $tlv_header = unpack("n", substr($lldp_payload, $offset, 2))[1];
        $type = ($tlv_header >> 9) & 0x7F;
        $tlv_len = $tlv_header & 0x1FF;
        $offset += 2;

        if ($offset + $tlv_len > $len) break;
        $value = substr($lldp_payload, $offset, $tlv_len);
        $offset += $tlv_len;

        // --- Debug print ---
        printf("TLV type=%d len=%d hex=%s\n", $type, $tlv_len, bin2hex($value));

        if ($type == 1 && $tlv_len >= 7) { // Chassis ID
            $subtype = ord($value[0]);
            if ($subtype == 4) {
                $mac_bytes = substr($value, 1, 6);
                $src_dpid = strtoupper(bin2hex($mac_bytes));
                echo "Parsed DPID raw hex: $src_dpid\n";
            }
        } elseif ($type == 2 && $tlv_len >= 2) { // Port ID
            $subtype = ord($value[0]);
            $src_port = ord($value[$tlv_len - 1]); // last byte as port
            echo "Parsed Port ID: $src_port\n";
        } elseif ($type == 0) { // End of LLDPDU
            break;
        }
    }

    if ($src_dpid !== null) {
        $src_dpid_int = hexdec(substr($src_dpid, -4)); // shorten for topology
    } else {
        $src_dpid_int = null;
    }

    return [$src_dpid_int, $src_port];
}

function parse_packet_in_v13_extract_eth($payload)
{
    // Minimum header size before match field (as per OpenFlow 1.3 spec)
    if (strlen($payload) < 24) return null;

    // Skip fixed fields: buffer_id (4) + total_len (2) + reason (1) + table_id (1) + cookie (8) = 16 bytes
    $offset = 16;

    // Read match length (2 bytes at offset 16)
    if (strlen($payload) < $offset + 4) return null;
    $match_type = unpack("n", substr($payload, $offset, 2))[1];
    $match_len  = unpack("n", substr($payload, $offset + 2, 2))[1];
    $offset += $match_len;

    // Align to 8-byte boundary
    if ($offset % 8 !== 0) {
        $offset += 8 - ($offset % 8);
    }

    // Skip padding (2 bytes)
    $offset += 2;

    // The rest is Ethernet frame
    if ($offset >= strlen($payload)) return null;
    return substr($payload, $offset);
}

// ---- I/O helpers ----
function read_exact($s, $n) {
    $buf = "";
    while (strlen($buf) < $n) {
        $chunk = fread($s, $n - strlen($buf));
        if ($chunk === false || $chunk === "") return false;
        $buf .= $chunk;
    }
    return $buf;
}
function socket_id($s) { return (int)$s; }

// ---- Server ----
// Use the IANA OpenFlow port 6653 (pure OF1.3). Change if your device expects 6633.
$server = stream_socket_server("tcp://0.0.0.0:6653", $errno, $errstr);
if (!$server) { echo "Server error: $errstr ($errno)\n"; exit(1); }
stream_set_blocking($server, false);
echo "OF1.3 LLDP Controller listening on 6653\n";

$last_tick = microtime(true);

while (true) {
    $read = [$server];
    foreach ($clients as $c) $read[] = $c['sock'];
    $write = null; $except = null;
    $n = stream_select($read, $write, $except, 0, 500000);
    if ($n === false) { echo "select() error\n"; break; }

    // Accept new
    if (in_array($server, $read, true)) {
        $conn = @stream_socket_accept($server, 0);
        if ($conn) {
            stream_set_blocking($conn, false);
            $id = socket_id($conn);
            $clients[$id] = ['sock'=>$conn, 'phase'=>'hello', 'dpid'=>null];
            // Send HELLO
            fwrite($conn, build_hello(1));
            echo "New TCP, sent HELLO\n";
        }
        $read = array_filter($read, fn($s) => $s !== $server);
    }

    // Handle clients
    foreach ($read as $sock) {
        $id = socket_id($sock);
        if (!isset($clients[$id])) { fclose($sock); continue; }

        $hdr = read_exact($sock, 8);
        if ($hdr === false) {
            $dpid = $clients[$id]['dpid'];
            if ($dpid !== null) { echo "Switch " . dechex($dpid) . " disconnected\n"; unset($switches[$dpid]); }
            else { echo "Client disconnected\n"; }
            fclose($sock); unset($clients[$id]); continue;
        }
        $h = unpack("Cver/Ctype/nlen/Nxid", $hdr);
        $type = $h['type']; $len = $h['len']; $xid = $h['xid'];
        $payload_len = max(0, $len - 8);
        $payload = $payload_len ? read_exact($sock, $payload_len) : "";

        // Basic handling
        if ($type == $OFPT_ECHO_REQUEST) {
            // Echo reply with same payload
            $reply = build_of_header($OFPT_ECHO_REPLY, 8 + strlen($payload), $xid) . $payload;
            fwrite($sock, $reply);
            echo "Echo replied\n";
            continue;
        } elseif ($type == $OFPT_ERROR) {
            if (strlen($payload) >= 4) {
                $err = unpack("netype/necode", substr($payload, 0, 4));
                $et = $err['etype']; $ec = $err['ecode'];
                echo "OF ERROR (len=$len) => err_type=$et err_code=$ec\n";
            } else {
                echo "OF ERROR (len=$len) => payload too short to parse\n";
            }
            // show first 48 bytes of payload to help debug
            $hex = substr(bin2hex($payload), 0, 96);
            echo "OF ERROR payload hex head: $hex\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'hello') {
            if ($type != $OFPT_HELLO) { echo "Expected HELLO, got type $type\n"; }
            // Send FEATURES_REQUEST
            fwrite($sock, build_features_request(10));
            $clients[$id]['phase'] = 'wait_features';
            echo "Sent FEATURES_REQUEST\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'wait_features') {
            if ($type != $OFPT_FEATURES_REPLY) {
                echo "Expected FEATURES_REPLY, got type $type\n";
                continue;
            }
            [$dpid] = parse_features_reply_of13($payload);
            if ($dpid === null) { echo "Bad FEATURES_REPLY\n"; continue; }
            $clients[$id]['dpid'] = $dpid;
            $clients[$id]['phase'] = 'ready';
            $switches[$dpid] = ['sock'=>$sock, 'ports'=>[], 'last_lldp'=>0];
            echo "Switch connected: DPID=" . dechex($dpid) . "\n";

            // Ask for PORT_DESC (1.3 way to learn ports)
            fwrite($sock, build_multipart_port_desc_request(11));
            echo "Sent PORT_DESC request\n";

            // Ensure we receive full packets + have Packet-In paths
            fwrite($sock, build_set_config(0xffff));                        echo "Sent SET_CONFIG\n";
        //    fwrite($sock, build_flow_mod_table_miss_to_controller(0));      echo "Installed table-miss -> CONTROLLER\n";
        //    fwrite($sock, build_flow_mod_eth_type_to_controller(0x88cc));   echo "Installed LLDP -> CONTROLLER flow\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'ready') {
            if ($type == $OFPT_MULTIPART_REPLY) {
                // First 8 bytes are type+flags+pad
                $ports = parse_multipart_port_desc_reply($payload);
                if (!empty($ports)) {
                    $dpid = $clients[$id]['dpid'];
                    $switches[$dpid]['ports'] = $ports;
                    echo "Ports for " . dechex($dpid) . ": [" . implode(",", $ports) . "]\n";
                } else {
                    echo "Received PORT_DESC but no usable ports for " . dechex($clients[$id]['dpid']) . "\n";
                }
            } elseif ($type == $OFPT_PACKET_IN) {

                echo "---- PACKET_IN ----\n";
                echo "DEBUG: PACKET_IN payload len=" . strlen($payload) . "\n";

                $eth = parse_packet_in_v13_extract_eth($payload);

                if ($eth === null) {
                    echo "⚠ DEBUG: parse_packet_in_v13_extract_eth() returned NULL\n";
                } else {
                    $eth_len = strlen($eth);
                    echo "DEBUG: Ethernet frame length=$eth_len\n";

                    if ($eth_len >= 14) {
                        $ethertype_hex = bin2hex(substr($eth, 12, 2));
                        echo "DEBUG: Ethertype=$ethertype_hex (should be 88cc for LLDP)\n";

                        if ($ethertype_hex === "88cc") {
                            $lldp_payload = substr($eth, 14);
                            echo "LLDP packet detected, payload len=" . strlen($lldp_payload) . "\n";

                            [$src_dpid, $src_port] = parse_lldp_tlvs($lldp_payload);

                            if ($src_dpid !== null && $src_port !== null) {
                                $dst_dpid = $clients[$id]['dpid'];
                                $key = dechex($src_dpid) . ":" . $src_port . "->" . dechex($dst_dpid);

                                if (!isset($topology[$key])) {
                                    $topology[$key] = time();
                                    echo "✅ Discovered link: " . dechex($src_dpid) . ":" . $src_port . " --> " . dechex($dst_dpid) . "\n";
                                    prune_topology($topology, 20);
                                    save_topology_json($topology, $TOPO_JSON);
                                }
                            } else {
                                echo "⚠ LLDP parse failed (src_dpid or src_port null)\n";
                            }
                        }
                    } else {
                        echo "⚠ DEBUG: Ethernet frame too short ($eth_len bytes)\n";
                    }
                }
            }
        }
    }

    // Periodic LLDP every 5s
    $now = microtime(true);
    if ($now - $last_tick >= 0.25) {
        foreach ($switches as $dpid => &$sw) {
            if (empty($sw['ports'])) continue; // wait until we have ports
            if ($now - $sw['last_lldp'] >= 5.0) {
                foreach ($sw['ports'] as $p) {
                    if ($p <= 0 || $p >= 0xffffff00) continue;  // skip LOCAL/CONTROLLER/etc.
                    $pkt = build_lldp_packet($dpid, $p);
                    $msg = build_packet_out_of13($p, $pkt, 100);
                    fwrite($sw['sock'], $msg);
                }
                $sw['last_lldp'] = $now;
                echo "Sent LLDP on " . dechex($dpid) . " ports [" . implode(",", $sw['ports']) . "]\n";
            }
        }
        prune_topology($topology, 20);
        save_topology_json($topology, $TOPO_JSON);
        unset($sw);
        $last_tick = $now;
    }
}
