-- 0007 — persist the infrastructure layer
--
-- The engine could describe policy and could not describe the network the policy
-- runs on. `grep -rn vlan db/` returned nothing, so "which VLAN is this host in",
-- "how many subnets do we have" and "what does the edge look like" were
-- unanswerable rather than merely unrendered.
--
-- These six tables are snapshot-scoped and CASCADE with their snapshot, exactly
-- like graph_nodes and graph_edges: they are a derived view of one ingest, not
-- governance. (The gap/evidence register, which must SURVIVE a recompute, is a
-- separate migration and deliberately uses ON DELETE SET NULL instead.)
--
-- THE CONSTRAINTS BELOW ARE THE POINT.
--
-- A layered network diagram is the single largest fabrication risk in this
-- product. Every other screen renders something the engine computed from a rule
-- somebody wrote; this one draws boxes and lines that look like a photograph of
-- a building. If we draw a modem, an edge router and two criss-crossed switches
-- that no source ever reported, the screen is a lie in a way a wrong severity
-- score is not — a reader cannot tell by looking.
--
-- So the honesty rules are CHECK constraints rather than review comments:
--
--   topology_links.evidence has no 'inferred' member. Every value names a
--   specific observation. A line drawn because the picture looked thin without
--   it cannot be stored, and therefore cannot be drawn.
--
--   (layer IS NULL) = (layer_source = 'unknown'). A device we could not place
--   must say so on BOTH columns or neither. Half-stating it is how an unplaced
--   node quietly acquires a lane.
--
--   role <> 'unknown' implies role_source IN ('declared','derived'). A named
--   device role with no provenance cannot exist, so the inventory can always
--   show its working for "why do you call this an L3 switch".
--
--   admin_up / oper_up are nullable and NULL MEANS NOT REPORTED. Never DEFAULT
--   false: "the source did not say" and "the port is down" are different facts,
--   and a diagram that greys out every unreported port invents an outage.

SET search_path TO ztpa, public;

-- ── Devices ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    snapshot_id   text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    device_key    text NOT NULL,
    name          text NOT NULL,
    role          text NOT NULL DEFAULT 'unknown'
                    CHECK (role IN ('modem','router','firewall','l3_switch','l2_switch',
                                    'hub','bridge','load_balancer','wireless_ap','server',
                                    'workstation','virtual_appliance','unknown')),
    role_source   text NOT NULL DEFAULT 'unknown'
                    CHECK (role_source IN ('declared','derived','unknown')),
    role_reason   text NOT NULL DEFAULT '',
    vendor        text,
    model         text,
    os_version    text,
    serial        text,
    mgmt_ip       text,
    site          text,
    ha_group      text,
    ha_role       text,
    -- Assigned by topology.reconstruct from graph POSITION, never by a source.
    layer         text CHECK (layer IN ('internet','circuit','modem','edge','perimeter',
                                        'core','access','segment','endpoint')),
    layer_source  text NOT NULL DEFAULT 'unknown'
                    CHECK (layer_source IN ('declared','derived','unknown')),
    layer_reason  text NOT NULL DEFAULT '',
    tags          text[] NOT NULL DEFAULT '{}',
    source_tool   text NOT NULL,
    source_tier   text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    raw_ref       text NOT NULL,
    simulated     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, device_key),

    -- A named role always has a story behind it.
    CONSTRAINT devices_role_is_sourced
        CHECK (role = 'unknown' OR role_source IN ('declared','derived')),
    -- Unplaced is a single state, stated on both columns or neither.
    CONSTRAINT devices_layer_matches_source
        CHECK ((layer IS NULL) = (layer_source = 'unknown'))
);

-- ── Interfaces ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_interfaces (
    snapshot_id     text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    interface_key   text NOT NULL,
    device_key      text NOT NULL,
    name            text NOT NULL,
    description     text,
    addresses       text[] NOT NULL DEFAULT '{}',
    -- Everything reachable THROUGH this interface, when the source says so.
    -- AlgoSec's "IPs behind interface" is the richest instance and is what lets
    -- a policy product contribute to a topology at all.
    networks_behind text[] NOT NULL DEFAULT '{}',
    vlan_id         int CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),
    zone            text,
    -- NULL = NOT REPORTED. See the header: never DEFAULT false.
    admin_up        boolean,
    oper_up         boolean,
    speed_mbps      int,
    lag_group       text,
    mac             text,
    neighbor_device    text,
    neighbor_interface text,
    source_tool     text NOT NULL,
    source_tier     text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    raw_ref         text NOT NULL,
    simulated       boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, interface_key)
);

-- ── Links ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS topology_links (
    snapshot_id     text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    link_key        text NOT NULL,
    a_device        text NOT NULL,
    a_interface     text,
    b_device        text NOT NULL,
    b_interface     text,
    -- NO 'inferred' MEMBER, AND THERE MUST NEVER BE ONE. Each value names an
    -- observation: a neighbour protocol, a console's topology API, a config
    -- stanza (HA pair, LAG), a next hop that resolves, an outright declaration,
    -- or provable address containment. `containment` is the weakest and is
    -- labelled rather than blended in with a cable.
    evidence        text NOT NULL
                      CHECK (evidence IN ('lldp','cdp','api_topology','config',
                                          'routing','declared','containment')),
    evidence_detail text NOT NULL DEFAULT '',
    -- Alternate paths for one purpose (the criss-cross). Read by the resilience
    -- analyzer, which must not report a bridge that has a live sibling.
    redundant_group text,
    aggregated      boolean NOT NULL DEFAULT false,
    member_count    int NOT NULL DEFAULT 1 CHECK (member_count >= 1),
    source_tool     text NOT NULL,
    source_tier     text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    simulated       boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, link_key),
    -- A device is not adjacent to itself; a self-link would make every
    -- articulation-point result wrong.
    CONSTRAINT topology_links_not_self CHECK (a_device <> b_device)
);

-- ── VLANs ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vlans (
    snapshot_id text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    vlan_id     int NOT NULL CHECK (vlan_id BETWEEN 1 AND 4094),
    name        text,
    subnets     text[] NOT NULL DEFAULT '{}',
    gateways    text[] NOT NULL DEFAULT '{}',
    device_keys text[] NOT NULL DEFAULT '{}',
    tags        text[] NOT NULL DEFAULT '{}',
    source_tool text NOT NULL,
    source_tier text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    raw_ref     text NOT NULL,
    simulated   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, vlan_id)
);

-- ── Subnets ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subnets (
    snapshot_id text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    cidr        text NOT NULL,
    name        text,
    vlan_id     int CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),
    gateways    text[] NOT NULL DEFAULT '{}',
    device_keys text[] NOT NULL DEFAULT '{}',
    zone        text,
    tags        text[] NOT NULL DEFAULT '{}',
    source_tool text NOT NULL,
    source_tier text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    raw_ref     text NOT NULL,
    simulated   boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, cidr)
);

-- ── Circuits ───────────────────────────────────────────────────────────────
-- Modelled separately from the interface that terminates one, because the whole
-- redundancy question is that two circuits can share a modem, a router, a
-- building entry or -- most expensively -- a CARRIER, and each is a different
-- single point of failure. A circuit that is merely an attribute of an interface
-- cannot express any of them, and "two diverse links from one carrier" is
-- redundancy that looks real on a diagram and is not.
CREATE TABLE IF NOT EXISTS circuits (
    snapshot_id    text NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
    circuit_id     text NOT NULL,
    provider       text,
    technology     text NOT NULL DEFAULT 'unknown'
                     CHECK (technology IN ('mpls','p2p','isdn','broadband','fiber',
                                           'lte','satellite','unknown')),
    bandwidth_mbps int,
    public_ips     text[] NOT NULL DEFAULT '{}',
    device_key     text,
    interface      text,
    state          text NOT NULL DEFAULT 'unknown'
                     CHECK (state IN ('up','down','standby','unknown')),
    source_tool    text NOT NULL,
    source_tier    text NOT NULL CHECK (source_tier IN ('aggregator','management_console','device')),
    raw_ref        text NOT NULL,
    simulated      boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, circuit_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_layer     ON devices (snapshot_id, layer);
CREATE INDEX IF NOT EXISTS idx_devices_role      ON devices (snapshot_id, role);
CREATE INDEX IF NOT EXISTS idx_ifaces_device     ON device_interfaces (snapshot_id, device_key);
CREATE INDEX IF NOT EXISTS idx_ifaces_vlan       ON device_interfaces (snapshot_id, vlan_id);
CREATE INDEX IF NOT EXISTS idx_links_a           ON topology_links (snapshot_id, a_device);
CREATE INDEX IF NOT EXISTS idx_links_b           ON topology_links (snapshot_id, b_device);
CREATE INDEX IF NOT EXISTS idx_circuits_device   ON circuits (snapshot_id, device_key);
