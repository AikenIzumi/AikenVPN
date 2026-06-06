export namespace config {
	
	export class ConnectionStatus {
	    profile_id: string;
	    profile_name: string;
	    state: string;
	    error?: string;
	    // Go type: time
	    connected_at?: any;
	    local_ip?: string;
	    server_ip?: string;
	    bytes_sent?: number;
	    bytes_recv?: number;
	
	    static createFrom(source: any = {}) {
	        return new ConnectionStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.profile_id = source["profile_id"];
	        this.profile_name = source["profile_name"];
	        this.state = source["state"];
	        this.error = source["error"];
	        this.connected_at = this.convertValues(source["connected_at"], null);
	        this.local_ip = source["local_ip"];
	        this.server_ip = source["server_ip"];
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_recv = source["bytes_recv"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class OpenVPNConfig {
	    config_content: string;
	    username?: string;
	    password?: string;
	
	    static createFrom(source: any = {}) {
	        return new OpenVPNConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config_content = source["config_content"];
	        this.username = source["username"];
	        this.password = source["password"];
	    }
	}
	export class WireGuardConfig {
	    private_key: string;
	    address: string;
	    dns: string;
	    mtu?: number;
	    peer_public_key: string;
	    peer_psk?: string;
	    peer_endpoint: string;
	    peer_allowed_ips: string;
	    peer_keepalive?: number;
	
	    static createFrom(source: any = {}) {
	        return new WireGuardConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.private_key = source["private_key"];
	        this.address = source["address"];
	        this.dns = source["dns"];
	        this.mtu = source["mtu"];
	        this.peer_public_key = source["peer_public_key"];
	        this.peer_psk = source["peer_psk"];
	        this.peer_endpoint = source["peer_endpoint"];
	        this.peer_allowed_ips = source["peer_allowed_ips"];
	        this.peer_keepalive = source["peer_keepalive"];
	    }
	}
	export class Profile {
	    id: string;
	    name: string;
	    tunnel_type: string;
	    // Go type: time
	    created_at: any;
	    // Go type: time
	    updated_at: any;
	    // Go type: time
	    last_used?: any;
	    is_favorite: boolean;
	    color?: string;
	    server?: string;
	    username?: string;
	    password?: string;
	    preshared_key?: string;
	    auth_method?: string;
	    encryption?: string;
	    remember_credential: boolean;
	    split_tunneling: boolean;
	    skip_cert_check: boolean;
	    use_winlogon_cred?: boolean;
	    wireguard?: WireGuardConfig;
	    openvpn?: OpenVPNConfig;
	
	    static createFrom(source: any = {}) {
	        return new Profile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.tunnel_type = source["tunnel_type"];
	        this.created_at = this.convertValues(source["created_at"], null);
	        this.updated_at = this.convertValues(source["updated_at"], null);
	        this.last_used = this.convertValues(source["last_used"], null);
	        this.is_favorite = source["is_favorite"];
	        this.color = source["color"];
	        this.server = source["server"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.preshared_key = source["preshared_key"];
	        this.auth_method = source["auth_method"];
	        this.encryption = source["encryption"];
	        this.remember_credential = source["remember_credential"];
	        this.split_tunneling = source["split_tunneling"];
	        this.skip_cert_check = source["skip_cert_check"];
	        this.use_winlogon_cred = source["use_winlogon_cred"];
	        this.wireguard = this.convertValues(source["wireguard"], WireGuardConfig);
	        this.openvpn = this.convertValues(source["openvpn"], OpenVPNConfig);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace nettest {
	
	export class PingResult {
	    host: string;
	    min_ms: number;
	    avg_ms: number;
	    max_ms: number;
	    loss_pct: number;
	    jitter_ms: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new PingResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.min_ms = source["min_ms"];
	        this.avg_ms = source["avg_ms"];
	        this.max_ms = source["max_ms"];
	        this.loss_pct = source["loss_pct"];
	        this.jitter_ms = source["jitter_ms"];
	        this.error = source["error"];
	    }
	}
	export class SpeedResult {
	    download_mbps: number;
	    upload_mbps: number;
	    ping_ms: number;
	    server: string;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new SpeedResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.download_mbps = source["download_mbps"];
	        this.upload_mbps = source["upload_mbps"];
	        this.ping_ms = source["ping_ms"];
	        this.server = source["server"];
	        this.error = source["error"];
	    }
	}

}

