const YAML = require("yaml");
const axios = require("axios");

/**
 * Parse a vless:// URI into a Clash proxy object.
 */
function parseVlessUri(uri) {
  const url = new URL(uri);
  const name = decodeURIComponent(url.hash.slice(1));
  const uuid = url.username;
  const server = url.hostname;
  const port = parseInt(url.port, 10);
  const params = url.searchParams;

  const proxy = {
    name,
    type: "vless",
    server,
    port,
    uuid,
    udp: true,
  };

  const network = params.get("type") || "tcp";
  if (network !== "tcp") {
    proxy.network = network;
  }

  const security = params.get("security");
  if (security === "tls" || security === "reality") {
    proxy.tls = true;
  }
  if (security === "reality") {
    const realityOpts = {};
    if (params.get("pbk")) realityOpts["public-key"] = params.get("pbk");
    if (params.get("sid")) realityOpts["short-id"] = params.get("sid");
    proxy["reality-opts"] = realityOpts;
  }

  const sni = params.get("sni") || params.get("servername");
  if (sni) {
    proxy.servername = sni;
  }

  const flow = params.get("flow");
  if (flow) {
    proxy.flow = flow;
  }

  const fp = params.get("fp");
  if (fp) {
    proxy["client-fingerprint"] = fp;
  }

  return proxy;
}

/**
 * Parse a vmess:// URI into a Clash proxy object.
 */
function parseVmessUri(uri) {
  const b64 = uri.slice("vmess://".length);
  let obj;
  try {
    obj = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  } catch (e) {
    return null;
  }

  const proxy = {
    name: obj.ps || obj.add,
    type: "vmess",
    server: obj.add,
    port: parseInt(obj.port, 10),
    uuid: obj.id,
    alterId: parseInt(obj.aid, 10) || 0,
    cipher: obj.scy || "auto",
    udp: true,
  };

  if (obj.net) proxy.network = obj.net;
  if (obj.tls === "tls") proxy.tls = true;
  if (obj.sni) proxy.servername = obj.sni;
  if (obj["skip-cert-verify"]) proxy["skip-cert-verify"] = true;
  if (obj.path) proxy["ws-path"] = obj.path;
  if (obj.host) proxy["ws-opts"] = { headers: { Host: obj.host } };

  return proxy;
}

/**
 * Parse a trojan:// URI into a Clash proxy object.
 */
function parseTrojanUri(uri) {
  const url = new URL(uri);
  const name = decodeURIComponent(url.hash.slice(1));
  const password = url.username;
  const server = url.hostname;
  const port = parseInt(url.port, 10);
  const params = url.searchParams;

  const proxy = {
    name,
    type: "trojan",
    server,
    port,
    password,
    udp: true,
  };

  const sni = params.get("sni") || params.get("peer");
  if (sni) proxy.sni = sni;

  const skipVerify = params.get("allowInsecure");
  if (skipVerify === "1" || skipVerify === "true") {
    proxy["skip-cert-verify"] = true;
  }

  const network = params.get("type");
  if (network && network !== "tcp") proxy.network = network;

  return proxy;
}

/**
 * Parse a shadowsocks ss:// URI into a Clash proxy object.
 */
function parseSsUri(uri) {
  // ss://BASE64(method:password)@host:port#name
  // or ss://BASE64(method:password@host:port)#name
  const hashIdx = uri.lastIndexOf("#");
  const name = hashIdx !== -1 ? decodeURIComponent(uri.slice(hashIdx + 1)) : "";
  const withoutHash = hashIdx !== -1 ? uri.slice(0, hashIdx) : uri;
  const rest = withoutHash.slice("ss://".length);

  let method, password, server, port;
  if (rest.includes("@")) {
    const atIdx = rest.lastIndexOf("@");
    const credB64 = rest.slice(0, atIdx);
    const hostPort = rest.slice(atIdx + 1);
    let creds;
    try {
      creds = Buffer.from(credB64, "base64").toString("utf8");
    } catch (e) {
      creds = credB64;
    }
    const colonIdx = creds.indexOf(":");
    if (colonIdx === -1) return null;
    method = creds.slice(0, colonIdx);
    password = creds.slice(colonIdx + 1);
    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) return null;
    server = hostPort.slice(0, lastColon);
    port = parseInt(hostPort.slice(lastColon + 1), 10);
  } else {
    let decoded;
    try {
      decoded = Buffer.from(rest, "base64").toString("utf8");
    } catch (e) {
      return null;
    }
    const atIdx = decoded.lastIndexOf("@");
    if (atIdx === -1) return null;
    const creds = decoded.slice(0, atIdx);
    const hostPort = decoded.slice(atIdx + 1);
    const colonIdx = creds.indexOf(":");
    if (colonIdx === -1) return null;
    method = creds.slice(0, colonIdx);
    password = creds.slice(colonIdx + 1);
    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) return null;
    server = hostPort.slice(0, lastColon);
    port = parseInt(hostPort.slice(lastColon + 1), 10);
  }

  return {
    name: name || server,
    type: "ss",
    server,
    port,
    cipher: method,
    password,
    udp: true,
  };
}

/**
 * Try to parse content as newline-separated proxy URIs.
 * Returns an array of Clash proxy objects, or null if none found.
 */
function parseProxyUriLines(content) {
  const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const proxies = [];
  for (const line of lines) {
    let proxy = null;
    try {
      if (line.startsWith("vless://")) {
        proxy = parseVlessUri(line);
      } else if (line.startsWith("vmess://")) {
        proxy = parseVmessUri(line);
      } else if (line.startsWith("trojan://")) {
        proxy = parseTrojanUri(line);
      } else if (line.startsWith("ss://")) {
        proxy = parseSsUri(line);
      }
    } catch (e) {
      const scheme = line.split("://")[0] + "://";
      console.log(`⚠️ Failed to parse proxy URI scheme ${scheme}, error: ${e.message}`);
    }
    if (proxy) proxies.push(proxy);
  }
  return proxies.length > 0 ? proxies : null;
}

/**
 * Attempt to extract proxies from raw subscription content.
 * Handles: Clash YAML, base64-encoded proxy URIs, raw proxy URI lines.
 */
function extractProxies(raw) {
  // 1. Try YAML parse
  let config = null;
  try {
    config = YAML.parse(raw);
    console.log(`📄 YAML parse succeeded, type: ${typeof config}`);
  } catch (e) {
    console.log(`⚠️ YAML parse failed: ${e.message}`);
  }

  if (config && typeof config === "object" && Array.isArray(config.proxies)) {
    console.log(`✅ Found ${config.proxies.length} proxies in YAML config`);
    return { proxies: config.proxies };
  }

  // 2. Try treating raw content as proxy URI lines
  console.log(`🔍 Trying raw content as proxy URI lines`);
  const directProxies = parseProxyUriLines(raw);
  if (directProxies) {
    console.log(`✅ Parsed ${directProxies.length} proxies from raw URI lines`);
    return { proxies: directProxies };
  }

  // 3. Try base64 decode
  console.log(`🔍 Trying base64 decode`);
  let decoded = null;
  try {
    decoded = Buffer.from(raw.trim(), "base64").toString("utf8");
    console.log(`📄 Base64 decoded successfully, line count: ${decoded.split(/\r?\n/).filter(Boolean).length}`);
  } catch (e) {
    console.log(`⚠️ Base64 decode failed: ${e.message}`);
    return null;
  }

  // 3a. Try YAML on decoded content
  try {
    const decodedConfig = YAML.parse(decoded);
    if (decodedConfig && typeof decodedConfig === "object" && Array.isArray(decodedConfig.proxies)) {
      console.log(`✅ Found ${decodedConfig.proxies.length} proxies in base64-decoded YAML config`);
      return { proxies: decodedConfig.proxies };
    }
  } catch (e) {
    console.log(`⚠️ YAML parse of base64-decoded content failed: ${e.message}`);
  }

  // 3b. Try decoded content as proxy URI lines
  const decodedProxies = parseProxyUriLines(decoded);
  if (decodedProxies) {
    console.log(`✅ Parsed ${decodedProxies.length} proxies from base64-decoded URI lines`);
    return { proxies: decodedProxies };
  }

  console.log(`❌ Could not extract proxies from subscription content`);
  return null;
}

module.exports = async (req, res) => {
  const url = req.query.url;
  const target = req.query.target;
  console.log(`query: ${JSON.stringify(req.query)}`);
  if (url === undefined) {
    res.status(400).send("Missing parameter: url");
    return;
  }

  console.log(`Fetching url: ${url}`);
  let configFile = null;
  try {
    const result = await axios({
      url,
      headers: {
        "User-Agent":
          "ClashX Pro/1.72.0.4 (com.west2online.ClashXPro; build:1.72.0.4; macOS 12.0.1) Alamofire/5.4.4",
      },
    });
    configFile = result.data;
    console.log(`📥 Fetched content, type: ${typeof configFile}, length: ${typeof configFile === 'string' ? configFile.length : JSON.stringify(configFile).length}`);
  } catch (error) {
    console.log(`❌ Fetch error: ${error}`);
    res.status(400).send(`Unable to get url, error: ${error}`);
    return;
  }

  // axios may auto-parse JSON; ensure we work with a string
  if (typeof configFile !== "string") {
    configFile = JSON.stringify(configFile);
  }

  console.log(`🔄 Extracting proxies from subscription`);
  const config = extractProxies(configFile);

  if (!config || !config.proxies) {
    console.log(`❌ No proxies found in subscription`);
    res.status(400).send("No proxies in this config");
    return;
  }

  if (target === "surge") {
    const supportedProxies = config.proxies.filter((proxy) =>
      ["ss", "vmess", "trojan"].includes(proxy.type)
    );
    const surgeProxies = supportedProxies.map((proxy) => {
      console.log(proxy.server);
      const common = `${proxy.name} = ${proxy.type}, ${proxy.server}, ${proxy.port}`;
      if (proxy.type === "ss") {
        // ProxySS = ss, example.com, 2021, encrypt-method=xchacha20-ietf-poly1305, password=12345, obfs=http, obfs-host=example.com, udp-relay=true
        if (proxy.plugin === "v2ray-plugin") {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge does not support Shadowsocks with v2ray-plugin`
          );
          return;
        }
        let result = `${common}, encrypt-method=${proxy.cipher}, password=${proxy.password}`;
        if (proxy.plugin === "obfs") {
          const mode = proxy?.["plugin-opts"].mode;
          const host = proxy?.["plugin-opts"].host;
          result = `${result}, obfs=${mode}${
            host ? `, obfs-host=example.com ${host}` : ""
          }`;
        }
        if (proxy.udp) {
          result = `${result}, udp-relay=${proxy.udp}`;
        }
        return result;
      } else if (proxy.type === "vmess") {
        // ProxyVmess = vmess, example.com, 2021, username=0233d11c-15a4-47d3-ade3-48ffca0ce119, skip-cert-verify=true, sni=example.com, tls=true, ws=true, ws-path=/path
        if (["h2", "http", "grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Vmess(${proxy.network})`
          );
          return;
        }
        let result = `${common}, username=${proxy.uuid}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.servername) {
          result = `${result}, sni=${proxy.servername}`;
        }
        if (proxy.tls) {
          result = `${result}, tls=${proxy.tls}`;
        }
        if (proxy.network === "ws") {
          result = `${result}, ws=true`;
        }
        if (proxy["ws-path"]) {
          result = `${result}, ws-path=${proxy["ws-path"]}`;
        }
        return result;
      } else if (proxy.type === "trojan") {
        // ProxyTrojan = trojan, example.com, 2021, username=user, password=12345, skip-cert-verify=true, sni=example.com
        if (["grpc"].includes(proxy.network)) {
          console.log(
            `Skip convert proxy ${proxy.name} because Surge probably doesn't support Trojan(${proxy.network})`
          );
          return;
        }
        let result = `${common}, password=${proxy.password}`;
        if (proxy["skip-cert-verify"]) {
          result = `${result}, skip-cert-verify=${proxy["skip-cert-verify"]}`;
        }
        if (proxy.sni) {
          result = `${result}, sni=${proxy.sni}`;
        }
        return result;
      }
    });
    const proxies = surgeProxies.filter((p) => p !== undefined);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(proxies.join("\n"));
  } else {
    const response = YAML.stringify({ proxies: config.proxies });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.status(200).send(response);
  }
};
