---
layout: home

hero:
  name: meow-rs
  text: The manual
  tagline: Every feature and every config key of the Rust proxy kernel that always lands on its feet — protocols, rules, DNS, transparent proxy, and the REST API.
  image:
    src: /logo.svg
    alt: meow-rs
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: Configuration
      link: /guide/configuration
    - theme: alt
      text: View on GitHub
      link: https://github.com/madeye/meow-rs

features:
  - icon: 🧭
    title: Proxy protocols
    details: Shadowsocks, Trojan, VLESS (REALITY / XTLS-Vision), VMess, Hysteria2, Snell, AnyTLS, HTTP & SOCKS5 — TCP and UDP relay.
    link: /guide/proxies
  - icon: 📋
    title: Rule engine
    details: 30 rule types — domain, IP-CIDR, GeoIP, GeoSite, ASN, port, process, and AND/OR/NOT logic. First match wins.
    link: /guide/rules
  - icon: 🔭
    title: DNS & snooping
    details: Caching resolver with FakeIP, redir-host snooping, nameserver policies, DoT/DoH upstreams, and a reverse IP→domain table.
    link: /guide/dns
  - icon: 🛡️
    title: Transparent proxy
    details: Kernel-level interception via nftables (Linux) or pf (macOS), SNI sniffing, and SO_MARK loop avoidance.
    link: /guide/transparent-proxy
  - icon: 🧶
    title: Proxy groups
    details: Selector, URL-Test, Fallback, LoadBalance, and Relay groups with periodic health checks.
    link: /guide/proxy-groups
  - icon: 🖥️
    title: REST API & dashboard
    details: An Axum-powered API plus a built-in web UI — switch proxies, edit rules, watch live traffic, stream logs.
    link: /reference/rest-api
---
