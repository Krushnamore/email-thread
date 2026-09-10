const ips = ['8.8.8.8', '198.51.100.1', '104.244.42.1', '3.80.0.0', '192.0.2.1'];
async function test() {
  for (let ip of ips) {
    const r = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting,lat,lon`);
    console.log(ip, await r.json());
  }
}
test();
