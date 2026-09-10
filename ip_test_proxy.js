async function testIp(ip) {
  const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,city,isp,org,proxy,hosting`);
  const data = await resp.json();
  console.log(ip, data);
}
testIp('209.85.220.41');
