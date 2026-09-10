import { fileURLToPath } from 'url';
import dns from 'dns/promises';

async function safeDnsLookup(host) {
  try {
    const promise = dns.lookup(host);
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 1200));
    const res = await Promise.race([promise, timeout]);
    return res;
  } catch (e) {
    console.log("caught dns", e.message);
  }
}

async function safeGeoLookup(ip) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,proxy,hosting,lat,lon`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (resp.ok) {
      return await resp.json();
    }
  } catch (e) {
    console.log("caught fetch", e.message);
  }
}

async function run() {
  await safeDnsLookup('invalid.domain.that.does.not.exist');
  await safeGeoLookup('999.999.999.999');
  console.log("Survived!");
}
run();
