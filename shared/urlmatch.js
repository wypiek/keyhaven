// Match saved login URLs against a page URL.
//  3 = same host (and port if specified)   2 = same registrable domain   0 = no match
// Security: http(s) only; an https item never matches an http page; IPs/localhost need
// exact host+port; shared-hosting suffixes are treated as public suffixes.

const MULTI_SUFFIXES = new Set(
  ('co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk com.au net.au org.au edu.au gov.au ' +
    'co.nz org.nz net.nz govt.nz co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ne.kr com.br net.br org.br ' +
    'gov.br com.cn net.cn org.cn gov.cn com.hk com.tw com.sg com.my com.mx com.ar com.co com.pe com.tr ' +
    'com.ua com.pl net.pl org.pl co.in net.in org.in gov.in co.za org.za co.il org.il co.id or.id com.ph ' +
    'com.vn com.eg com.sa com.pk com.ng co.th in.th ac.th com.es com.pt com.gr com.ru co.at or.at ac.at ' +
    'github.io gitlab.io vercel.app netlify.app pages.dev workers.dev herokuapp.com blogspot.com web.app ' +
    'firebaseapp.com azurewebsites.net cloudfront.net s3.amazonaws.com appspot.com glitch.me repl.co ' +
    'onrender.com fly.dev surge.sh neocities.org wordpress.com tumblr.com myshopify.com ngrok.io ' +
    'ngrok-free.app duckdns.org dyndns.org no-ip.org translate.goog')
    .split(' '),
);

export function parseLoose(input) {
  const s = String(input || '').trim();
  if (!s) return null;
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
  } catch {
    return null;
  }
}

function isLocalOrIp(host) {
  return (
    host === 'localhost' || host.endsWith('.localhost') || !host.includes('.') ||
    /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')
  );
}

export function baseDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  for (const take of [3, 2]) {
    if (labels.length > take && MULTI_SUFFIXES.has(labels.slice(-take).join('.'))) {
      return labels.slice(-take - 1).join('.');
    }
  }
  return labels.slice(-2).join('.');
}

function port(u) {
  return u.port || (u.protocol === 'https:' ? '443' : '80');
}

export function matchScore(saved, page) {
  const s = parseLoose(saved);
  let p;
  try {
    p = new URL(page);
  } catch {
    return 0;
  }
  if (!s || !/^https?:$/.test(s.protocol) || !/^https?:$/.test(p.protocol)) return 0;
  if (s.protocol === 'https:' && p.protocol === 'http:') return 0;
  const sh = s.hostname.toLowerCase();
  const ph = p.hostname.toLowerCase();
  if (isLocalOrIp(sh) || isLocalOrIp(ph)) return sh === ph && port(s) === port(p) ? 3 : 0;
  if (sh === ph) return s.port && s.port !== p.port ? 0 : 3;
  return baseDomain(sh) === baseDomain(ph) ? 2 : 0;
}

export function itemMatchScore(item, pageUrl) {
  if (item.type !== 'login' || item.deletedAt) return 0;
  return Math.max(0, ...(item.urls || []).map((u) => matchScore(u, pageUrl)));
}

export function displayHost(input) {
  const u = parseLoose(input);
  return u ? u.hostname.replace(/^www\./, '') : '';
}

/** Saved URL to store for a page: origin only (no paths/queries that may contain tokens). */
export function originFor(pageUrl) {
  try {
    return new URL(pageUrl).origin;
  } catch {
    return '';
  }
}
