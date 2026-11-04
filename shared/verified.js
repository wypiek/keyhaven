// Well-known, widely used sites. A login whose website belongs to one of these
// registrable domains gets a "verified" tick. Matching is on the registrable domain
// (see urlmatch.baseDomain), so look-alikes such as "paypal.com.evil.net" or
// "accounts-google.com" never match, and shared-hosting tenants (x.github.io) don't either.

import { baseDomain, parseLoose } from './urlmatch.js';

const DOMAINS = `
google.com google.co.uk google.de google.fr google.pl google.es google.it google.ca google.com.au youtube.com gmail.com
blogger.com android.com chromium.org gstatic.com
facebook.com instagram.com whatsapp.com messenger.com threads.net meta.com oculus.com
x.com twitter.com linkedin.com reddit.com tiktok.com snapchat.com pinterest.com discord.com telegram.org signal.org
twitch.tv quora.com medium.com substack.com bsky.app mastodon.social vk.com ok.ru line.me wechat.com
microsoft.com live.com outlook.com office.com microsoftonline.com microsoft365.com xbox.com bing.com skype.com azure.com
github.com gitlab.com bitbucket.org stackoverflow.com stackexchange.com npmjs.com pypi.org crates.io docker.com
apple.com icloud.com
amazon.com amazon.co.uk amazon.de amazon.fr amazon.it amazon.es amazon.pl amazon.ca amazon.co.jp amazon.com.au amazon.in
amazon.nl amazon.se primevideo.com audible.com aws.amazon.com
digitalocean.com heroku.com vercel.com netlify.com cloudflare.com atlassian.com jetbrains.com hetzner.com ovhcloud.com
ovh.com linode.com akamai.com oracle.com ibm.com intel.com nvidia.com amd.com
openai.com chatgpt.com anthropic.com claude.ai huggingface.co kaggle.com perplexity.ai mistral.ai
figma.com notion.so slack.com zoom.us trello.com asana.com monday.com miro.com dropbox.com box.com wetransfer.com
mozilla.org firefox.com wikipedia.org wikimedia.org archive.org
proton.me protonmail.com tuta.com tutanota.com fastmail.com yahoo.com aol.com zoho.com gmx.net gmx.de web.de t-online.de
mail.ru yandex.ru yandex.com duckduckgo.com brave.com opera.com vivaldi.com
adobe.com canva.com grammarly.com salesforce.com hubspot.com shopify.com wix.com squarespace.com godaddy.com
namecheap.com porkbun.com hostinger.com ionos.com strato.de
samsung.com sony.com lenovo.com dell.com hp.com logitech.com asus.com xiaomi.com huawei.com
steampowered.com steamcommunity.com epicgames.com ea.com ubisoft.com blizzard.com battle.net riotgames.com
playstation.com nintendo.com roblox.com minecraft.net mojang.com rockstargames.com gog.com humblebundle.com itch.io
netflix.com spotify.com disneyplus.com hulu.com max.com hbomax.com paramountplus.com crunchyroll.com
soundcloud.com deezer.com tidal.com vimeo.com dailymotion.com
ebay.com ebay.co.uk ebay.de etsy.com aliexpress.com alibaba.com temu.com shein.com walmart.com target.com bestbuy.com
costco.com homedepot.com ikea.com zalando.com zalando.pl zalando.de asos.com nike.com adidas.com hm.com zara.com
booking.com airbnb.com expedia.com tripadvisor.com skyscanner.net kayak.com hotels.com
uber.com lyft.com bolt.eu doordash.com ubereats.com deliveroo.co.uk glovoapp.com wolt.com just-eat.co.uk
ryanair.com wizzair.com lufthansa.com emirates.com britishairways.com klm.com airfrance.com lot.com
paypal.com stripe.com revolut.com wise.com n26.com monzo.com chase.com bankofamerica.com wellsfargo.com citi.com
capitalone.com americanexpress.com discover.com hsbc.com hsbc.co.uk barclays.co.uk lloydsbank.com natwest.com
santander.com ing.com bnpparibas.com deutsche-bank.de commerzbank.de sparkasse.de
coinbase.com binance.com kraken.com robinhood.com venmo.com cash.app klarna.com visa.com mastercard.com
allegro.pl olx.pl onet.pl wp.pl interia.pl o2.pl gazeta.pl tvn24.pl
mbank.pl pkobp.pl ipko.pl ing.pl santander.pl pekao.com.pl bankmillennium.pl aliorbank.pl credit-agricole.pl
bnpparibas.pl citibank.pl velobank.pl blik.com
inpost.pl inpost.eu poczta-polska.pl gov.pl empik.com ceneo.pl x-kom.pl mediaexpert.pl euro.com.pl morele.net
pyszne.pl vinted.pl vinted.com otodom.pl otomoto.pl pracuj.pl librus.pl vulcan.net.pl
play.pl orange.pl plus.pl t-mobile.pl
nytimes.com bbc.co.uk bbc.com theguardian.com cnn.com washingtonpost.com wsj.com bloomberg.com reuters.com ft.com
economist.com
craigslist.org yelp.com imdb.com goodreads.com duolingo.com coursera.org udemy.com edx.org khanacademy.org
chess.com lichess.org patreon.com kickstarter.com gofundme.com indeed.com glassdoor.com fiverr.com upwork.com
docusign.com evernote.com todoist.com
1password.com bitwarden.com lastpass.com nordvpn.com mullvad.net expressvpn.com protonvpn.com tailscale.com
orange.fr free.fr sfr.fr vodafone.com verizon.com att.com t-mobile.com xfinity.com
ups.com fedex.com dhl.com dhl.de usps.com dpd.com gls-group.eu
irs.gov login.gov ssa.gov
`.split(/\s+/).filter(Boolean);

/** Built-in list (used when the server admin hasn't set one). */
export const DEFAULT_DOMAINS = [...new Set(DOMAINS)].sort();

let VERIFIED = new Set(DOMAINS.map((d) => baseDomain(d)));

/** Replace the list with the server's (null restores the built-in list). */
export function setVerifiedDomains(list) {
  VERIFIED = new Set((Array.isArray(list) ? list : DOMAINS).map((d) => baseDomain(d)));
}

/** The verified registrable domain for a URL/host, or null. https (or bare host) only. */
export function verifiedDomain(urlOrHost) {
  const u = parseLoose(urlOrHost);
  if (!u || u.protocol !== 'https:') return null;
  const base = baseDomain(u.hostname);
  return VERIFIED.has(base) ? base : null;
}

/** Verified domain for an item (first matching website), or null. */
export function itemVerified(item) {
  if (item.type !== 'login') return null;
  for (const u of item.urls || []) {
    const d = verifiedDomain(u);
    if (d) return d;
  }
  return null;
}
