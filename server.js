const express = require('express');
const cors = require('cors');
const useragent = require('useragent');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const crypto = require('crypto');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
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
  windowMs: 15 * 60 * 1000, // 15 min
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://random-nfpf.onrender.com',
      'https://vanprojects.netlify.app'
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
app.use(express.static('public')); // Serve static files
app.use(limiter);

const csrfProtection = csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production' } });
app.use(csrfProtection);

app.use((req, res, next) => {
  req.sessionId = req.headers['x-session-id'] || uuidv4();
  res.setHeader('X-Session-ID', req.sessionId);
  res.setHeader('X-CSRF-Token', req.csrfToken());
  next();
});

app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
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
      <script src="/client.js"></script>
    </body>
    </html>
  `);
});

// Basic route
app.get('/', (req, res) => {
  res.send('Tf you doing here.');
});

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
}

function getDeviceFingerprint(req) {
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept'] || '',
    req.headers['connection'] || '',
    req.body.screenSize || '',
    req.body.timezone || '',
    req.body.canvasHash || ''
  ];
  return crypto.createHash('md5').update(components.join('|')).digest('hex');
}

function detectSecurityThreats(req, visitorInfo) {
  const threats = [];

  if (req.body.inlineScripts?.length || req.body.cookieAccess) {
    threats.push({
      type: 'XSS',
      details: `Detected ${req.body.inlineScripts?.length || 0} inline scripts and cookie access: ${req.body.cookieAccess}`
    });
  }

  if (req.headers['referer']?.includes('token=') || req.headers['referer']?.includes('auth=')) {
    threats.push({
      type: 'Referrer Leakage',
      details: `Sensitive data in referer: ${req.headers['referer']}`
    });
  }

  if (req.body.thirdPartyRequests?.length) {
    threats.push({
      type: 'Cookie Syncing',
      details: `Third-party requests to: ${req.body.thirdPartyRequests.join(', ')}`
    });
  }

  if (req.cookies?.some(cookie => cookie.domain?.startsWith('.'))) {
    threats.push({
      type: 'Subdomain Cookie Scope Abuse',
      details: 'Broad cookie domain detected'
    });
  }

  if (!req.secure && process.env.NODE_ENV === 'production') {
    threats.push({
      type: 'MITM Risk',
      details: 'Insecure HTTP connection detected'
    });
  }

  if (req.body.postMessageCalls?.length) {
    threats.push({
      type: 'PostMessage Misuse',
      details: `Unverified postMessage calls: ${req.body.postMessageCalls.join(', ')}`
    });
  }

  return threats;
}

app.post('/api/visit', csrfProtection, async (req, res) => {
  try {
    const ip = getClientIP(req);
    
    const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,mobile,proxy,hosting`);
    const geoData = await geoResponse.json();

    if (geoData.status === 'fail') {
      logger.error('Geolocation API error', { message: geoData.message, ip });
      return res.status(400).send('Invalid IP address');
    }

    const agent = useragent.parse(req.headers['user-agent']);
    const referer = req.headers['referer'] || 'Direct';
    const fingerprint = getDeviceFingerprint(req);

    const plugins = req.body.plugins ? Array.isArray(req.body.plugins) ? req.body.plugins : [] : [];
    const mimeTypes = req.body.mimeTypes ? Array.isArray(req.body.mimeTypes) ? req.body.mimeTypes : [] : [];

    const visitorInfo = {
      sessionId: req.sessionId,
      ip: geoData.query,
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
      device: req.body.device || 'Unknown',
      timestamp: req.body.ts || new Date().toISOString(),
      browser: agent.toAgent(),
      os: agent.os.toString(),
      deviceType: agent.device.toString(),
      referer: referer,
      acceptLanguage: req.headers['accept-language'] || 'Unknown',
      accept: req.headers['accept'] || 'Unknown',
      connection: req.headers['connection'] || 'Unknown',
      fingerprint: fingerprint,
      requestMethod: req.method,
      requestPath: req.originalUrl,
      userAgentRaw: req.headers['user-agent'],
      screenSize: req.body.screenSize || 'Unknown',
      colorDepth: req.body.colorDepth || 'Unknown',
      timezone: req.body.timezone || 'Unknown',
      language: req.body.language || 'Unknown',
      hardwareConcurrency: req.body.hardwareConcurrency || 'Unknown',
      deviceMemory: req.body.deviceMemory || 'Unknown',
      doNotTrack: req.body.doNotTrack || 'Unknown',
      canvasHash: req.body.canvasHash || 'Unknown',
      plugins: plugins,
      mimeTypes: mimeTypes,
      inlineScripts: req.body.inlineScripts || [],
      cookieAccess: req.body.cookieAccess || false,
      thirdPartyRequests: req.body.thirdPartyRequests || [],
      postMessageCalls: req.body.postMessageCalls || []
    };

    const threats = detectSecurityThreats(req, visitorInfo);
    if (threats.length) {
      logger.warn('Security Threats Detected', { threats, visitorInfo });
    }

    logger.info('Visitor Info', { ...visitorInfo, threats });

    const webhookURL = 'https://ptb.discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';
    const payload = {
      embeds: [{
        title: 'New Visitor Detected!',
        color: threats.length ? 0xff0000 : 0x00ff00, // Red if threats detected, else green
        timestamp: visitorInfo.timestamp,
        fields: [
          { name: 'Session ID', value: visitorInfo.sessionId, inline: true },
          { name: 'Device', value: visitorInfo.device, inline: true },
          { name: 'IP', value: visitorInfo.ip, inline: true },
          { name: 'Country', value: visitorInfo.country, inline: true },
          { name: 'Region', value: visitorInfo.region, inline: true },
          { name: 'City', value: visitorInfo.city, inline: true },
          { name: 'ZIP', value: visitorInfo.zip || 'N/A', inline: true },
          { name: 'Coordinates', value: `(${visitorInfo.latitude}, ${visitorInfo.longitude})`, inline: true },
          { name: 'ISP', value: visitorInfo.isp, inline: true },
          { name: 'Organization', value: visitorInfo.organization || 'N/A', inline: true },
          { name: 'AS', value: visitorInfo.as || 'N/A', inline: true },
          { name: 'Mobile', value: visitorInfo.mobile ? 'Yes' : 'No', inline: true },
          { name: 'Proxy', value: visitorInfo.proxy ? 'Yes' : 'No', inline: true },
          { name: 'Hosting', value: visitorInfo.hosting ? 'Yes' : 'No', inline: true },
          { name: 'Browser', value: visitorInfo.browser, inline: true },
          { name: 'OS', value: visitorInfo.os, inline: true },
          { name: 'Device Type', value: visitorInfo.deviceType, inline: true },
          { name: 'Referer', value: visitorInfo.referer, inline: true },
          { name: 'Language', value: visitorInfo.acceptLanguage, inline: true },
          { name: 'Accept', value: visitorInfo.accept, inline: true },
          { name: 'Connection', value: visitorInfo.connection, inline: true },
          { name: 'Fingerprint', value: visitorInfo.fingerprint, inline: true },
          { name: 'Screen Size', value: visitorInfo.screenSize, inline: true },
          { name: 'Color Depth', value: visitorInfo.colorDepth, inline: true },
          { name: 'Timezone', value: visitorInfo.timezone, inline: true },
          { name: 'Threats', value: threats.length ? threats.map(t => `${t.type}: ${t.details}`).join('\n') : 'None', inline: false }
        ]
      }]
    };

    const webhookResponse = await fetch(webhookURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!webhookResponse.ok) {
      const text = await webhookResponse.text();
      logger.error('Failed to send to Discord', {
        status: webhookResponse.status,
        statusText: webhookResponse.statusText,
        response: text
      });
    } else {
      logger.info('Successfully sent to Discord Webhook');
    }

    res.status(200).send('Visitor info recorded');
  } catch (error) {
    logger.error('Error in /api/visit', { error: error.message, stack: error.stack });
    res.status(500).send('Server error');
  }
});

app.use((req, res, next) => {
  logger.info('Incoming Request', {
    method: req.method,
    path: req.originalUrl,
    ip: getClientIP(req),
    timestamp: new Date().toISOString()
  });
  next();
});

app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack });
  if (err.code === 'EBADCSRFTOKEN') {
    logger.warn('CSRF Attack Detected', { ip: getClientIP(req), path: req.originalUrl });
    res.status(403).send('Invalid CSRF token');
  } else {
    res.status(500).send('Something broke!');
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
