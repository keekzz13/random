// Backend server using Express.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch'); 
const app = express();

app.use(cors());

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello! Your backend is working!');
});

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  return forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
}

// API Endpoint to log IP and payload
app.post('/api/visit', async (req, res) => {
  try {
    const ip = getClientIP(req);

    const geoResponse = await fetch(`http://ip-api.com/json/${ip}`);
    const geoData = await geoResponse.json();

    console.log('Visitor Info:', {
      ip,
      country: geoData.country,
      region: geoData.regionName,
      city: geoData.city,
      isp: geoData.isp,
      device: req.body.device,
      ts: req.body.ts,
    });

    const webhookURL = 'https://ptb.discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';
    const payload = {
      content: `**New Visitor Detected!**\n- Device: ${req.body.device}\n- Timestamp: ${req.body.ts}\n- IP: ${ip}\n- Country: ${geoData.country}\n- Region: ${geoData.regionName}\n- City: ${geoData.city}\n- ISP: ${geoData.isp}`,
    };

    const response = await fetch(webhookURL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error('Failed to send to Discord:', response.status, response.statusText, text);
    } else {
      console.log('Successfully sent to Discord Webhook');
    }

    res.status(200).send('IP recorded');
  } catch (error) {
    console.error('Error in /api/visit:', error);
    res.status(500).send('Server error');
  }
});

// Use dynamic port binding for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
