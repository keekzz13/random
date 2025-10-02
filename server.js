// Backend server using Express.js
const express = require('express');
const cors = require('cors');
const app = express();

// Enable CORS
app.use(cors());

// Parse JSON request bodies
app.use(express.json());

// Root Endpoint
app.get('/', (req, res) => {
  res.send('Hello! Your backend is working!');
});

// API Endpoint to log IP and payload
app.post('/api/visit', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  console.log(`User IP: ${ip}`);
  console.log('Payload:', req.body);

  // Send data to Discord webhook
  const webhookURL = 'https://ptb.discord.com/api/webhooks/1423009299826868396/7ezGh2CAQRooHIvE5sXCBGW0AAgFE2Ku8aFqUDe2eqC2BG7quehvy6JBgWqSwfhrROAq';
  const payload = {
    content: `New visitor detected!\n- **Device**: ${req.body.device}\n- **Timestamp**: ${req.body.ts}\n- **IP Address**: ${ip}`,
  };

  fetch(webhookURL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
    .then((response) => {
      if (!response.ok) {
        console.error('Failed to send to Discord. Status:', response.status, 'Status Text:', response.statusText);
        return response.text().then((text) => console.error('Response Body:', text));
      }
      console.log('Successfully sent to Discord Webhook');
    })
    .catch((error) => {
      console.error('Error sending request to Discord webhook:', error);
    });

  res.status(200).send('IP recorded');
});

// Use dynamic port binding for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

