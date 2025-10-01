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

  res.status(200).send('IP recorded');
});

// Use dynamic port binding for Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
