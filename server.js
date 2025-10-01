const express = require('express');
const app = express();

app.use(express.json());

app.post('/api/visit', (req, res) => {
  // Extract the user's IP address
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  console.log(`User IP: ${ip}`);

  // Log the payload sent from the frontend
  console.log('Payload:', req.body);

  res.status(200).send('IP recorded');
});

app.listen(3000, () => console.log('Server running on port 3000')); 