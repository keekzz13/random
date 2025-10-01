// y'all chill this prob a yest
const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello! Your backend is working!');
});

app.post('/api/visit', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  console.log(`User IP: ${ip}`);

  console.log('Payload:', req.body);

  res.status(200).send('IP recorded');
});

app.listen(3000, () => console.log('Server running on port 3000'));
