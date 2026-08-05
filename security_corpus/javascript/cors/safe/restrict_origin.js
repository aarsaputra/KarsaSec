const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({ origin: 'https://example.com' }));

app.get('/', (req, res) => {
  res.send('hello');
});
