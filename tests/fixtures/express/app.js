const express = require('express');
const app = express();

app.post('/api/login', (req, res) => {
    res.json({ status: 'ok' });
});

app.listen(3000);
