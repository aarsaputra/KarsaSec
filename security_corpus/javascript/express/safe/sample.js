const express = require('express');
const child_process = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        return res.status(400).send('Invalid host');
    }
    child_process.execFile('ping', ['-c', '1', host], (err, stdout) => {
        res.send(stdout);
    });
});
