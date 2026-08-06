const express = require('express');
const child_process = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    child_process.exec('ping -c 1 ' + host, (err, stdout) => {
        res.send(stdout);
    });
});
