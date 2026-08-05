function renderMessage(req) {
    const userMsg = req.body.message;
    document.getElementById('output').innerHTML = userMsg;
}
