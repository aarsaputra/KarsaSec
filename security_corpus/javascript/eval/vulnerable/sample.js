function executeUserCode(req, res) {
    // Vulnerable eval call from untrusted request body
    return eval(req.body.code);
}
