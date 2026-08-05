const vm = require('vm');

function runInContextRegression(req) {
    vm.runInThisContext(req.body.script);
}
