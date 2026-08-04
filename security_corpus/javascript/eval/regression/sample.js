const vm = require('vm');

function runInContextRegression(codeStr) {
    vm.runInThisContext(codeStr);
}
