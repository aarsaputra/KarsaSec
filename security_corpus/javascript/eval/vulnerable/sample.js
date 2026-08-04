function executeUserCode(userInput) {
    // Vulnerable eval call
    return eval(userInput);
}
