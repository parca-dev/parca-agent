function cpu() {
    for (let i = 0; i < 1001; i++) {
        // Do nothing, simulating CPU work
    }
}

function c1() {
    cpu();
}

function b1() {
    c1();
}

function a1() {
    b1();
}

console.log(`PID: ${process.pid}`);

function runLoop() {
    while (true) {
        a1();
    }
}

runLoop();
