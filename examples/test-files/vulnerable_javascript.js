// Sample JavaScript code with security vulnerabilities for testing Semgrep

// XSS vulnerability
function displayUserInput(input) {
    // Vulnerable: Direct DOM manipulation without sanitization
    document.getElementById('output').innerHTML = input;
}

// SQL Injection in Node.js
function getUserData(userId) {
    const mysql = require('mysql');
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password123', // Hardcoded password
        database: 'users'
    });
    
    // Vulnerable: String concatenation in SQL query
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, function(error, results) {
        console.log(results);
    });
}

// Command Injection
function executeCommand(userInput) {
    const { exec } = require('child_process');
    // Vulnerable: User input directly in exec
    exec(`ls ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// Weak random number generation
function generateToken() {
    // Vulnerable: Using Math.random() for security token
    return Math.random().toString(36).substring(2, 15);
}

// Prototype pollution
function merge(target, source) {
    for (let key in source) {
        // Vulnerable: No prototype pollution protection
        target[key] = source[key];
    }
    return target;
}

// Hardcoded API keys
const API_SECRET = "abc123secretkey";
const JWT_SECRET = "mysecretjwtkey";

// Insecure HTTP cookies
function setCookie(res, sessionId) {
    // Vulnerable: No secure flags
    res.cookie('sessionId', sessionId, {
        httpOnly: false,
        secure: false
    });
}

// Path traversal
function readFile(filename) {
    const fs = require('fs');
    // Vulnerable: No path validation
    return fs.readFileSync(filename, 'utf8');
}

// Regex DoS (ReDoS)
function validateEmail(email) {
    // Vulnerable: Catastrophic backtracking
    const regex = /^([a-zA-Z0-9_\.-]+)*@([a-zA-Z0-9_\.-]+)*\.([a-zA-Z]{2,5})$/;
    return regex.test(email);
}