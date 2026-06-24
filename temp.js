/**
 * Temporary Vulnerability Demo File
 * 
 * This file contains examples of common security vulnerabilities and their secure alternatives.
 */

const crypto = require('crypto');
const { exec } = require('child_process');

// ==========================================
// 1. WEAK HASHING ALGORITHM
// ==========================================
// ❌ VULNERABLE: Using SHA-1 or MD5 for sensitive hashing (like passwords).
// Risk: These algorithms are cryptographically broken and prone to collision attacks.
function hashPasswordVulnerable(password) {
    return crypto.createHash('sha1').update(password).digest('hex');
}

//  SECURE REMEDIATION:
// Use a secure, slow key-derivation function (e.g., bcrypt, PBKDF2, or Argon2).
// const bcrypt = require('bcrypt');
// async function hashPasswordSecure(password) {
//     return await bcrypt.hash(password, 12);
// }


// ==========================================
// 2. REMOTE OS COMMAND INJECTION
// ==========================================
// ❌ VULNERABLE: Direct execution of user input in a shell command.
// Risk: Attackers can append command separators (e.g., ;, &&, |) to execute arbitrary commands.
function systemPingVulnerable(target) {
    exec(`ping -c 1 ${target}`, (err, stdout, stderr) => {
        if (err) {
            console.error(err);
            return;
        }
        console.log(stdout);
    });
}

//  SECURE REMEDIATION:
// Use execFile or spawn to pass arguments safely as an array, avoiding the shell.
// const { execFile } = require('child_process');
// function systemPingSecure(target) {
//     if (!/^[a-zA-Z0-9.-]+$/.test(target)) {
//         throw new Error("Invalid target format");
//     }
//     execFile('ping', ['-c', '1', target], (err, stdout, stderr) => {
//         console.log(stdout);
//     });
// }
