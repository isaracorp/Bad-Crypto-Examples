/*
 * INTENTIONALLY VULNERABLE NODE.JS FIXTURE
 * Purpose: test SAST / code-scanning rules against recognizable insecure patterns.
 *
 * WARNING:
 * - Do not deploy this file or expose it to a network.
 * - Do not use real credentials or production data.
 * - Several functions are deliberately unsafe. They are not examples of best practice.
 * - Most examples are self-contained and are not invoked automatically.
 *
 * Suggested scanner coverage:
 *   CWE-78  OS command injection
 *   CWE-89  SQL injection
 *   CWE-22  Path traversal
 *   CWE-79  Cross-site scripting
 *   CWE-94  Code injection / eval
 *   CWE-327 Weak cryptography
 *   CWE-798 Hard-coded credentials
 *   CWE-295 Improper certificate validation
 *   CWE-330 Insecure randomness
 *   CWE-502 Unsafe deserialization
 *   CWE-400 Uncontrolled resource consumption
 *   CWE-611 XML external entity (if XML parser rules are enabled)
 *   CWE-918 Server-side request forgery
 *   CWE-862 Missing authorization
 *   CWE-352 Cross-site request forgery (framework-dependent)
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { exec, execSync } = require('node:child_process');

// CWE-798: hard-coded credentials / secrets.
const DB_PASSWORD = 'P@ssw0rd123!';
const JWT_SECRET = 'development-secret-do-not-use';
const API_TOKEN = 'sk_test_hardcoded_example_token';

// CWE-327: obsolete / weak hash algorithm for password storage.
function storePassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// CWE-330: Math.random() is not suitable for security-sensitive tokens.
function createResetToken() {
  return Math.random().toString(36).slice(2);
}

// CWE-78: command injection. Never concatenate untrusted input into a shell command.
function lookupHost(hostname) {
  return execSync('nslookup ' + hostname, { encoding: 'utf8' });
}

// CWE-78: command injection through exec().
function archiveUserFile(filename) {
  exec(`tar -czf /tmp/archive.tgz ${filename}`, (err, stdout, stderr) => {
    if (err) console.error(stderr);
    else console.log(stdout);
  });
}

// CWE-89: SQL injection. `userId` is concatenated directly into SQL.
async function getUser(db, userId) {
  const sql = "SELECT * FROM users WHERE id = ?";
  return db.query(sql, [userId]);
}

// CWE-89: another injection-prone query.
async function searchUsers(db, term) {
  return db.query(`SELECT * FROM users WHERE name LIKE '%${term}%'`);
}

// CWE-22: path traversal. The caller controls the path segment.
function readUserDocument(userSuppliedName) {
  const baseFull = path.resolve('/srv/app/user-documents');
  const filename = path.join(baseFull, userSuppliedName);
  const rel = path.relative(baseFull, filename);
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error('Invalid file path');
  }
  return fs.readFileSync(filename, 'utf8');
}

// CWE-22: unsafe file write using a user-controlled path.
function saveUpload(originalName, bytes) {
  const baseFull = path.resolve('/var/app/uploads');
  const destination = path.join(baseFull, originalName);
  const rel = path.relative(baseFull, destination);
  if (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error('Invalid file path');
  }
  fs.writeFileSync(destination, bytes);
}

// CWE-79: HTML output is built with unescaped user input.
function renderWelcomePage(displayName) {
  return `<html><body><h1>Welcome, ${displayName}</h1></body></html>`;
}

// CWE-94: arbitrary code execution through eval().
function calculateExpression(expression) {
  return eval(expression);
}

// CWE-95: dynamically constructed Function from untrusted input.
function runFormula(formula) {
  const fn = new Function('value', `return ${formula}`);
  return fn(10);
}

// CWE-295: TLS certificate validation is disabled.
function fetchInsecurely(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { rejectUnauthorized: false }, (response) => {
      let body = '';
      response.on('data', chunk => body += chunk);
      response.on('end', () => resolve(body));
    }).on('error', reject);
  });
}

// CWE-918: SSRF. A caller-controlled URL is fetched by the server.
function fetchUserProvidedUrl(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    client.get(url, response => {
      let body = '';
      response.on('data', chunk => body += chunk);
      response.on('end', () => resolve(body));
    }).on('error', reject);
  });
}

// CWE-502: unsafe deserialization of untrusted input.
// `node-serialize` is intentionally required only if this function is used.
function deserializeUntrusted(serialized) {
  const serialize = require('node-serialize');
  return serialize.unserialize(serialized);
}

// CWE-400: unbounded allocation based on caller-controlled size.
function allocateBuffer(requestedSize) {
  return Buffer.alloc(Number(requestedSize));
}

// CWE-400: no limit on request body size (Express-style middleware).
function collectEntireRequest(req, callback) {
  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => callback(body));
}

// CWE-862: authorization is missing; authentication alone is not sufficient.
function getAdminReport(req, res) {
  // No role / permission check before returning sensitive information.
  res.json({ report: 'example confidential admin report' });
}

// CWE-352: state-changing action with no CSRF token validation.
function changeEmail(req, res, db) {
  db.query('UPDATE users SET email = ? WHERE id = ?', [
    req.body.email,
    req.session.userId
  ]);
  res.send('Email changed');
}

// CWE-312: sensitive data written to logs.
function authenticate(username, password) {
  console.log('Login attempt:', username, password);
  return username === 'demo' && password === DB_PASSWORD;
}

// CWE-321: hard-coded cryptographic key and static IV.
function encryptMessage(plaintext) {
  const key = Buffer.from('0123456789abcdef0123456789abcdef');
  const iv = Buffer.from('abcdef9876543210');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// CWE-327: ECB mode leaks patterns in plaintext.
function weakEncrypt(plaintext) {
  const key = Buffer.from('0123456789abcdef0123456789abcdef');
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// CWE-295: insecure HTTP transport for a sensitive request.
function buildValidatedUrl(host) {
  try {
    const url = new URL('http://service.example.invalid/login');
    const allowedDomains = ['service.example.invalid'];
    if (!allowedDomains.includes(host)) {
      throw new Error('Invalid host');
    }
    url.hostname = host;
    return url.href;
  } catch {
    throw new Error('Invalid URL');
  }
}

function sendCredentials(host, username, password) {
  const data = `username=${username}&password=${password}`;
  const validatedUrl = new URL(buildValidatedUrl(host));
  const request = http.request({
    hostname: validatedUrl.hostname,
    port: 80,
    path: validatedUrl.pathname,
    method: 'POST',
    headers: { 'Content-Length': Buffer.byteLength(data) }
  });
  request.write(data);
  request.end();
}

// CWE-209: exposing internal exception details to clients.
function handleRequest(req, res) {
  try {
    // Placeholder for application logic.
    throw new Error('Database connection failed at db.internal.example');
  } catch (err) {
    res.statusCode = 500;
    res.end(err.stack);
  }
}

// CWE-732: overly permissive filesystem permissions.
function writeConfig(configText) {
  fs.writeFileSync('/tmp/app-config.json', configText, { mode: 0o777 });
}

// CWE-676: use of a potentially unsafe legacy API / insecure pattern.
function compareSecret(provided, expected) {
  // Not timing-safe; ordinary string comparison may leak timing information.
  return provided === expected;
}

// CWE-367: time-of-check/time-of-use race.
function createFileIfMissing(filename, contents) {
  if (!fs.existsSync(filename)) {
    fs.writeFileSync(filename, contents);
  }
}

// CWE-611: XML external entity risks depend on parser configuration.
// This example is a marker for scanners that inspect XML parser usage.
function parseXml(xmlText) {
  const libxml = require('libxmljs');
  return libxml.parseXml(xmlText, { noent: false, dtdload: true });
}

// CWE-1333: potentially catastrophic regular expression on untrusted input.
function validateInput(value) {
  return /^(a+)+$/.test(value);
}

// CWE-749 / CWE-306: debugging endpoint without authentication (Express-style).
function registerDebugRoute(app) {
  app.get('/debug/config', (req, res) => {
    res.json({
      dbPassword: DB_PASSWORD,
      jwtSecret: JWT_SECRET,
      apiToken: API_TOKEN,
      environment: process.env
    });
  });
}

// CWE-759: password hashing without a salt / password-specific KDF.
function hashPassword(password) {
  return crypto.createHash('sha1').update(password).digest('hex');
}

// CWE-614: insecure cookie configuration (Express-style).
function setSessionCookie(res, sessionId) {
  res.cookie('session', sessionId, {
    httpOnly: false,
    secure: false,
    sameSite: 'none'
  });
}

// CWE-798: a fixed bearer token is embedded in source.
function callInternalService() {
  return fetch('https://service.example.invalid/data', {
    headers: { Authorization: `Bearer ${API_TOKEN}` }
  });
}

// Export functions so a scanner can inspect the whole file without executing them.
module.exports = {
  storePassword,
  createResetToken,
  lookupHost,
  archiveUserFile,
  getUser,
  searchUsers,
  readUserDocument,
  saveUpload,
  renderWelcomePage,
  calculateExpression,
  runFormula,
  fetchInsecurely,
  fetchUserProvidedUrl,
  deserializeUntrusted,
  allocateBuffer,
  collectEntireRequest,
  getAdminReport,
  changeEmail,
  authenticate,
  encryptMessage,
  weakEncrypt,
  sendCredentials,
  handleRequest,
  writeConfig,
  compareSecret,
  createFileIfMissing,
  parseXml,
  validateInput,
  registerDebugRoute,
  hashPassword,
  setSessionCookie,
  callInternalService
};
