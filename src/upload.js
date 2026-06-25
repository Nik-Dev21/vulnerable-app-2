const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

// Define the base directory for uploads and ensure it exists
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// PATH TRAVERSAL: user-controlled filename joined onto a base dir with no
// sanitization — "../../etc/passwd" escapes the uploads folder.
router.get("/download", (req, res) => {
  const file = req.query.file;

  if (!file) {
    return res.status(400).send("Filename is required.");
  }

  const filePath = path.join(uploadsDir, file);
  const resolvedPath = path.resolve(filePath);

  // Security check: Ensure the resolved path is strictly within the uploads directory
  if (!resolvedPath.startsWith(uploadsDir + path.sep) && resolvedPath !== uploadsDir) {
    console.warn(`Attempted path traversal for download: ${file}`);
    return res.status(403).send("Access denied.");
  }

  // SECURITY_MISCONFIGURATION fix: Set Content-Disposition to attachment to prevent browser execution of uploaded files (e.g., XSS).
  res.setHeader('Content-Disposition', 'attachment; filename="' + path.basename(resolvedPath) + '"');

  // RESOURCE_LEAK fix: Use fs.createReadStream to stream the file, preventing excessive memory consumption for large files.
  const readStream = fs.createReadStream(resolvedPath);

  readStream.on('open', () => {
    readStream.pipe(res);
  });

  readStream.on('error', (err) => {
    if (err.code === 'ENOENT') {
      return res.status(404).send("File not found.");
    }
    console.error(`Error reading file ${resolvedPath}:`, err);
    return res.status(500).send("Error reading file.");
  });

  // Handle client aborts to prevent resource leaks if the client disconnects early
  req.on('aborted', () => {
    readStream.destroy();
  });
});

// ARBITRARY FILE WRITE: writes user content to a user-chosen path.
router.post("/save", (req, res) => {
  const { name, content } = req.body;

  if (!name || !content) {
    return res.status(400).send("Filename and content are required.");
  }

  // SECURITY_MISCONFIGURATION fix: Sanitize filename to prevent dangerous characters and ensure a safe name.
  let sanitizedName = path.basename(name); // Remove any path components
  // Remove any characters that are not alphanumeric, underscore, dot, or hyphen
  sanitizedName = sanitizedName.replace(/[^a-zA-Z0-9_.-]/g, '');
  // Ensure it's not empty after sanitization
  if (sanitizedName.length === 0) {
    sanitizedName = 'untitled';
  }
  // Prevent hidden files (e.g., .htaccess) if not explicitly intended
  if (sanitizedName.startsWith('.')) {
    sanitizedName = '_' + sanitizedName.substring(1);
  }

  const filePath = path.join(uploadsDir, sanitizedName);
  const resolvedPath = path.resolve(filePath);

  // Security check: Ensure the resolved path is strictly within the uploads directory
  if (!resolvedPath.startsWith(uploadsDir + path.sep) && resolvedPath !== uploadsDir) {
    console.warn(`Attempted path traversal for write: ${sanitizedName}`);
    return res.status(403).send("Access denied.");
  }

  // RESOURCE_LEAK fix: Use fs.createWriteStream to stream the content, preventing excessive memory consumption for large content.
  const writeStream = fs.createWriteStream(resolvedPath);

  writeStream.on('error', (err) => {
    console.error(`Error writing file ${resolvedPath}:`, err);
    // Clean up stream if an error occurs before it finishes
    writeStream.destroy();
    return res.status(500).send("Error writing file.");
  });

  writeStream.on('finish', () => {
    res.send("saved");
  });

  // RESOURCE_LEAK fix: Handle client aborts during POST request to prevent resource leaks.
  req.on('aborted', () => {
    console.warn(`Client aborted POST /save for file: ${sanitizedName}`);
    writeStream.destroy(); // Destroy the stream to release the file handle
  });

  // Write the content to the stream. Note: If req.body.content is already a large string/buffer,
  // the memory issue might still exist in parsing the request body itself. This fix addresses the write operation.
  writeStream.write(content);
  writeStream.end();
});

// HARDCODED CREDENTIAL fix: Read STORAGE_PASSWORD from environment variables.
const STORAGE_PASSWORD = process.env.STORAGE_PASSWORD || "default-secret-for-dev"; // In production, ensure this environment variable is set.

module.exports = { router, STORAGE_PASSWORD };