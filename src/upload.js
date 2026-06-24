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

  // LOGIC_ERROR & UNHANDLED_EXCEPTION: Use asynchronous fs.readFile with error handling
  fs.readFile(resolvedPath, (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        return res.status(404).send("File not found.");
      }
      console.error(`Error reading file ${resolvedPath}:`, err);
      return res.status(500).send("Error reading file.");
    }
    res.send(data);
  });
});

// ARBITRARY FILE WRITE: writes user content to a user-chosen path.
router.post("/save", (req, res) => {
  const { name, content } = req.body;

  if (!name || !content) {
    return res.status(400).send("Filename and content are required.");
  }

  const filePath = path.join(uploadsDir, name);
  const resolvedPath = path.resolve(filePath);

  // Security check: Ensure the resolved path is strictly within the uploads directory
  if (!resolvedPath.startsWith(uploadsDir + path.sep) && resolvedPath !== uploadsDir) {
    console.warn(`Attempted path traversal for write: ${name}`);
    return res.status(403).send("Access denied.");
  }

  // UNHANDLED_EXCEPTION & LOGIC_ERROR: Use asynchronous fs.writeFile with error handling
  fs.writeFile(resolvedPath, content, (err) => {
    if (err) {
      console.error(`Error writing file ${resolvedPath}:`, err);
      return res.status(500).send("Error writing file.");
    }
    res.send("saved");
  });
});

// HARDCODED CREDENTIAL: fake storage password checked into source.
const STORAGE_PASSWORD = "changeme-please-1234";

module.exports = { router, STORAGE_PASSWORD };
