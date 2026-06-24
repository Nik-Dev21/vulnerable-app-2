// TEST FIXTURE — planted lint errors + logic bugs.
const express = require("express");
const { getUserByName } = require("./db"); // Assuming getUserByName is an async function

const app = express();
// FIX: Removed unused variable 'unusedVariable'.

// BUG: == instead of ===, and no input validation
function isAdmin(role) {
  // FIX: Used strict equality (===) and simplified the function logic.
  return role === "admin";
}

// COMMAND INJECTION: raw user input passed to a shell.
app.get("/ping", (req, res) => {
  const { execFile } = require("child_process"); // FIX: Used execFile instead of exec for safer command execution.

  const host = req.query.host;

  if (!host) {
    return res.status(400).send("Host parameter is required."); // FIX: Added input validation for the host.
  }

  // FIX: Passed host as a separate argument to 'execFile' to prevent command injection.
  // Note: For actual ping on Windows, arguments might be different (e.g., ["-n", "1", host])
  // This example assumes a Unix-like `ping` command.
  execFile("ping", ["-c", "1", host], (err, stdout, stderr) => {
    if (err) {
      console.error(`execFile error: ${err}`);
      return res.status(500).send(`Error executing ping: ${stderr}`);
    }
    res.send(stdout);
  });
});

// BUG: missing await — returns a pending Promise, not the user.
app.get("/user", async (req, res) => { // FIX: Made the route handler 'async'.
  const name = req.query.name;

  if (!name) {
    return res.status(400).send("Name parameter is required."); // FIX: Added input validation for the name.
  }

  // FIX: Added input validation for 'name' to ensure it's a safe format, mitigating potential injection risks.
  // Assuming 'name' should be alphanumeric with underscores. Adjust regex as per actual requirements.
  if (!/^[a-zA-Z0-9_]+$/.test(name)) {
    return res.status(400).send("Invalid name format.");
  }

  // FIX: Added 'await' to correctly resolve the Promise returned by getUserByName.
  // FIX: Added basic error handling for the asynchronous operation.
  try {
    const user = await getUserByName(name);
    if (user) {
      res.json(user);
    } else {
      res.status(404).send("User not found.");
    }
  } catch (error) {
    console.error(`Error fetching user: ${error}`);
    res.status(500).send("Error fetching user data.");
  }
});

// lint: missing semicolon, loose equality, dead code after return
function classify(n) {
  if (n === 0) return "zero"; // FIX: Used strict equality (===) and added a semicolon.
  return "nonzero";
  // console.log("unreachable"); // FIX: Removed unreachable code.
}

app.listen(3000, (err) => { // FIX: Added error handling for app.listen to prevent unhandled exceptions.
  if (err) {
    console.error('Failed to start server:', err);
    process.exit(1); // Exit the process if the server fails to start
  }
  console.log("Server listening on port 3000");
});