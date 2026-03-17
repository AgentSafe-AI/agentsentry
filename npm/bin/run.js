#!/usr/bin/env node

const os = require('os');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawn } = require('child_process');

const platformMap = {
  darwin: 'darwin',
  linux: 'linux',
  win32: 'windows',
};

const archMap = {
  x64: 'amd64',
  arm64: 'arm64',
};

const sysPlatform = os.platform();
const sysArch = os.arch();

const goos = platformMap[sysPlatform];
const goarch = archMap[sysArch];

if (!goos || !goarch) {
  console.error(`Unsupported platform/architecture: ${sysPlatform}/${sysArch}`);
  process.exit(1);
}

const suffix = goos === 'windows' ? '.exe' : '';
const binName = `tooltrust-mcp_${goos}_${goarch}${suffix}`;
const downloadUrl = `https://github.com/AgentSafe-AI/tooltrust-scanner/releases/latest/download/${binName}`;

const cacheDir = path.join(os.homedir(), '.tooltrust-mcp', 'bin');
const binPath = path.join(cacheDir, binName);

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return downloadFile(res.headers.location, dest).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download, status code: ${res.statusCode}`));
      }
      
      const file = fs.createWriteStream(dest);
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        fs.chmodSync(dest, 0o755);
        resolve();
      });
      file.on('error', (err) => {
        fs.unlink(dest, () => reject(err));
      });
    }).on('error', (err) => {
      fs.unlink(dest, () => reject(err));
    });
  });
}

function runBinary() {
  const args = process.argv.slice(2);
  const child = spawn(binPath, args, { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error(`Failed to start subprocess: ${err}`);
  });
  child.on('exit', (code) => {
    process.exit(code || 0);
  });
}

async function main() {
  if (!fs.existsSync(binPath)) {
    console.error(`Downloading ToolTrust MCP binary for ${sysPlatform}-${sysArch}...`);
    fs.mkdirSync(cacheDir, { recursive: true });
    try {
      await downloadFile(downloadUrl, binPath);
    } catch (e) {
      console.error(`Error downloading binary: ${e.message}`);
      process.exit(1);
    }
  }
  
  runBinary();
}

main();
