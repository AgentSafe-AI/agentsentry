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

function runBinary(args) {
  const child = spawn(binPath, args, { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error(`Failed to start subprocess: ${err}`);
  });
  child.on('exit', (code) => {
    process.exit(code || 0);
  });
}

async function main() {
  const pkg = require('../package.json');
  const args = process.argv.slice(2);

  if (args.includes('--version') || args.includes('-v')) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`ToolTrust MCP Server (${pkg.version})\n`);
    console.log('Starts the ToolTrust Scanner as an MCP stdio server.\n');
    console.log('Options:');
    console.log('  -h, --help     Show this help message');
    console.log('  -v, --version  Show version information\n');
    console.log('Supported Security Rules (Catalog):');
    console.log('  AS-001  Tool Poisoning / Prompt Injection (malicious instructions in tool descriptions)');
    console.log('  AS-002  Excessive Permission Surface (executing commands, file writes, network access)');
    console.log('  AS-003  Scope Mismatch (tool name implies read-only but requests write permissions)');
    console.log('  AS-004  Supply Chain CVE (known vulnerabilities in declared package dependencies)');
    console.log('  AS-005  Privilege Escalation (tools that acquire elevated access at runtime)');
    console.log('  AS-006  Arbitrary Code Execution (eval, execute_script, sandbox escape patterns)');
    console.log('  AS-007  Insufficient Tool Data (missing description or input schema)');
    console.log('  AS-010  Secret Handling (tools requesting API keys, tokens, or credentials)');
    console.log('  AS-011  DoS Resilience (missing rate-limit or timeout configuration)\n');
    console.log('Configuration for Claude Desktop:');
    console.log('  {"command": "npx", "args": ["-y", "@agentsafe/tooltrust-mcp"]}');
    process.exit(0);
  }

  if (!fs.existsSync(binPath)) {
    console.error(`Downloading ToolTrust MCP binary for ${sysPlatform}-${sysArch}...`);
    fs.mkdirSync(cacheDir, { recursive: true });
    try {
      await downloadFile(downloadUrl, binPath);
    } catch (e) {
      console.error(`Error downloading binary: ${e.message}`);
      console.error("Failed to download binary. If you are behind a proxy, try setting NODE_TLS_REJECT_UNAUTHORIZED=0 or download the binary manually from GitHub Releases.");
      process.exit(1);
    }
  }
  
  runBinary(args);
}

main();
