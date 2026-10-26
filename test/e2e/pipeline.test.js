#!/usr/bin/env node
// E2E test script for Qorvex pipeline
// Usage: node test/e2e.js <project_path>

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PROJECT_PATH = process.argv[2] || path.join(__dirname, '..', 'test-data', 'sample');

if (!fs.existsSync(PROJECT_PATH)) {
  console.error(`Project path not found: ${PROJECT_PATH}`);
  process.exit(1);
}

console.log('=== Qorvex E2E Pipeline Test ===\n');

// Step 1: Start the Qorvex server
console.log('1. Starting Qorvex server...');
try {
  const serverProc = execSync('cd D:\\PortfolioProjects\\Qorvex && go run ./cmd/qorvex', {
    timeout: 10000,
    stdio: 'pipe'
  });
  console.log('   Server started\n');
} catch (e) {
  console.error('   Failed to start server:', e.message);
  process.exit(1);
}

// Step 2: Create a project
console.log('2. Creating test project...');
try {
  const projectName = 'e2e-test-' + Date.now();
  const result = execSync(
    `curl -s -X POST http://localhost:8422/api/v1/projects \
      -H "Content-Type: application/json" \
      -d '{"name":"${projectName}","path":"${PROJECT_PATH}"}'`,
    { timeout: 5000, encoding: 'utf-8' }
  );
  const project = JSON.parse(result);
  console.log(`   Project created: ${project.id}\n`);
} catch (e) {
  console.error('   Failed to create project:', e.message);
  process.exit(1);
}

// Step 3: Start a check
console.log('3. Starting check...');
try {
  const checkResult = execSync(
    `curl -s -X POST http://localhost:8422/api/v1/projects/${project.id}/checks`,
    { timeout: 5000, encoding: 'utf-8' }
  );
  const check = JSON.parse(checkResult);
  console.log(`   Check started: ${check.id}, status: ${check.status}\n`);
} catch (e) {
  console.error('   Failed to start check:', e.message);
  process.exit(1);
}

// Step 4: Poll for completion
console.log('4. Waiting for check completion...');
let checkStatus;
let maxAttempts = 60;
for (let i = 0; i < maxAttempts; i++) {
  try {
    const checkResp = execSync(
      `curl -s http://localhost:8422/api/v1/checks/${check.id}`,
      { timeout: 3000, encoding: 'utf-8' }
    );
    checkStatus = JSON.parse(checkResp.status);
    if (checkStatus.status === 'completed' || checkStatus.status === 'failed') {
      break;
    }
  } catch (e) {
    // ignore
  }
  require('timers').setTimeout(1000);
}

// Step 5: Verify results
console.log('5. Verifying results...');
try {
  console.log(`   Status: ${checkStatus.status}`);
  
  if (checkStatus.result) {
    console.log(`   Score: ${checkStatus.result.score}`);
    console.log(`   Risk level: ${checkStatus.result.risk_level}`);
    console.log(`   Findings: ${checkStatus.result.findings.length}`);
    console.log(`   Summary: ${checkStatus.result.summary.substring(0, 100)}...`);
  }
  
  // Verify audit log
  const auditResp = execSync(
    `curl -s http://localhost:8422/api/v1/audit/verify`,
    { timeout: 3000, encoding: 'utf-8' }
  );
  const audit = JSON.parse(auditResp);
  console.log(`   Audit valid: ${audit.valid}`);
  
  console.log('\n=== E2E Test PASSED ===\n');
} catch (e) {
  console.error('   Verification failed:', e.message);
  process.exit(1);
}

// Step 6: Shutdown server
process.on('exit', () => {
  try {
    execSync('taskkill /F /IM qorvex.exe 2>nul');
  } catch {}
});

console.log('=== E2E Test Complete ===');