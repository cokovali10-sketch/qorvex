#!/usr/bin/env node
// E2E test script for Qorvex pipeline
// Usage: node test/e2e/pipeline.test.js <project_path>
//        npx wait-on npm start -- test:e2e

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const fetch = require('node-fetch');

const PROJECT_PATH =
    process.argv[2] ||
    path.join(__dirname, '..', 'test-data', 'sample');

const API_BASE = 'http://localhost:8422/api/v1';

// Helper: wait for condition
function waitFor(conditionFn, interval = 1000, maxAttempts = 30) {
    return new Promise((resolve, reject) => {
        let attempts = 0;
        const check = () => {
            attempts++;
            if (attempts > maxAttempts) {
                reject(new Error('Max attempts exceeded'));
                return;
            }
            try {
                const result = conditionFn();
                if (result) {
                    resolve(result);
                } else {
                    setTimeout(check, interval);
                }
            } catch (e) {
                setTimeout(check, interval);
            }
        };
        check();
    });
}

// Helper: make API request with auth
async function apiRequest(method, endpoint, body = null, token = null) {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    const url = `${API_BASE}${endpoint}`;
    const options: RequestInit = { method, headers };

    if (body !== null) {
        options.body = JSON.stringify(body);
    }

    const res = await fetch(url, options);
    const data = await res.json();
    return { res, data, status: res.status };
}

// Main E2E test
async function runE2E() {
    console.log('=== Qorvex E2E Pipeline Test ===\n');

    // Step 1: Check if server is already running
    console.log('1. Checking server status...');
    let serverRunning = false;
    let token = null;

    try {
        const { data } = await apiRequest('GET', '/health');
        serverRunning = true;
        console.log('   Server is already running\n');

        // Try to get auth token if not already logged in
        if (!token) {
            // Try login with default credentials or skip if already authenticated
            try {
                const { data: loginData } = await apiRequest(
                    'POST',
                    '/auth/login',
                    {
                        username: 'admin',
                        password: 'admin123',
                    }
                );
                token = loginData.access_token;
                console.log('   Logged in as admin\n');
            } catch {
                // Maybe already authenticated
                const { res: res2 } = await apiRequest('GET', '/auth/me');
                if (res2.status === 200) {
                    token = res2.data.access_token;
                    console.log('   Already authenticated\n');
                }
            }
        }
    } catch (e) {
        console.log('   Server not running, will start it\n');
    }

    // Step 2: Start the Qorvex server if not running
    let serverProc;
    if (!serverRunning) {
        console.log('2. Starting Qorvex server...');
        try {
            serverProc = execSync(
                'cd D:\\PortfolioProjects\\Qorvex && go run ./cmd/qorvex',
                { timeout: 15000, stdio: 'pipe' }
            );
            // Wait for server to be ready
            await waitFor(async () => {
                try {
                    const { data } = await apiRequest('GET', '/health');
                    return data;
                } catch {
                    return false;
                }
            }, 500, 20);
            console.log('   Server started\n');
        } catch (e) {
            console.error('   Failed to start server:', e.message);
            process.exit(1);
        }
    }

    // Step 3: Create a project
    console.log('3. Creating test project...');
    const projectName = 'e2e-test-' + Date.now();

    let project;
    try {
        const { data } = await apiRequest(
            'POST',
            '/projects',
            { name: projectName, path: PROJECT_PATH },
            token
        );
        project = data;
        console.log(`   Project created: ${project.id}\n`);
    } catch (e) {
        console.error('   Failed to create project:', e.message);
        process.exit(1);
    }

    // Step 4: Start a check
    console.log('4. Starting check...');
    let check;
    try {
        const { data } = await apiRequest(
            'POST',
            `/projects/${project.id}/checks`,
            {},
            token
        );
        check = data;
        console.log(`   Check started: ${check.id}, status: ${check.status}\n`);
    } catch (e) {
        console.error('   Failed to start check:', e.message);
        process.exit(1);
    }

    // Step 5: Poll for completion with timeout
    console.log('5. Waiting for check completion...');
    let checkStatus;
    let maxAttempts = 120; // 2 minutes at 1s intervals
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const { data: checkData } = await apiRequest(
                'GET',
                `/checks/${check.id}`,
                null,
                token
            );
            checkStatus = checkData;

            if (
                checkStatus.status === 'completed' ||
                checkStatus.status === 'failed'
            ) {
                break;
            }
        } catch (e) {
            // ignore connection errors during polling
        }

        if (i % 10 === 0) {
            console.log(`   Polling... (${i}/${maxAttempts})`);
        }
        await new Promise((r) => setTimeout(r, 1000));
    }

    if (
        !checkStatus ||
        !(checkStatus.status === 'completed' || checkStatus.status === 'failed')
    ) {
        console.error(
            '   Check did not complete within timeout, status:',
            checkStatus?.status
        );
        process.exit(1);
    }

    console.log(`   Check completed: ${checkStatus.status}\n`);

    // Step 6: Verify results
    console.log('6. Verifying results...');
    try {
        console.log(`   Status: ${checkStatus.status}`);
        console.log(`   Score: ${checkStatus.result?.score}`);
        console.log(`   Risk level: ${checkStatus.result?.risk_level}`);
        console.log(`   Findings: ${checkStatus.result?.findings?.length || 0}`);
        console.log(
            `   Summary: ${checkStatus.result?.summary.substring(
                0,
                100
            )}...`
        );

        // Verify audit log
        const { data: auditData } = await apiRequest(
            'GET',
            '/audit/verify',
            null,
            token
        );
        console.log(`   Audit valid: ${auditData.valid}`);

        // Fail-closed verification: if risk_level is critical, check should be failed
        if (
            checkStatus.result?.risk_level === 'critical' &&
            checkStatus.status !== 'failed'
        ) {
            console.error(
                '   FAIL: Critical risk level but check status is not failed!'
            );
            console.error(
                '   This violates the fail-closed security policy.'
            );
            process.exit(1);
        }

        // Verify there are some findings (sample project should have some)
        const findingCount = checkStatus.result?.findings?.length || 0;
        if (findingCount === 0) {
            console.warn(
                '   Warning: No findings detected - sample project may have no issues'
            );
        }

        console.log('\n=== E2E Test PASSED ===\n');
    } catch (e) {
        console.error('   Verification failed:', e.message);
        process.exit(1);
    }
}

// Step 7: Shutdown server on exit
process.on('exit', () => {
    try {
        if (serverProc) {
            execSync('taskkill /F /IM qorvex.exe 2>nul');
        }
    } catch {}
});

runE2E().catch((e) => {
    console.error('E2E test failed:', e.message);
    process.exit(1);
});

console.log('=== E2E Test Complete ===');