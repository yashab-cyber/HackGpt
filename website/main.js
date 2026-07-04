// HackGPT Landing Page JS logic

document.addEventListener('DOMContentLoaded', () => {
    // 1. Mobile navigation menu toggle
    const navToggle = document.getElementById('navToggle');
    const navMenu = document.getElementById('navMenu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            const icon = navToggle.querySelector('i');
            if (icon.classList.contains('fa-bars')) {
                icon.classList.replace('fa-bars', 'fa-xmark');
            } else {
                icon.classList.replace('fa-xmark', 'fa-bars');
            }
        });
    }

    // Close menu when clicking links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', () => {
            if (navMenu) navMenu.classList.remove('active');
            const icon = navToggle ? navToggle.querySelector('i') : null;
            if (icon) icon.classList.replace('fa-xmark', 'fa-bars');
        });
    });

    // 2. Interactive Terminal Simulator
    const terminalInput = document.getElementById('terminalInput');
    const interactiveTerminal = document.getElementById('interactiveTerminal');

    if (terminalInput && interactiveTerminal) {
        terminalInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const cmdText = terminalInput.value.trim();
                terminalInput.value = '';
                
                if (cmdText) {
                    processCommand(cmdText);
                }
            }
        });
    }

    function writeLine(text, cssClass = '') {
        const line = document.createElement('div');
        line.className = 'line' + (cssClass ? ' ' + cssClass : '');
        line.innerHTML = text;
        
        // Insert before the input line
        const inputLine = interactiveTerminal.querySelector('.terminal-input-line');
        interactiveTerminal.insertBefore(line, inputLine);
        
        // Auto scroll to bottom
        interactiveTerminal.scrollTop = interactiveTerminal.scrollHeight;
    }

    function processCommand(cmd) {
        // Echo command
        writeLine(`<span class="t-cyan">guest@hackgpt:~$</span> ${cmd}`);
        
        const lowerCmd = cmd.toLowerCase();
        
        if (lowerCmd === 'clear') {
            const lines = interactiveTerminal.querySelectorAll('.line');
            lines.forEach(l => l.remove());
            return;
        }
        
        if (lowerCmd === 'help') {
            writeLine('Available commands:');
            writeLine('  <span class="t-cyan">help</span>             - Show this help output');
            writeLine('  <span class="t-cyan">about</span>            - Tell me about HackGPT');
            writeLine('  <span class="t-cyan">run</span>              - Simulate a quick vulnerability assessment');
            writeLine('  <span class="t-cyan">compliance</span>       - View compliance mapping report');
            writeLine('  <span class="t-cyan">clear</span>            - Clear the terminal screen');
            return;
        }
        
        if (lowerCmd === 'about') {
            writeLine('<strong>HackGPT Enterprise v2026.07.beta.4</strong>');
            writeLine('An advanced, AI-powered penetration testing platform. It uses agentic workflows to orchestrate standard security tools under a structured six-phase framework, combined with machine learning anomaly detectors.');
            writeLine('Developed by Yashab Alam.');
            return;
        }
        
        if (lowerCmd === 'run') {
            writeLine('🚀 Initiating quick pentest simulation on dummy-target.com...', 't-blue');
            
            setTimeout(() => {
                writeLine('[+] Phase 1: Passive Reconnaissance completed. Found HTTP banner: Apache 2.4.41.', 't-green');
            }, 500);
            
            setTimeout(() => {
                writeLine('[+] Phase 2: Active Scanning completed. Exposed .git directory detected!', 't-yellow');
            }, 1000);
            
            setTimeout(() => {
                writeLine('[!] Phase 3: Vulnerability Assessment completed.', 't-blue');
                writeLine('    - Critical: SQL Injection on login query verified.', 't-red');
            }, 1500);
            
            setTimeout(() => {
                writeLine('[+] Phase 4: Exploitation verified. Session database dump completed.', 't-green');
                writeLine('[+] Session Completed successfully. PDF Report generated.', 't-green');
            }, 2000);
            
            return;
        }
        
        if (lowerCmd === 'compliance') {
            writeLine('Compliance Standards Mapping:');
            writeLine('  - OWASP Top 10  : <span class="t-green">PASS</span> (A01:2021, A03:2021, A05:2021)');
            writeLine('  - PCI-DSS v4.0  : <span class="t-red">FAIL</span> (Req 6.3.1: Outdated Apache Server version)');
            writeLine('  - NIST SP 800-53: <span class="t-green">PASS</span> (SI-10, SI-11 controls mapping)');
            return;
        }
        
        // Default unknown command
        writeLine(`bash: command not found: ${cmd}. Type <span class="t-cyan">help</span> to view available sandbox commands.`, 't-red');
    }
});
