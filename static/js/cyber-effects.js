// Cyber security visual effects
document.addEventListener('DOMContentLoaded', function() {
    // Matrix-style background particles
    createMatrixParticles();
    
    // Cyber button effects
    initCyberButtons();
    
    // Security scan animation
    initScanAnimation();
});

function createMatrixParticles() {
    const container = document.querySelector('.matrix-bg');
    if (!container) return;
    
    for (let i = 0; i < 50; i++) {
        const particle = document.createElement('div');
        particle.style.position = 'absolute';
        particle.style.width = '2px';
        particle.style.height = '2px';
        particle.style.background = 'var(--cyber-green)';
        particle.style.opacity = Math.random() * 0.3;
        particle.style.left = Math.random() * 100 + '%';
        particle.style.top = Math.random() * 100 + '%';
        particle.style.animation = `float ${5 + Math.random() * 10}s infinite linear`;
        container.appendChild(particle);
    }
}

function initCyberButtons() {
    const buttons = document.querySelectorAll('.btn-cyber');
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.boxShadow = '0 0 20px currentColor';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.boxShadow = '0 0 10px currentColor';
        });
    });
}

function initScanAnimation() {
    const scanElements = document.querySelectorAll('.status-dot');
    scanElements.forEach(dot => {
        setInterval(() => {
            dot.style.animation = 'none';
            setTimeout(() => {
                dot.style.animation = 'pulse 2s infinite';
            }, 10);
        }, 5000);
    });
}

// Add CSS for floating animation
const style = document.createElement('style');
style.textContent = `
    @keyframes float {
        0% { transform: translateY(0) translateX(0); opacity: 0; }
        10% { opacity: 0.3; }
        90% { opacity: 0.1; }
        100% { transform: translateY(-100vh) translateX(20px); opacity: 0; }
    }
`;
document.head.appendChild(style);