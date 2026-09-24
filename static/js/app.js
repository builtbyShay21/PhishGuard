document.addEventListener("DOMContentLoaded", () => {
    const gaugeContainer = document.querySelector('.gauge-container');
    if (gaugeContainer) {
        const score = parseInt(gaugeContainer.getAttribute('data-score'), 10);
        const level = gaugeContainer.getAttribute('data-level').toLowerCase();
        
        const gaugeFill = document.querySelector('.gauge-fill');
        
        // Colors corresponding to risk levels
        const colors = {
            'low': '#22C55E',
            'guarded': '#3b82f6',
            'moderate': '#F59E0B',
            'high': '#f97316',
            'critical': '#EF4444'
        };
        
        if (colors[level]) {
            gaugeFill.style.stroke = colors[level];
        }

        // Calculate offset (125.6 is max dasharray for this arc)
        // offset = 125.6 - (125.6 * score / 100)
        const maxDash = 125.6;
        // Check for reduced motion
        const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        
        const targetOffset = maxDash - (maxDash * score / 100);
        
        if (prefersReducedMotion) {
            gaugeFill.style.strokeDashoffset = targetOffset;
        } else {
            // Animate
            setTimeout(() => {
                gaugeFill.style.strokeDashoffset = targetOffset;
            }, 100);
        }
    }
});
