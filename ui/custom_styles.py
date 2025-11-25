"""
Custom CSS Styling for Yahoo_Phish Dashboard
Modern, professional design with smooth animations and visual polish
"""

CUSTOM_STYLE = '''
<style>
/* Global Styles - Modern Professional Theme */

:root {
    --primary-color: #00d9ff;
    --success-color: #00ff88;
    --warning-color: #ffaa00;
    --danger-color: #ff3366;
    --dark-bg: #0a0e27;
    --card-bg: #1a1f3a;
    --hover-bg: #252a4a;
}

.card {
    background: var(--card-bg) !important;
    border-radius: 16px !important;
    transition: all 0.3s ease;
}

.card:hover {
    transform: translateY(-4px);
    box-shadow: 0 0 20px rgba(0, 217, 255, 0.3) !important;
}
</style>
'''
