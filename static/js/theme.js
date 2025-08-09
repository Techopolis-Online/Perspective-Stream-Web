// Theme switcher for WCAG and dark mode support
(function() {
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }
    // Detect system preference
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(prefersDark ? 'dark' : 'light');
    // Optional: add toggle button logic here
})();
