(() => {
    const key = 'evidence-vault-theme';
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    let preference;
    try { preference = localStorage.getItem(key); } catch (_) { /* System theme works without storage. */ }
    if (!['light', 'dark'].includes(preference)) preference = null;

    const apply = (theme) => {
        document.documentElement.dataset.theme = theme;
        document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#111315' : '#f5f6f8');
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            const label = theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему';
            button.setAttribute('aria-label', label);
            button.setAttribute('title', label);
            button.setAttribute('aria-pressed', String(theme === 'dark'));
        });
    };

    apply(preference || (system.matches ? 'dark' : 'light'));
    document.addEventListener('DOMContentLoaded', () => {
        apply(document.documentElement.dataset.theme);
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            button.addEventListener('click', () => {
                preference = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
                try { localStorage.setItem(key, preference); } catch (_) { /* Keep the choice for this page. */ }
                apply(preference);
            });
        });
    });
    system.addEventListener('change', () => {
        if (!preference) apply(system.matches ? 'dark' : 'light');
    });
    window.addEventListener('storage', (event) => {
        if (event.key !== key) return;
        preference = ['light', 'dark'].includes(event.newValue) ? event.newValue : null;
        apply(preference || (system.matches ? 'dark' : 'light'));
    });
})();
