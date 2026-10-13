document.querySelectorAll('.flash-close').forEach((button) => {
    button.addEventListener('click', () => button.closest('.flash')?.remove());
});

document.querySelectorAll('[data-password-toggle]').forEach((button) => {
    button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.passwordToggle);
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        button.textContent = input.type === 'password' ? 'Показать' : 'Скрыть';
        button.setAttribute('aria-label', input.type === 'password' ? 'Показать пароль' : 'Скрыть пароль');
        button.setAttribute('aria-pressed', String(input.type === 'text'));
    });
});

const menuButton = document.getElementById('menuButton');
const sidebar = document.getElementById('sidebar');
if (menuButton && sidebar) {
    const mobile = window.matchMedia('(max-width: 860px)');
    const backdrop = document.getElementById('sidebarBackdrop');
    const pageShell = document.querySelector('.page-shell');
    const setMenu = (open, restoreFocus = true) => {
        const isOpen = mobile.matches && open;
        sidebar.classList.toggle('open', isOpen);
        sidebar.inert = mobile.matches && !isOpen;
        pageShell.inert = isOpen;
        if (backdrop) backdrop.hidden = !isOpen;
        document.body.classList.toggle('menu-open', isOpen);
        menuButton.setAttribute('aria-expanded', String(isOpen));
        if (isOpen) sidebar.querySelector('[data-menu-close]')?.focus();
        else if (restoreFocus && mobile.matches) menuButton.focus();
    };
    setMenu(false, false);
    menuButton.addEventListener('click', () => setMenu(!sidebar.classList.contains('open')));
    backdrop?.addEventListener('click', () => setMenu(false));
    sidebar.querySelector('[data-menu-close]')?.addEventListener('click', () => setMenu(false));
    mobile.addEventListener('change', () => setMenu(false, false));
    document.addEventListener('keydown', (event) => {
        if (!sidebar.classList.contains('open')) return;
        if (event.key === 'Escape') { setMenu(false); return; }
        if (event.key !== 'Tab') return;
        const focusable = [...sidebar.querySelectorAll('a, button, input')].filter((element) => element.offsetParent !== null && element.type !== 'hidden' && !element.disabled);
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
        }
    });
}

document.querySelectorAll('[data-file-picker]').forEach((picker) => {
    const input = picker.querySelector('input[type="file"]');
    const label = picker.querySelector('[data-file-label]');
    if (!input || !label) return;

    const defaultLabel = label.textContent;
    const updateLabel = () => {
        const files = Array.from(input.files || []);
        if (files.length === 0) {
            label.textContent = defaultLabel;
        } else if (files.length === 1) {
            label.textContent = files[0].name;
        } else {
            label.textContent = `Выбрано файлов: ${files.length}`;
        }
    };

    input.addEventListener('change', updateLabel);
    ['dragenter', 'dragover'].forEach((eventName) => {
        picker.addEventListener(eventName, (event) => {
            event.preventDefault();
            picker.classList.add('is-dragover');
        });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
        picker.addEventListener(eventName, (event) => {
            event.preventDefault();
            picker.classList.remove('is-dragover');
        });
    });
    picker.addEventListener('drop', (event) => {
        if (!event.dataTransfer?.files?.length) return;
        input.files = event.dataTransfer.files;
        updateLabel();
    });
});

document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(button.dataset.copy);
            const previous = button.textContent;
            button.textContent = 'Скопировано';
            setTimeout(() => { button.textContent = previous; }, 1500);
        } catch (_error) {
            button.textContent = 'Выделите вручную';
        }
    });
});

document.querySelectorAll('[data-print]').forEach((button) => {
    button.addEventListener('click', () => window.print());
});
