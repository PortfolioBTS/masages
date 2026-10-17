// public/js/09-auth-screen.js — экран входа и тема оформления.
// Вынесено из public/script.js (строки 3321–3601 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Экран входа и тема ====================
// Аккаунт только временный: без почты и номера телефона, с выбранным
// сроком хранения. Экран один: выбор срока, «Начать анонимно» и, если есть,
// приглашение в группу (ссылка или код). Формат приглашения проверяется ДО
// PoW: битый код не должен стоить человеку проверки и лишнего аккаунта.
// Ход проверки и ошибки остаются на экране (#auth-progress), а не только в
// тосте: тост исчезает, пока человек смотрит на кнопку.

// Почему человек снова видит экран входа (#auth-notice).
const AUTH_NOTICES = {
    deleted: 'Аккаунт удалён. Данные на этом устройстве стёрты.',
    deletedElsewhere: 'Аккаунт удалён в другой вкладке.',
    expired: 'Прежний аккаунт удалён: вы не заходили дольше выбранного срока.',
    sessionLost: 'Вход в аккаунт потерян: аккаунт удалён или сессия закончилась. Данные на этом устройстве стёрты.',
    otherAccount: 'В соседней вкладке открыт другой аккаунт. Данные прежнего на этом устройстве стёрты.',
    noCookies: 'Браузер не сохранил cookie — без неё аккаунт не работает. Разрешите cookie для этого сайта.',
};

const AUTH_POW_PROGRESS = 'Создаём аккаунт: проверка, что вы не бот. Обычно несколько секунд, в Tor Browser — дольше.';
const INVITE_FORMAT_ERROR = 'Не похоже на код приглашения. Нужна ссылка вида …/#join=… или 26 символов (буквы и цифры 2–9).';
const INVITE_EMPTY_ERROR = 'Вставьте ссылку-приглашение или код.';

let authBusy = false;
let authInviteMode = false;
let registrationCancelled = false;   // аккаунт появился в соседней вкладке, пока считался PoW

function selectedAuthLifetime() {
    const checked = elements.authLifetime.querySelector('input[name="auth-lifetime"]:checked');
    return checked && NyxoLifetime.isLifetime(checked.value) ? checked.value : NyxoLifetime.DEFAULT_LIFETIME;
}

function updateAuthLifetimeDetail() {
    elements.authLifetimeDetail.textContent = NyxoLifetime.lifetimeDetail(selectedAuthLifetime());
    updateAuthInviteAdvice();
}

// Совет для срока «Пока открыта вкладка» в режиме приглашения: заявка в
// группу удаляется вместе с аккаунтом, а одобрения можно ждать долго.
function updateAuthInviteAdvice() {
    const text = authInviteMode ? NyxoLifetime.inviteTabWarning(selectedAuthLifetime(), false) : '';
    elements.authInviteAdvice.textContent = text;
    elements.authInviteAdvice.classList.toggle('hidden', !text);
}

// Подпись кнопки — в её <span>: иконки рядом остаются на месте.
function setButtonText(btn, text) {
    const span = btn.querySelector('span');
    if (span) span.textContent = text;
    else btn.textContent = text;
}

// Режим «У меня есть приглашение»: поле ссылки или кода над выбором срока.
// value — подставить в поле (ссылка #join=), error — сразу показать ошибку.
function setInviteMode(on, { value = null, focus = false, error = null } = {}) {
    authInviteMode = Boolean(on);
    elements.authInvite.classList.toggle('hidden', !authInviteMode);
    elements.inviteToggleBtn.setAttribute('aria-expanded', authInviteMode ? 'true' : 'false');
    setButtonText(elements.inviteToggleBtn, authInviteMode ? 'Без приглашения' : 'У меня есть приглашение');
    setButtonText(elements.anonStartBtn, authInviteMode ? 'Создать аккаунт и открыть приглашение' : 'Начать анонимно');
    if (value !== null) elements.authInviteInput.value = value;
    if (error) showInviteError(error);
    else if (!authInviteMode || value !== null) clearInviteError();
    updateAuthInviteAdvice();
    if (focus && authInviteMode) elements.authInviteInput.focus();
}

function showInviteError(text) {
    elements.authInviteError.textContent = text;
    elements.authInviteError.classList.remove('hidden');
    elements.authInviteInput.setAttribute('aria-invalid', 'true');
}

function clearInviteError() {
    elements.authInviteError.textContent = '';
    elements.authInviteError.classList.add('hidden');
    elements.authInviteInput.removeAttribute('aria-invalid');
}

function setAuthProgress(text, { error = false } = {}) {
    const el = elements.authProgress;
    el.classList.toggle('is-error', Boolean(text) && error);
    if (!text) {
        el.replaceChildren();
        return;
    }
    const span = document.createElement('span');
    span.textContent = text;
    el.replaceChildren(error ? icon('alert-triangle', { size: 'sm' }) : icon('loader', { size: 'sm', className: 'spin' }), span);
}

function showAuthNotice(text) {
    elements.authNotice.textContent = text || '';
    elements.authNotice.classList.toggle('hidden', !text);
}

// Пока создаётся аккаунт, выбор срока и приглашение заблокированы: двойной
// клик и повторный Enter не запускают вторую проверку.
function setAuthBusy(busy) {
    authBusy = busy;
    elements.authLifetime.disabled = busy;
    elements.inviteToggleBtn.disabled = busy;
    elements.authInviteInput.readOnly = busy;
    elements.anonStartBtn.disabled = busy;
}

// GET /api/auth — единый источник состояния аккаунта (он же продлевает
// сессию). null — сервер недоступен или ответил не JSON: тогда ничего не
// решаем и ничего не стираем.
async function fetchAuthState() {
    let data;
    try {
        const res = await fetch('/api/auth', { cache: 'no-store' });
        data = await res.json();
    } catch {
        return null;
    }
    if (!data || typeof data !== 'object' || typeof data.authenticated !== 'boolean') return null;
    lastAuthAt = Date.now();
    if ('onionUrl' in data) applyOnionUrl(data.onionUrl);
    return data;
}

async function startAccount() {
    if (authBusy || currentUser) return;
    let invite = null;
    if (authInviteMode) {
        const parsed = NyxoInvite.parseInviteInput(elements.authInviteInput.value);
        if (!parsed.ok) {
            showInviteError(parsed.reason === 'empty' ? INVITE_EMPTY_ERROR : INVITE_FORMAT_ERROR);
            elements.authInviteInput.focus();
            return;
        }
        clearInviteError();
        invite = { code: parsed.code, secret: parsed.secret };
    }
    const lifetime = selectedAuthLifetime();
    const btn = elements.anonStartBtn;
    registrationCancelled = false;
    setAuthBusy(true);
    setAuthProgress('');
    let entered = false;
    const enter = (user) => {
        entered = true;
        pendingJoin = invite;
        pendingJoinBroken = false;
        enterApp(user);
        // Другие вкладки на экране входа подхватят аккаунт, остальные
        // сверят, не сменилась ли кука на чужой аккаунт.
        postSessionEvent({ type: 'session-started', userId: user.id });
    };
    try {
        // Аккаунт уже создан (в соседней вкладке или до перезагрузки) —
        // входим в него, второй не создаём.
        const before = await fetchAuthState();
        if (currentUser) return;
        if (before && before.authenticated && before.user) {
            enter(before.user);
            return;
        }

        setAuthProgress(AUTH_POW_PROGRESS);
        const data = await postWithPow('/api/register/anonymous', { lifetime }, 'register-anon', btn, {
            isCancelled: () => registrationCancelled || Boolean(currentUser),
        });
        // postWithPow разблокирует кнопку сам; держим её выключенной до конца.
        btn.disabled = true;
        if (registrationCancelled || currentUser || (data && data.cancelled)) return;

        if (data && data.code === 'already-authenticated') {
            // 409: живая сессия есть (её не было видно при первой проверке) — входим в неё.
            const state = await fetchAuthState();
            if (currentUser) return;
            if (state && state.authenticated && state.user) {
                enter(state.user);
                return;
            }
            setAuthProgress(data.message || 'Вы уже вошли в аккаунт. Обновите страницу.', { error: true });
            return;
        }
        if (!data || !data.success || !data.user) {
            setAuthProgress((data && data.message) || 'Не удалось создать аккаунт. Попробуйте ещё раз.', { error: true });
            return;
        }

        // Ответ регистрации поставил куку сессии. Если /api/auth её не видит,
        // браузер cookie не сохранил: аккаунт без неё недоступен, а уход на
        // экран входа зациклил бы попытки — просто объясняем, что случилось.
        const state = await fetchAuthState();
        if (currentUser) return;
        if (state && !state.authenticated) {
            setAuthProgress('');
            showAuthNotice(AUTH_NOTICES.noCookies);
            return;
        }
        const user = state && state.authenticated && state.user ? state.user : { anonLifetime: lifetime, ...data.user };
        rememberBotChatId(user.id, data.botChatId);
        enter(user);
    } finally {
        setAuthBusy(false);
        if (entered) setAuthProgress('');
    }
}

// Окно «Как это работает»: с экрана входа и из профиля. section 'tor' —
// сразу к разделу про IP и onion-адрес (ссылка «Открыть через Tor»).
function openAboutModal(section) {
    closeAllModals();
    openModal(elements.aboutModal);
    if (section === 'tor') {
        elements.aboutTor.focus({ preventScroll: true });
        elements.aboutTor.scrollIntoView({ block: 'start', behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    }
}

// Onion-адрес приходит полем onionUrl в /api/auth: заголовок Onion-Location
// скрипт прочитать не может, а шаблонизировать index.html нельзя. Ссылка
// «Открыть через Tor» показывается только для проверенного v3-адреса (иначе
// её нет вовсе) и не ведёт прямо на onion: в обычном браузере такая ссылка
// не откроется — она открывает раздел про Tor с адресом и «Скопировать».
let onionUrl = null;

function applyOnionUrl(value) {
    onionUrl = NyxoInvite.parseOnionUrl(value);
    const onOnion = /\.onion$/i.test(location.hostname);
    const show = Boolean(onionUrl) && !onOnion;
    elements.onionOpenBtn.classList.toggle('hidden', !show);
    elements.authLinksSep.classList.toggle('hidden', !show);
    elements.aboutOnion.classList.toggle('hidden', !show);
    elements.aboutOnionMissing.classList.toggle('hidden', show || onOnion);
    elements.aboutOnionCurrent.classList.toggle('hidden', !onOnion);
    elements.aboutOnionAddress.textContent = show ? onionUrl : '';
    if (show) elements.aboutOnionLink.href = onionUrl;
    else elements.aboutOnionLink.removeAttribute('href');
}

// Тема — через window.NyxoTheme (public/theme.js). Кнопка показывает, КУДА
// переключит: в тёмной теме — солнце, в светлой — луна.
function currentTheme() {
    try {
        if (window.NyxoTheme && typeof window.NyxoTheme.get === 'function') return window.NyxoTheme.get();
    } catch { /* ниже — по атрибуту */ }
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function refreshThemeButtons() {
    const dark = currentTheme() !== 'light';
    const label = dark ? 'Светлая тема' : 'Тёмная тема';
    const iconName = dark ? 'sun' : 'moon';
    const hasApi = Boolean(window.NyxoTheme);
    // Кнопки-иконки: в сайдбаре и в углу экрана входа.
    for (const btn of [elements.themeToggleBtn, elements.authThemeBtn]) {
        btn.replaceChildren(icon(iconName));
        btn.title = `Включить: ${label.toLowerCase()}`;
        btn.setAttribute('aria-label', `Включить ${label.toLowerCase()}`);
        btn.classList.toggle('hidden', !hasApi);
    }
    setIconLabel(elements.profileThemeBtn, iconName, label);
    elements.profileThemeBtn.classList.toggle('hidden', !hasApi);
}

function toggleTheme() {
    try {
        if (window.NyxoTheme && typeof window.NyxoTheme.toggle === 'function') window.NyxoTheme.toggle();
    } catch (err) {
        console.warn('Не удалось сменить тему:', err);
    }
    refreshThemeButtons();
}

function setupThemeControls() {
    elements.themeToggleBtn.addEventListener('click', toggleTheme);
    elements.authThemeBtn.addEventListener('click', toggleTheme);
    elements.profileThemeBtn.addEventListener('click', toggleTheme);
    // Тему может сменить и сама система (если выбор не сохранён), и другая
    // вкладка — следим за атрибутом, а не за своими кликами.
    if (typeof MutationObserver === 'function') {
        new MutationObserver(refreshThemeButtons).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    }
    refreshThemeButtons();
}
