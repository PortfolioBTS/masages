// public/js/15-bot-suggestions.js — подсказки в чате с ботом.
// Вынесено из public/script.js (строки 6194–6268 версии до разбиения) в задаче T6.2 (R14): чистый перенос, код не менялся.
// Классический скрипт (не ES-модуль): общая глобальная область со всеми файлами public/js/, порядок подключения — как в index.html.

// ==================== Подсказки в чате с ботом ====================
// Над полем ввода в чате с ботом — кнопки с темами («Гайд», «Шифрование», …).
// Нажатие — обычное сообщение с подписью кнопки, тем же путём (sendText), что и
// набранный текст: ответ бота приходит как на любое другое сообщение. Подписи
// отдаёт сервер (chat.quickReplies в ответе истории): это же ключевые слова
// бота (lib/bot-guide.js), и разойтись они не должны.

const MAX_BOT_SUGGESTIONS = 6;         // больше кнопок на экране не поместится
const MAX_BOT_SUGGESTION_LENGTH = 60;  // подпись длиннее — уже не подсказка

let botSuggestionsChatId = null;       // чат, для которого нарисованы кнопки: нажатие уходит только в него

function clearBotSuggestions() {
    botSuggestionsChatId = null;
    elements.botSuggestions.classList.add('hidden');
    elements.botSuggestions.replaceChildren();
}

// Пока идёт отправка, кнопки помечены aria-disabled, а не disabled: фокус
// остаётся на нажатой кнопке (клавиатура и скринридер не теряют место), а
// повторное нажатие всё равно ничего не делает.
function syncBotSuggestionsBusy() {
    elements.botSuggestions.querySelectorAll('button.suggestion').forEach((button) => {
        if (sending) button.setAttribute('aria-disabled', 'true');
        else button.removeAttribute('aria-disabled');
    });
}

// Единственное место, где меняется замок отправки: кнопки подсказок должны
// отражать его и тогда, когда сообщение уходит из поля ввода.
function setSending(value) {
    sending = value;
    syncBotSuggestionsBusy();
}

// labels — chat.quickReplies из ответа сервера. Рисуем только строки разумной
// длины и не больше MAX_BOT_SUGGESTIONS, через textContent, как любой текст,
// пришедший с сервера. chatId запоминается: нажатие отправит сообщение именно
// в этот чат, даже если к тому времени открыт другой.
function renderBotSuggestions(chatId, labels) {
    clearBotSuggestions();
    if (!Array.isArray(labels)) return;
    const shown = labels
        .filter(label => typeof label === 'string' && label.trim() !== '' && label.length <= MAX_BOT_SUGGESTION_LENGTH)
        .slice(0, MAX_BOT_SUGGESTIONS);
    if (shown.length === 0) return;
    const fragment = document.createDocumentFragment();
    shown.forEach((label) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'chip suggestion';
        button.textContent = label;
        fragment.appendChild(button);
    });
    elements.botSuggestions.appendChild(fragment);
    elements.botSuggestions.classList.remove('hidden');
    botSuggestionsChatId = chatId;
    syncBotSuggestionsBusy();
}

// Один обработчик на весь контейнер: кнопки пересоздаются при каждом открытии чата.
async function onBotSuggestionClick(event) {
    const button = event.target.closest('button.suggestion');
    if (!button || !elements.botSuggestions.contains(button)) return;
    const chatId = botSuggestionsChatId;
    if (!chatId || chatId !== currentChatId || sending) return;
    setSending(true);
    try {
        // Поле ввода не читаем и не очищаем: черновик пользователя остаётся как был.
        await sendText(button.textContent, { chatId });
    } finally {
        setSending(false);
    }
}
