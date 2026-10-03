'use strict';
// Тесты lib/bot-guide.js (этап 3, бот-помощник): разбор запроса, ключевые
// слова и подписи кнопок, тексты ответов и приветствие. Чистый Node, без БД.
// Запуск: node test/bot-guide.test.js

const assert = require('assert');
const guide = require('../lib/bot-guide');

let passed = 0, failed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        console.log('  ok  -', name);
    } catch (err) {
        failed++;
        console.error('  FAIL -', name);
        console.error('       ', err && err.stack ? err.stack : err);
    }
}

// Обязательные строки записаны escape-последовательностями, а не взяты из
// модуля: опечатка в кавычках или тире самого модуля иначе «подтвердила» бы
// сама себя. „ и “ — «„» и «“», — — длинное тире.
const DISCLAIMER = 'Чат со мной не защищён сквозным шифрованием — не пишите сюда личного';
const UNKNOWN_HINT = 'Напишите „гайд“ или выберите тему кнопкой ниже';
const WELCOME_CLOSING = 'Напишите „гайд“, чтобы узнать, как всё устроено';

const TOPIC_IDS = ['overview', 'start', 'invites', 'encryption', 'disappearing', 'account', 'files', 'privacy', 'settings'];

// Ключевые слова из плана этапа 3 — записаны здесь заново, а не взяты из
// TOPICS, чтобы ошибка в данных модуля не прошла проверку сама собой.
const KEYWORDS = {
    overview: ['гайд', 'помощь', 'help', '/start', 'меню', 'что умеешь'],
    start: ['начать', 'как пользоваться'],
    invites: ['приглашение', 'группа', 'вступить', 'заявка'],
    encryption: ['шифрование', 'ключ', 'код безопасности'],
    disappearing: ['исчезающие', 'таймер'],
    account: ['аккаунт', 'срок', 'удалить'],
    files: ['файлы', 'фото', 'метаданные'],
    privacy: ['приватность', 'tor', 'onion', 'ip'],
    settings: ['уведомления', 'тема'],
};

// Основы слов из задания: слово запроса должно НАЧИНАТЬСЯ с основы.
const STEMS = {
    overview: ['гайд', 'помощ', 'help', '/start', 'меню'],
    start: ['начать'],
    invites: ['приглаш', 'групп', 'вступ', 'заявк'],
    encryption: ['шифр', 'ключ'],
    disappearing: ['исчеза', 'таймер'],
    account: ['аккаунт', 'срок', 'удал'],
    files: ['файл', 'фото', 'метадан'],
    privacy: ['приватн', 'tor', 'onion', 'ip'],
    settings: ['уведомл', 'тем'],
};

// Эмодзи и пиктограммы: основные блоки эмодзи, стрелки, технические и
// геометрические символы, дингбаты, стрелки-дополнения, ©®™, клавиши-цифры,
// селекторы вариантов и «склейка» нулевой ширины. «•» (U+2022) сюда не входит:
// это маркер списка, он разрешён.
const EMOJI_OR_PICTOGRAPH = /[\u{1F000}-\u{1FAFF}\u{2190}-\u{21FF}\u{2300}-\u{23FF}\u{2460}-\u{24FF}\u{25A0}-\u{27BF}\u{2900}-\u{297F}\u{2B00}-\u{2BFF}\u{3030}\u{303D}\u{3297}\u{3299}©®™‍⃣︎️]/u;
// Строже, чем «нет эмодзи»: в текстах бота допустимы только буквы, цифры,
// пробелы и обычная пунктуация. Любой посторонний символ — повод посмотреть.
const ALLOWED_CHARS = /^[\p{Script=Cyrillic}\p{Script=Latin}\p{N}\s.,:;!?()«»„“"'—•/+-]*$/u;

function wordVariants(word) {
    return [
        word.toUpperCase(),
        word.charAt(0).toUpperCase() + word.slice(1),
        word.replace(/е/g, 'ё'),
        word.toUpperCase().replace(/Е/g, 'Ё'),
        `  ${word}  `,
        `${word}!`,
        `${word}?..`,
        `«${word}»`,
        `Подскажите, пожалуйста: ${word}`,
    ];
}

function allKeywords() {
    const list = [];
    for (const [topic, words] of Object.entries(KEYWORDS)) words.forEach(word => list.push({ topic, word }));
    for (const [topic, words] of Object.entries(STEMS)) words.forEach(word => list.push({ topic, word }));
    return list;
}

// Ответы, к которым применяются общие требования: все темы и подсказка.
function allReplies() {
    const replies = guide.TOPICS.map(topic => ({ name: topic.id, text: topic.text }));
    replies.push({ name: 'unknown', text: guide.botReply('qwerty').text });
    return replies;
}

function lines(text) {
    return text.split('\n');
}

// ---------- normalizeBotInput ----------

test('normalizeBotInput: регистр, ё, пунктуация и пробелы', () => {
    const n = guide.normalizeBotInput;
    assert.strictEqual(n('  ГАЙД!!!  '), 'гайд');
    assert.strictEqual(n('Всё,  что   умеешь?'), 'все что умеешь');
    assert.strictEqual(n('ЁЖ'), 'еж');
    assert.strictEqual(n('«Код\tбезопасности»…'), 'код безопасности');
    assert.strictEqual(n('как-то так_же'), 'как то так же');
    assert.strictEqual(n('Привет\nмир'), 'привет мир');
    assert.strictEqual(n('IP-адрес'), 'ip адрес');
    assert.strictEqual(n('1 день'), '1 день');
    assert.strictEqual(n('\u{1F600}'), '');
    assert.strictEqual(n(''), '');
});

test('normalizeBotInput: «/» остаётся, чтобы /start отличался от start', () => {
    const n = guide.normalizeBotInput;
    assert.strictEqual(n('/Start'), '/start');
    assert.strictEqual(n('/start@NyxoBot'), '/start nyxobot');
    assert.strictEqual(n('и/или'), 'и/или');
});

test('normalizeBotInput: «ё» из двух символов и знак ударения', () => {
    const n = guide.normalizeBotInput;
    assert.strictEqual(n('ёлка'), 'елка', '«ё» как «е» + диакритика');
    assert.strictEqual(n('гайд́'), 'гайд', 'знак ударения не часть слова');
});

test('normalizeBotInput: учитываются первые 500 символов', () => {
    const n = guide.normalizeBotInput;
    assert.strictEqual(n('а'.repeat(600)).length, 500);
    assert.ok(n(`гайд ${'я'.repeat(1000)}`).startsWith('гайд '));
    // Ключевое слово за пределом 500 символов не учитывается.
    assert.strictEqual(guide.detectTopic(`${'я '.repeat(250)}гайд`), null);
    assert.strictEqual(guide.detectTopic(`${'я '.repeat(200)}гайд`), 'overview');
});

test('normalizeBotInput и detectTopic: не строка — пустая строка и null, без падения', () => {
    for (const value of [undefined, null, 42, {}, [], true]) {
        assert.strictEqual(guide.normalizeBotInput(value), '');
        assert.strictEqual(guide.detectTopic(value), null);
        assert.strictEqual(guide.botReply(value).topic, null);
    }
});

test('detectTopic: очень длинный ввод не ломает разбор', () => {
    assert.strictEqual(guide.detectTopic('я '.repeat(1e6)), null);
    assert.strictEqual(guide.detectTopic('гайд '.repeat(1e5)), 'overview');
});

// ---------- Данные тем ----------

test('TOPICS: темы идут в порядке приоритета из плана', () => {
    assert.deepStrictEqual(guide.TOPICS.map(topic => topic.id), TOPIC_IDS);
    for (const topic of guide.TOPICS) {
        assert.ok(topic.label && typeof topic.label === 'string', `${topic.id}: нет заголовка`);
        assert.ok(topic.stems.length > 0, `${topic.id}: нет основ слов`);
        assert.ok(Array.isArray(topic.phrases), `${topic.id}: phrases должен быть массивом`);
    }
});

test('TOPICS: ключи записаны в нормализованном виде и не повторяются между темами', () => {
    const owner = new Map();
    for (const topic of guide.TOPICS) {
        for (const key of [...topic.phrases, ...topic.stems]) {
            assert.strictEqual(guide.normalizeBotInput(key), key, `ключ «${key}» (${topic.id}) не нормализован`);
            assert.ok(!owner.has(key), `ключ «${key}» есть и в ${owner.get(key)}, и в ${topic.id}: нижняя тема недостижима`);
            owner.set(key, topic.id);
        }
    }
});

test('TOPICS: основы из задания входят в темы, фразы из плана — тоже', () => {
    for (const [id, stems] of Object.entries(STEMS)) {
        const topic = guide.TOPICS.find(t => t.id === id);
        for (const stem of stems) assert.ok(topic.stems.includes(stem), `в ${id} нет основы «${stem}»`);
    }
    const phrases = new Map(guide.TOPICS.map(t => [t.id, t.phrases]));
    assert.ok(phrases.get('overview').includes('что умеешь'));
    assert.ok(phrases.get('start').includes('как пользоваться'));
    assert.ok(phrases.get('encryption').includes('код безопасности'));
});

test('TOPICS: данные заморожены', () => {
    assert.ok(Object.isFrozen(guide.TOPICS));
    for (const topic of guide.TOPICS) {
        assert.ok(Object.isFrozen(topic), topic.id);
        assert.ok(Object.isFrozen(topic.stems), topic.id);
        assert.ok(Object.isFrozen(topic.phrases), topic.id);
    }
    assert.ok(Object.isFrozen(guide.QUICK_REPLIES));
});

test('TOPICS: каждая фраза и основа, присланная как есть, ведёт к своей теме', () => {
    for (const topic of guide.TOPICS) {
        for (const key of [...topic.phrases, ...topic.stems]) {
            assert.strictEqual(guide.detectTopic(key), topic.id, `«${key}» должен вести к ${topic.id}`);
        }
    }
});

// ---------- Ключевые слова ----------

test('ключевые слова из плана ведут к своей теме и к её тексту', () => {
    const textById = new Map(guide.TOPICS.map(topic => [topic.id, topic.text]));
    for (const [id, words] of Object.entries(KEYWORDS)) {
        for (const word of words) {
            const reply = guide.botReply(word);
            assert.strictEqual(reply.topic, id, `«${word}» -> ${reply.topic}, ожидалась ${id}`);
            assert.strictEqual(reply.text, textById.get(id), `«${word}»: текст не той темы`);
        }
    }
});

test('основы слов из задания ведут к своей теме', () => {
    for (const [id, stems] of Object.entries(STEMS)) {
        for (const stem of stems) assert.strictEqual(guide.detectTopic(stem), id, `основа «${stem}»`);
    }
});

test('регистр, ё/е, пунктуация и соседние слова не влияют на тему', () => {
    for (const { topic, word } of allKeywords()) {
        for (const variant of wordVariants(word)) {
            assert.strictEqual(guide.detectTopic(variant), topic, `«${variant}» (из «${word}») -> ${guide.detectTopic(variant)}, ожидалась ${topic}`);
        }
    }
});

test('словоформы и естественные вопросы ведут к своей теме', () => {
    const FORMS = {
        overview: ['что ты умеешь?', 'Помощь!', '/help', '/Start', 'Меню'],
        start: ['с чего начать', 'как пользоваться ботом'],
        invites: ['приглашения', 'приглашений', 'приглашу', 'как пригласить друга', 'в группе', 'групповой чат', 'вступление', 'заявки'],
        encryption: ['шифрования', 'шифровать', 'зашифровано', 'ключи', 'кода безопасности', 'коды безопасности'],
        disappearing: ['исчезающих сообщений', 'исчезают', 'таймера'],
        account: ['аккаунта', 'в аккаунте', 'сроки', 'удалить аккаунт', 'удаление'],
        files: ['файла', 'фотографии', 'метаданных'],
        privacy: ['приватный', 'анонимность', 'Tor Browser', 'onion-адрес', 'IP-адрес'],
        settings: ['уведомлений', 'тёмная тема', 'настройки'],
    };
    for (const [id, texts] of Object.entries(FORMS)) {
        for (const text of texts) assert.strictEqual(guide.detectTopic(text), id, `«${text}»`);
    }
});

test('«start» без слэша — не команда /start, а «iphone» — не IP', () => {
    assert.strictEqual(guide.detectTopic('start'), null);
    // Основа считается по началу слова, поэтому «ip» ловит и «ipv6»; это известное и безвредное допущение.
    assert.strictEqual(guide.detectTopic('ipv6'), 'privacy');
});

test('приоритет: фразы раньше основ слов, а среди тем — порядок списка', () => {
    // Фраза важнее слов других тем в том же запросе.
    assert.strictEqual(guide.detectTopic('код безопасности и срок аккаунта'), 'encryption');
    assert.strictEqual(guide.detectTopic('что умеешь шифровать'), 'overview');
    // Если фразы двух тем, побеждает верхняя.
    assert.strictEqual(guide.detectTopic('как пользоваться кодом безопасности'), 'start');
    // Основы: побеждает тема, что выше в списке.
    assert.strictEqual(guide.detectTopic('удалить файлы'), 'account');
    assert.strictEqual(guide.detectTopic('шифрование файлов'), 'encryption');
    assert.strictEqual(guide.detectTopic('срок действия приглашения'), 'invites');
});

test('неизвестный текст получает подсказку', () => {
    for (const text of ['абракадабра', 'привет', 'как дела?', 'qwerty', 'hello', '???', '', '   ', '12345', '\u{1F600}']) {
        const reply = guide.botReply(text);
        assert.strictEqual(reply.topic, null, `«${text}»`);
        assert.strictEqual(guide.detectTopic(text), null, `«${text}»`);
        assert.ok(reply.text.startsWith(UNKNOWN_HINT), `«${text}»: ${reply.text}`);
    }
    assert.strictEqual(guide.UNKNOWN_HINT, UNKNOWN_HINT);
});

// ---------- Кнопки-подсказки ----------

test('QUICK_REPLIES: шесть подписей, и каждая ведёт к своей теме', () => {
    assert.deepStrictEqual([...guide.QUICK_REPLIES], ['Гайд', 'Шифрование', 'Приглашения', 'Исчезающие', 'Аккаунт', 'Приватность']);
    const expected = {
        'Гайд': 'overview',
        'Шифрование': 'encryption',
        'Приглашения': 'invites',
        'Исчезающие': 'disappearing',
        'Аккаунт': 'account',
        'Приватность': 'privacy',
    };
    for (const label of guide.QUICK_REPLIES) {
        assert.strictEqual(guide.botReply(label).topic, expected[label], label);
        assert.strictEqual(guide.detectTopic(label.toLowerCase()), expected[label], `${label} в нижнем регистре`);
        assert.strictEqual(guide.detectTopic(label.toUpperCase()), expected[label], `${label} в верхнем регистре`);
    }
    // Пределы клиента: не больше 6 кнопок и 60 символов в подписи.
    assert.ok(guide.QUICK_REPLIES.length <= 6);
    for (const label of guide.QUICK_REPLIES) assert.ok(label.length > 0 && label.length <= 60, label);
    assert.strictEqual(new Set(guide.QUICK_REPLIES.map(label => guide.botReply(label).topic)).size, guide.QUICK_REPLIES.length, 'темы кнопок не повторяются');
});

// ---------- Тексты ответов ----------

test('регулярка эмодзи ловит эмодзи и пиктограммы и пропускает «•»', () => {
    for (const bad of ['\u{1F600}', '❤️', '✅', '→', '⚠', '©', '\u{1F1F7}\u{1F1FA}', '1️⃣', '⭐']) {
        assert.ok(EMOJI_OR_PICTOGRAPH.test(bad), `должна ловить U+${bad.codePointAt(0).toString(16)}`);
        assert.ok(!ALLOWED_CHARS.test(`текст ${bad}`), `белый список должен отвергать U+${bad.codePointAt(0).toString(16)}`);
    }
    const fine = '• «Гайд» — тире, „кавычки“, 50 МБ, QR и PDF: (да), нет; /start +1';
    assert.ok(!EMOJI_OR_PICTOGRAPH.test(fine));
    assert.ok(ALLOWED_CHARS.test(fine));
});

test('ответы: без эмодзи, длина в пределах сообщения, дисклеймер отдельной последней строкой', () => {
    assert.strictEqual(guide.MAX_BOT_REPLY_LENGTH, 4000);
    assert.strictEqual(guide.BOT_DISCLAIMER, DISCLAIMER);
    for (const { name, text } of allReplies()) {
        assert.ok(typeof text === 'string' && text.length > 0, name);
        assert.ok(text.length <= 4000, `${name}: ${text.length} символов`);
        assert.doesNotMatch(text, EMOJI_OR_PICTOGRAPH, name);
        assert.match(text, ALLOWED_CHARS, name);
        const rows = lines(text);
        assert.strictEqual(rows[rows.length - 1], DISCLAIMER, `${name}: последняя строка — дисклеймер`);
        assert.strictEqual(rows[rows.length - 2], '', `${name}: дисклеймер отделён пустой строкой`);
        assert.strictEqual(text.split(DISCLAIMER).length - 1, 1, `${name}: дисклеймер ровно один раз`);
    }
});

test('ответы: короткие, без лишних пробелов и без управляющих символов', () => {
    for (const { name, text } of allReplies()) {
        assert.ok(text.length <= 1200, `${name}: ${text.length} символов — это уже не «коротко»`);
        assert.ok(!/\r|\t/.test(text), `${name}: \\r и \\t не нужны`);
        assert.strictEqual(text, text.trim(), `${name}: пробелы по краям`);
        for (const row of lines(text)) assert.strictEqual(row, row.trimEnd(), `${name}: пробел в конце строки «${row}»`);
        assert.ok(!text.includes('\n\n\n'), `${name}: две пустые строки подряд`);
    }
});

test('ответы тем: заголовок, пустая строка, пункты с «•»', () => {
    for (const topic of guide.TOPICS) {
        const rows = lines(topic.text);
        assert.strictEqual(rows[0], topic.label, `${topic.id}: первая строка — заголовок`);
        assert.strictEqual(rows[1], '', `${topic.id}: после заголовка пустая строка`);
        // Тело — всё между заголовком и дисклеймером; у обзора первая строка — вступление.
        const body = rows.slice(2, -2);
        assert.ok(body.length >= 3, `${topic.id}: слишком мало пунктов`);
        body.forEach((row, index) => {
            const intro = topic.id === 'overview' && (index === 0 || index === 1);
            if (intro || row === '') return;
            assert.ok(row.startsWith('• '), `${topic.id}: строка без маркера: «${row}»`);
        });
    }
});

test('ответы: разные темы — разные тексты', () => {
    const texts = allReplies().map(reply => reply.text);
    assert.strictEqual(new Set(texts).size, texts.length);
});

test('ответы: нет отпечатков, хэшей, адресов и ссылок', () => {
    // Бот — текст сервера: ничего, что можно принять за проверку безопасности.
    for (const { name, text } of [...allReplies(), ...['tab', 'day', 'week'].map(l => ({ name: `welcome:${l}`, text: guide.welcomeText(l) }))]) {
        assert.doesNotMatch(text, /https?:|www\.|:\/\//i, `${name}: ссылка`);
        assert.doesNotMatch(text, /@|\.onion\b|\.com\b|\.org\b|\.net\b|\.ru\b/i, `${name}: адрес`);
        assert.doesNotMatch(text, /[0-9a-f]{16,}/i, `${name}: похоже на хэш или отпечаток`);
        assert.doesNotMatch(text, /\d{5,}/, `${name}: длинная цифровая группа (код безопасности?)`);
        assert.doesNotMatch(text, /отпечат|fingerprint|хэш|хеш|sha-?\d|md5/i, `${name}: упоминание отпечатков и хэшей`);
    }
});

test('ответы: не обещают потолок «7 дней от создания»', () => {
    for (const { name, text } of [...allReplies(), ...['tab', 'day', 'week'].map(l => ({ name: `welcome:${l}`, text: guide.welcomeText(l) }))]) {
        assert.doesNotMatch(text, /не позже чем|после создания|с момента создания/i, name);
    }
});

test('обзор: каждое слово из списка ведёт к одной из остальных тем, и темы не повторяются', () => {
    const overview = guide.TOPICS.find(topic => topic.id === 'overview');
    const keywords = lines(overview.text)
        .map(row => /^• «([^»]+)» — .+$/.exec(row))
        .filter(Boolean)
        .map(match => match[1]);
    const reached = keywords.map(word => guide.detectTopic(word));
    assert.deepStrictEqual([...reached].sort(), TOPIC_IDS.filter(id => id !== 'overview').sort(), `слова обзора: ${keywords.join(', ')} -> ${reached.join(', ')}`);
});

test('ответы по честности: коды безопасности — где смотреть и как сверять, баннер «ключ изменился»', () => {
    const encryption = guide.botReply('шифрование').text;
    assert.ok(encryption.includes('«Участники и ключи»'), 'название окна');
    assert.match(encryption, /лично или по другому каналу/);
    assert.ok(encryption.includes('не через этот чат'), 'сверять вне чата с ботом');
    assert.ok(encryption.includes('«ключ изменился»'), 'баннер');
    assert.match(encryption, /очист\S+ данные браузера/);
});

test('ответы по честности: исчезающие, приглашения, файлы, приватность', () => {
    const text = (word) => guide.botReply(word).text;
    // Исчезающие: общий таймер группы и все пять значений.
    const disappearing = text('исчезающие');
    assert.match(disappearing, /общий для всей группы/);
    for (const option of ['«Выключены»', '5 минут', '1 час', '1 день', '7 дней']) assert.ok(disappearing.includes(option), option);
    // Приглашения: код, QR, ссылка, заявка, лимит, история.
    const invites = text('приглашения');
    for (const part of ['код', 'QR', 'ссылк', 'заявк', 'лимит участников', 'не видит сообщения, отправленные до его вступления']) assert.ok(invites.includes(part), part);
    // Файлы: метаданные вычищаются в браузере, имена обезличиваются, 50 МБ, аудио нет.
    const files = text('файлы');
    for (const part of ['в вашем браузере до отправки', 'обезличенными', '50 МБ', 'Аудио не поддерживается']) assert.ok(files.includes(part), part);
    // Приватность: что видит сервер, IP, Tor, отметки, поиск, уведомления.
    const privacy = text('приватность');
    for (const part of ['кто в какой группе', 'когда пишет', 'размер', 'IP-адрес виден серверу и интернет-провайдеру', 'Tor', '«Как это работает»', 'Отметки о прочтении по умолчанию выключены', 'только на вашем устройстве', 'без текста']) assert.ok(privacy.includes(part), part);
    // Настройки: отметки о прочтении взаимные и выключены, уведомления выключены и без текста.
    const settings = text('настройки');
    for (const part of ['Отметки о прочтении выключены по умолчанию', 'только если сами отправляете', 'Уведомления выключены, пока вы не включите их в «Профиле»', 'без текста и имени отправителя']) assert.ok(settings.includes(part), part);
    // Аккаунт: сроки, потолка нет, удаление, потеря доступа.
    const account = text('аккаунт');
    for (const part of ['30 минут после закрытия последней вкладки', '1 день', '7 дней', 'потолка от даты создания нет', '«Удалить и выйти»', 'пропадёт навсегда']) assert.ok(account.includes(part), part);
});

// ---------- Приветствие ----------

test('welcomeText: срок хранения, предупреждение и последняя строка для всех сроков', () => {
    const RULES = {
        tab: 'через 30 минут после закрытия последней вкладки',
        day: 'если не заходить сутки',
        week: 'если не заходить 7 дней',
    };
    for (const [lifetime, rule] of Object.entries(RULES)) {
        const text = guide.welcomeText(lifetime);
        assert.ok(text.includes(rule), `${lifetime}: ${text}`);
        for (const [other, otherRule] of Object.entries(RULES)) {
            if (other !== lifetime) assert.ok(!text.includes(otherRule), `${lifetime}: в тексте чужой срок (${other})`);
        }
        assert.ok(text.includes('Если очистить данные браузера или сменить устройство, доступ пропадёт навсегда'), `${lifetime}: предупреждение`);
        assert.ok(text.endsWith(WELCOME_CLOSING), `${lifetime}: приветствие заканчивается нужной фразой`);
        assert.strictEqual(lines(text).pop(), WELCOME_CLOSING, `${lifetime}: последняя строка`);
        assert.strictEqual(guide.WELCOME_CLOSING, WELCOME_CLOSING);
    }
});

test('welcomeText: дисклеймер, длина, без эмодзи', () => {
    for (const lifetime of ['tab', 'day', 'week']) {
        const text = guide.welcomeText(lifetime);
        assert.ok(text.includes(`\n${DISCLAIMER}\n`), `${lifetime}: дисклеймер отдельной строкой`);
        assert.ok(text.length <= 4000 && text.length <= 1200, `${lifetime}: ${text.length}`);
        assert.doesNotMatch(text, EMOJI_OR_PICTOGRAPH, lifetime);
        assert.match(text, ALLOWED_CHARS, lifetime);
        assert.strictEqual(text, text.trim());
        assert.ok(!/\r|\t/.test(text));
    }
});

test('welcomeText: неизвестный срок считается самым коротким и ничего не ломает', () => {
    const expected = guide.welcomeText('tab');
    for (const value of [undefined, null, '', 'month', 'Tab', 'constructor', '__proto__', 'toString', 7, {}, []]) {
        assert.strictEqual(guide.welcomeText(value), expected, String(value));
    }
});

// ---------- Чистота ----------

test('botReply и welcomeText: одинаковый вход — одинаковый ответ', () => {
    for (const text of ['гайд', 'qwerty', 'Шифрование', '']) {
        assert.deepStrictEqual(guide.botReply(text), guide.botReply(text));
    }
    assert.strictEqual(guide.welcomeText('week'), guide.welcomeText('week'));
    // Ответ — строка: изменить общий текст темы снаружи нельзя.
    const reply = guide.botReply('гайд');
    reply.text += ' лишнее';
    assert.ok(!guide.botReply('гайд').text.includes('лишнее'));
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exitCode = 1;
