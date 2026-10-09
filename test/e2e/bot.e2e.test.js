'use strict';
// Бот-помощник с гайдом (контракт волны 1, §7, T1.3b; roadmap R4; план
// владельца, этап 3): каждое ключевое слово и каждая подпись кнопки-подсказки
// через сокет приводят к ответу своей темы; приветствие заканчивается
// подсказкой про «гайд»; chat.quickReplies есть только у чата с ботом.
//
// Тексты гайда ещё будут правиться (сверка с кодом в конце работ), поэтому
// набор не сравнивает ответы с эталонными текстами. Тема ответа узнаётся по
// устойчивым признакам:
//   * соответствие «ключевое слово -> тема» берётся из плана владельца (3.1),
//     а не из lib/bot-guide.js: набор сверяет сервер с планом, а не код с собой;
//   * ответы одной темы совпадают друг с другом и с ответом на подпись кнопки
//     этой темы (кнопка = обычное сообщение с её подписью), ответы разных тем
//     различаются, неизвестный запрос не похож ни на одну тему;
//   * заголовок темы (первая строка) называет её своим корнем — слабый, но
//     независимый от формулировок якорь.

const { test } = require('node:test');
const assert = require('assert');
const { createSuite } = require('./helpers/scenarios');

const suite = createSuite('bot');

// Предел текста сообщения (POST /api/messages): ответ бота — такое же сообщение.
const MAX_MESSAGE_LENGTH = 4000;
const DISCLAIMER = 'Чат со мной не защищён сквозным шифрованием — не пишите сюда личного';
const WELCOME_CLOSING = 'Напишите „гайд“, чтобы узнать, как всё устроено';
const UNKNOWN_HINT = 'Напишите „гайд“ или выберите тему кнопкой ниже';

// План владельца 3.1: ключевые слова (без учёта регистра и е/ё) по темам.
// buttonLabel — подпись кнопки-подсказки этой темы (3.3), если у темы есть кнопка;
// heading — корень названия темы в заголовке ответа.
const TOPICS = {
    overview: { keywords: ['гайд', 'помощь', 'help', '/start', 'меню', 'что умеешь'], buttonLabel: 'Гайд', heading: null },
    start: { keywords: ['начать', 'как пользоваться'], buttonLabel: null, heading: /шаг|начал|нач/i },
    invites: { keywords: ['приглашение', 'группа', 'вступить', 'заявка'], buttonLabel: 'Приглашения', heading: /приглаш/i },
    encryption: { keywords: ['шифрование', 'ключ', 'код безопасности'], buttonLabel: 'Шифрование', heading: /шифр/i },
    disappearing: { keywords: ['исчезающие', 'таймер'], buttonLabel: 'Исчезающие', heading: /исчезающ/i },
    account: { keywords: ['аккаунт', 'срок', 'удалить'], buttonLabel: 'Аккаунт', heading: /аккаунт/i },
    files: { keywords: ['файлы', 'фото', 'метаданные'], buttonLabel: null, heading: /файл/i },
    privacy: { keywords: ['приватность', 'tor', 'onion', 'ip'], buttonLabel: 'Приватность', heading: /приватн/i },
    settings: { keywords: ['уведомления', 'тема'], buttonLabel: null, heading: /настро|уведомл/i },
};
// План владельца 3.3: кнопки над полем ввода, в этом порядке.
const QUICK_REPLIES = ['Гайд', 'Шифрование', 'Приглашения', 'Исчезающие', 'Аккаунт', 'Приватность'];

const EMOJI = /\p{Extended_Pictographic}/u;
const URL_LIKE = /https?:|www\.|\.onion\b|\.com\b|\.org\b/i;

// Новый аккаунт, его чат с ботом и сокет, подписанный на этот чат.
async function botSession(t, { lifetime = 'tab' } = {}) {
    const client = suite.client();
    await client.registerAnon({ lifetime });
    const bot = await client.botChat();
    const sock = await client.socket();
    t.after(() => sock.close());
    // Явная подписка на чат: на уже существующие чаты сервер подписывает
    // сокет асинхронно, а ответ бота приходит через ~0.6 с — подписка готова.
    sock.emit('joinChat', `chat:${bot.id}`);
    return { client, bot, sock };
}

// Сообщение пользователю -> ответ бота, пришедший по сокету.
async function ask({ client, bot, sock }, text) {
    const sent = await client.send(bot.id, text);
    const reply = await sock.waitFor('newMessage', m => m.chat_id === bot.id && m.sent === 0 && m.seq > sent.seq);
    return reply;
}

const firstLine = (text) => text.split('\n')[0];
const lastLine = (text) => text.split('\n').pop();

// Общие свойства любого ответа бота.
function assertReplyShape(reply, what) {
    assert.strictEqual(typeof reply.text, 'string', what);
    assert.ok(reply.text.length > 0 && reply.text.length <= MAX_MESSAGE_LENGTH, `${what}: длина ответа ${reply.text.length}`);
    assert.strictEqual(lastLine(reply.text), DISCLAIMER, `${what}: дисклеймер — отдельная последняя строка`);
    assert.ok(!EMOJI.test(reply.text), `${what}: в ответе эмодзи`);
    assert.ok(!URL_LIKE.test(reply.text), `${what}: в ответе ссылка или адрес`);
    assert.strictEqual(reply.sender_username, 'Бот Помощник', what);
    assert.strictEqual(reply.sent, 0, what);
}

test('чат с ботом отдаёт quickReplies — шесть подписей из плана, коротких и без повторов', async () => {
    const client = suite.client();
    await client.registerAnon();
    const bot = await client.botChat();
    const history = await client.messages(bot.id);
    assert.deepStrictEqual(history.chat.quickReplies, QUICK_REPLIES);
    assert.ok(history.chat.quickReplies.length <= 6, 'клиент рисует не больше 6 кнопок');
    for (const label of history.chat.quickReplies) {
        assert.ok(label.length > 0 && label.length <= 60, `подпись «${label}» длиннее 60 символов`);
        assert.ok(!EMOJI.test(label), `в подписи «${label}» эмодзи`);
    }
    assert.strictEqual(new Set(history.chat.quickReplies).size, history.chat.quickReplies.length, 'подписи не повторяются');
    // Поле — часть ответа об одном чате, а не список чатов.
    assert.ok(Array.isArray(history.messages));
});

test('quickReplies есть только у чата с ботом: у комнат (владельца и участника) поля нет', async () => {
    const owner = suite.client();
    const member = suite.client();
    await owner.registerAnon();
    await member.registerAnon();
    const ownerChat = await owner.createRoom('Комната без подсказок');
    const { code } = await owner.invite(ownerChat.id);
    const pending = await member.join(code);
    await owner.approve(pending.requestId);
    const memberChat = (await member.chats()).find(c => c.room_id === ownerChat.room_id);
    assert.ok(memberChat, 'участник вошёл в комнату');

    for (const [who, client, chat] of [['владелец', owner, ownerChat], ['участник', member, memberChat]]) {
        const history = await client.messages(chat.id);
        assert.ok(history.chat, `${who}: в ответе есть chat`);
        assert.strictEqual(history.chat.id, chat.id);
        assert.ok(!('quickReplies' in history.chat), `${who}: у комнаты не должно быть quickReplies`);
        assert.strictEqual(history.chat.is_bot, 0, who);
    }
    // У чата с ботом тех же аккаунтов поле есть.
    for (const client of [owner, member]) {
        const bot = await client.botChat();
        assert.deepStrictEqual((await client.messages(bot.id)).chat.quickReplies, QUICK_REPLIES);
    }
});

test('приветствие нового аккаунта заканчивается «Напишите „гайд“…»; у всех сроков жизни', async () => {
    for (const lifetime of ['tab', 'day', 'week']) {
        const client = suite.client();
        await client.registerAnon({ lifetime });
        const bot = await client.botChat();
        const { messages } = await client.messages(bot.id);
        assert.strictEqual(messages.length, 1, `${lifetime}: в чате с ботом только приветствие`);
        const [welcome] = messages;
        assert.strictEqual(welcome.sent, 0, lifetime);
        assert.ok(welcome.text.endsWith(WELCOME_CLOSING), `${lifetime}: приветствие должно заканчиваться «${WELCOME_CLOSING}»: ${JSON.stringify(welcome.text.slice(-80))}`);
        assert.ok(welcome.text.includes(DISCLAIMER), `${lifetime}: в приветствии нет дисклеймера`);
        assert.ok(!EMOJI.test(welcome.text), lifetime);
        assert.ok(welcome.text.length <= MAX_MESSAGE_LENGTH, lifetime);
    }
});

test('каждое ключевое слово и каждая кнопка дают ответ своей темы; темы различаются', async (t) => {
    // Тема = отдельный аккаунт со своим чатом: темы опрашиваются параллельно,
    // а внутри темы запросы идут по очереди (ответ приходит через ~0.6 с).
    const answers = {};
    await Promise.all(Object.entries(TOPICS).map(async ([topic, spec]) => {
        const session = await botSession(t);
        const byRequest = {};
        const requests = [...spec.keywords, ...(spec.buttonLabel ? [spec.buttonLabel] : [])];
        for (const request of requests) byRequest[request] = await ask(session, request);
        answers[topic] = byRequest;
    }));

    const textOf = {};
    for (const [topic, spec] of Object.entries(TOPICS)) {
        const byRequest = answers[topic];
        for (const [request, reply] of Object.entries(byRequest)) assertReplyShape(reply, `«${request}» (${topic})`);

        // Все запросы темы — один и тот же ответ.
        const texts = new Set(Object.values(byRequest).map(r => r.text));
        assert.strictEqual(texts.size, 1, `тема ${topic}: запросы ${Object.keys(byRequest).join(', ')} дали разные ответы:\n${[...texts].map(x => firstLine(x)).join('\n')}`);
        textOf[topic] = [...texts][0];

        // Подпись кнопки — ровно тот же ответ, что и на ключевые слова темы (проверено множеством выше).
        if (spec.buttonLabel) assert.ok(byRequest[spec.buttonLabel], `нет ответа на кнопку «${spec.buttonLabel}»`);
        if (spec.heading) assert.match(firstLine(textOf[topic]), spec.heading, `заголовок темы ${topic}`);
        // Содержательный ответ, а не заглушка: заголовок, тело и дисклеймер.
        assert.ok(textOf[topic].split('\n').length >= 4, `тема ${topic}: ответ слишком короткий`);
    }
    // Разные темы — разные ответы и разные заголовки.
    const texts = Object.values(textOf);
    assert.strictEqual(new Set(texts).size, texts.length, 'две разные темы дали один и тот же ответ');
    const headings = texts.map(firstLine);
    assert.strictEqual(new Set(headings).size, headings.length, `заголовки тем повторяются: ${headings.join(' | ')}`);
    // Обзор перечисляет остальные темы словами-ключами, которые ведут к ним.
    for (const word of ['приглашения', 'шифрование', 'исчезающие', 'аккаунт', 'файлы', 'приватность', 'уведомления']) {
        assert.ok(textOf.overview.toLowerCase().includes(word), `в обзоре нет темы «${word}»`);
    }
});

test('ключевые слова без учёта регистра, ё/е и знаков препинания; слово внутри фразы находится', async (t) => {
    const session = await botSession(t);
    const guide = await ask(session, 'гайд');
    const settings = await ask(session, 'тема');
    const disappearing = await ask(session, 'таймер');
    assert.notStrictEqual(guide.text, settings.text);
    const same = [
        ['ГАЙД', guide], ['Гайд!', guide], ['  гайд  ', guide], ['Помощь?', guide], ['HELP', guide], ['/Start', guide],
        ['Что умеешь?', guide], ['Всё, что умеешь', guide], ['мёню', guide],
        ['ТЕМА', settings], ['тёма', settings], ['Тема.', settings],
        ['Таймер!!!', disappearing], ['покажи таймер пожалуйста', disappearing],
    ];
    for (const [text, expected] of same) {
        const reply = await ask(session, text);
        assert.strictEqual(reply.text, expected.text, `«${text}» должно вести к той же теме`);
    }
});

test('неизвестный текст получает подсказку, а не тему; ответ без эмодзи, с дисклеймером', async (t) => {
    const session = await botSession(t);
    const topicTexts = new Set();
    for (const spec of Object.values(TOPICS)) topicTexts.add((await ask(session, spec.keywords[0])).text);
    assert.strictEqual(topicTexts.size, Object.keys(TOPICS).length);

    const unknown = [];
    for (const text of ['абракадабра', 'Привет, бот', 'qwerty 12345', '???', 'как дела у котика']) {
        const reply = await ask(session, text);
        assertReplyShape(reply, `неизвестное «${text}»`);
        assert.ok(reply.text.includes(UNKNOWN_HINT), `«${text}»: нет подсказки «${UNKNOWN_HINT}»:\n${reply.text}`);
        assert.ok(!topicTexts.has(reply.text), `«${text}»: неизвестный запрос получил ответ темы`);
        unknown.push(reply.text);
    }
    assert.strictEqual(new Set(unknown).size, 1, 'подсказка одна и та же');
});

test('ответы бота сохраняются в истории и доходят с правильными полями; чужой чат с ботом ничего не получает', async (t) => {
    const a = await botSession(t);
    const b = await botSession(t);
    const sent = await a.client.send(a.bot.id, 'гайд');
    const reply = await a.sock.waitFor('newMessage', m => m.chat_id === a.bot.id && m.sent === 0 && m.seq > sent.seq);
    const { messages } = await a.client.messages(a.bot.id);
    const stored = messages.find(m => m.id === reply.id);
    assert.ok(stored, 'ответ бота есть в истории');
    assert.strictEqual(stored.text, reply.text);
    // Порядок: приветствие, вопрос, ответ.
    assert.deepStrictEqual(messages.map(m => m.sent), [0, 1, 0]);
    assert.strictEqual(messages[1].text, 'гайд');
    // Ответ второму пользователю приходит его сокету; первый его не видит. Барьер вместо паузы:
    // после ответа второму спрашиваем бота ещё раз на первом сокете — события одного сокета идут по порядку.
    const other = await ask(b, 'аккаунт');
    assert.strictEqual(other.chat_id, b.bot.id);
    await ask(a, 'шифрование');
    assert.strictEqual(a.sock.collect('newMessage').filter(m => m.chat_id === b.bot.id).length, 0, 'чужой ответ бота не должен приходить');
    // В базе ответ лежит в чате владельца, не зашифрованный и не от другого пользователя.
    const row = (await suite.query('SELECT user_id, chat_id, sent FROM messages WHERE id = $1', [reply.id])).rows[0];
    assert.strictEqual(Number(row.chat_id), a.bot.id);
    assert.strictEqual(Number(row.user_id), a.client.user.id);
    assert.strictEqual(Number(row.sent), 0);
});
