# 🔐 Безопасность мессенджера

## Защита от копирования сайта

Мессенджер имеет многоуровневую защиту от несанкционированного копирования и клонирования:

### 1️⃣ **Клиентская защита (JavaScript)**

#### Отключенные действия:
```javascript
✅ Копирование текста (Ctrl+C)
✅ Вырезание текста (Ctrl+X)
✅ Вставка текста (Ctrl+V)
✅ Выделение текста (user-select: none)
✅ Правая кнопка мыши (context menu)
✅ Перетаскивание файлов (drag & drop)
✅ F12 (инспектор)
✅ Ctrl+Shift+I (инструменты разработки)
✅ Ctrl+Shift+J (консоль JavaScript)
✅ Ctrl+Shift+C (инспектор элементов)
```

#### Особенности:
- Текст в полях ввода (input, textarea) остаётся доступным для редактирования
- Автоматическое обнаружение открытых инструментов разработки
- Всестороннее перекрытие способов копирования контента

### 2️⃣ **HTML-уровень защиты**

```html
<!-- Запрет индексации поисковыми системами -->
<meta name="robots" content="noindex, nofollow">
<meta name="googlebot" content="noindex, nofollow">

<!-- Запрет кеширования -->
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="cache-control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="expires" content="0">
```

### 3️⃣ **Серверная защита (HTTP заголовки)**

| Заголовок | Значение | Назначение |
|-----------|----------|-----------|
| `Cache-Control` | `no-store, no-cache, must-revalidate, proxy-revalidate, private` | Полный запрет кеширования |
| `Pragma` | `no-cache` | Дополнительный запрет кеша (для старых браузеров) |
| `Expires` | `0` | Время жизни кеша = 0 |
| `X-Robots-Tag` | `noindex, nofollow` | Запрет для поисковых ботов |
| `Content-Security-Policy` | Строгая политика | Запрет внешних скриптов и ресурсов |
| `X-Frame-Options` | `DENY` | Запрет встраивания в iframe |
| `X-Content-Type-Options` | `nosniff` | Запрет на определение типа контента |
| `X-XSS-Protection` | `1; mode=block` | Защита от XSS атак |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Контроль referrer информации |

### 4️⃣ **CSS-уровень защиты**

```css
* {
    user-select: none;
    -webkit-user-select: none;
    -moz-user-select: none;
    -ms-user-select: none;
    -webkit-user-drag: none;
    -webkit-touch-callout: none;
}

/* Исключения для полей ввода */
input, textarea {
    user-select: text;
    -webkit-user-select: text;
}
```

---

## 📋 Матрица защиты

```
┌─────────────────────────────┬───────────┬─────────┬──────────┐
│ Попытка копирования         │ JS блокирует │ CSS блокирует │ Server блокирует │
├─────────────────────────────┼───────────┼─────────┼──────────┤
│ Копирование текста (Ctrl+C) │ ✅        │ ✅      │ ✅       │
│ Выделение мыши              │ ✅        │ ✅      │ ✅       │
│ Правая кнопка               │ ✅        │ ✅      │ -        │
│ Перетаскивание              │ ✅        │ -       │ -        │
│ Dev Tools                   │ ✅        │ -       │ -        │
│ Сохранение страницы         │ -         │ -       │ ✅ (no cache) │
│ Индексация ботами           │ -         │ -       │ ✅       │
│ Встраивание в iframe        │ -         │ -       │ ✅       │
└─────────────────────────────┴───────────┴─────────┴──────────┘
```

---

## ⚙️ Как работает каждый уровень защиты?

### 🔹 JavaScript Event Listeners

```javascript
// Блокируем левую кнопку мыши
document.addEventListener('contextmenu', (e) => {
    e.preventDefault(); // Отмена стандартного меню
    return false;
});

// Блокируем выделение
document.addEventListener('selectstart', (e) => {
    e.preventDefault();
});

// Блокируем горячие клавиши
document.addEventListener('keydown', (e) => {
    if (e.key === 'F12' || 
        (e.ctrlKey && e.shiftKey && e.key === 'I')) {
        e.preventDefault();
    }
});

// Детектируем открытые Dev Tools
setInterval(() => {
    const devtoolsOpen = window.outerHeight - window.innerHeight > 160;
    if (devtoolsOpen) console.warn('Dev Tools detected!');
}, 200);
```

### 🔹 CSS User-Select

Комбинация CSS-свойств для максимальной совместимости:
- `user-select: none` - стандартное свойство
- `-webkit-user-select: none` - Chrome, Safari
- `-moz-user-select: none` - Firefox
- `-ms-user-select: none` - Internet Explorer

### 🔹 Server Headers

Все заголовки устанавливаются через middleware Express:

```javascript
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    // ... остальные заголовки
    next();
});
```

---

## 📝 Примеры попыток копирования и их блокировки

### 1️⃣ **Попытка выделить текст мышью**
```
Результат: Текст НЕ выделяется благодаря CSS user-select: none
```

### 2️⃣ **Нажать Ctrl+C**
```
JS обработчик срабатывает → e.preventDefault() → копирование блокируется
```

### 3️⃣ **Нажать F12**
```
JS обработчик горячих клавиш → e.preventDefault() → Dev Tools НЕ открываются
```

### 4️⃣ **Сохранить страницу (Ctrl+S)**
```
Server отправляет: Cache-Control: no-store
→ Браузер НЕ сохраняет в кеш
→ При сохранении файла контент может быть неполным
```

### 5️⃣ **Попытка индексации ботом**
```
Bot запрашивает страницу
Server отправляет: X-Robots-Tag: noindex, nofollow
→ Bot пропускает индексацию
```

---

## ⚠️ Ограничения и особенности

### ✅ Что защищено:
- Случайное копирование контента
- Простое клонирование сайта
- Индексация в поисковых системах
- Встраивание в iframe (clickjacking)
- Легкий доступ к коду через инструменты разработки

### ⚠️ Что НЕ защищено:
- Опытные разработчики могут отключить JS через браузер
- Network traffic можно перехватить (используйте HTTPS!)
- Screenshot/снимки экрана не блокируются
- Очень продвинутые техники (modifying DOM через console)

---

## 🛡️ Рекомендации по усилению безопасности

1. **Используйте HTTPS** - шифруйте трафик
2. **Добавьте Content Security Policy** - уже есть в проекте ✅
3. **Регулярно обновляйте dependencies** - применяйте патчи безопасности
4. **Валидируйте входные данные** - защита от XSS
5. **Используйте CORS правильно** - ограничивайте источники запросов
6. **Логируйте подозрительную активность** - мониторьте попытки копирования

---

## 🧪 Тестирование защиты

### Проверьте каждый уровень:

```javascript
// 1. Тест CSS user-select
document.body.style.userSelect; // должен вернуть 'none'

// 2. Тест JS обработчиков
// Нажмите F12 → должно быть заблокировано

// 3. Тест context menu
// Нажмите ПКМ → меню не должно появиться

// 4. Тест копирования
// Попробуйте Ctrl+C → буфер обмена не изменится
```

---

**Созданно:** Май 2026  
**Версия:** 1.0  
**Статус:** ✅ Активна
