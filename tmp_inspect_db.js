const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('messenger.db');
db.serialize(() => {
  db.all('PRAGMA table_info(chats)', (err, rows) => {
    console.log('chats schema:', err ? err : rows);
  });
  db.all('PRAGMA table_info(rooms)', (err, rows) => {
    console.log('rooms schema:', err ? err : rows);
  });
  db.all('SELECT id, user_id, room_id, name FROM chats LIMIT 5', (err, rows) => {
    console.log('chat rows:', err ? err : rows);
  });
});
