const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./filesharing.db', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Database connected');
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                email TEXT UNIQUE,
                user_type TEXT
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                filepath TEXT,
                uploader_id INTEGER,
                FOREIGN KEY (uploader_id) REFERENCES users (id)
            )
        `);
    }
});

module.exports = db;
