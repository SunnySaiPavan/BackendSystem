const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const db = require('./database');

const app = express();
app.use(express.json());

// Secret Key for JWT
const SECRET_KEY = "your_secret_key";

// File Storage Configuration
const upload = multer({
    dest: './uploads/',
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/vnd.openxmlformats-officedocument.presentationml.presentation',
                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
        if (!allowedTypes.includes(file.mimetype)) {
            cb(new Error('Invalid file type'));
        } else {
            cb(null, true);
        }
    }
});

// Signup API
app.post('/signup', async (req, res) => {
    const { username, password, email, userType } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = uuidv4();
    const emailVerified = false; // Mock email verification

    db.run(`INSERT INTO users (username, password, email, user_type) VALUES (?, ?, ?, ?)`,
        [username, hashedPassword, email, userType],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error signing up user' });
            }
            res.status(201).json({ message: 'User signed up successfully' });
        });
});

// Login API
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, userType: user.user_type }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// File Upload API
app.post('/upload', upload.single('file'), (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, SECRET_KEY);

    if (decoded.userType !== 'ops_user') {
        return res.status(403).json({ message: 'Only Ops Users can upload files' });
    }

    const { filename, path } = req.file;
    db.run(`INSERT INTO files (filename, filepath, uploader_id) VALUES (?, ?, ?)`,
        [filename, path, decoded.id],
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error uploading file' });
            }
            res.json({ message: 'File uploaded successfully' });
        });
});

// List Files API
app.get('/files', (req, res) => {
    db.all(`SELECT * FROM files`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching files' });
        }
        res.json(rows);
    });
});

// File Download API
app.get('/download/:fileId', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, SECRET_KEY);

    if (decoded.userType !== 'client_user') {
        return res.status(403).json({ message: 'Only Client Users can download files' });
    }

    const fileId = req.params.fileId;
    db.get(`SELECT * FROM files WHERE id = ?`, [fileId], (err, file) => {
        if (err || !file) {
            return res.status(404).json({ message: 'File not found' });
        }
        const downloadLink = `http://localhost:3000/uploads/${file.filepath}`;
        res.json({ message: 'success', 'download-link': downloadLink });
    });
});

// Start the Server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
