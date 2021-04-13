const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv-flow');
const jwt = require('jsonwebtoken');
const users = require('./users');
let tasks = require('./tasks');

dotenv.config();
const app = express();

const tokenBlackList = [];

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT");
  next();
});
app.use(bodyParser.json());
app.use((req, res, next) => {
    if (req.headers.authorization) {
        const token = req.headers.authorization.split(' ')[1];
        jwt.verify(
            token,
            process.env.TOKEN_KEY,
            (err, payload) => {
                if (err || tokenBlackList.find(v => v === token)) {
                    next();
                } else if (payload) {
                    const user = users.find(({ id }) => payload.id === id);
                    req.user = user;
                    req.token = token;
                    next();
                }
            }
        );
    }

    next();
});

app.post(`/api/login`, (req, res) => {
    const user = users.find(({ login, password }) => (login === req.body.login) && (password === req.body.password));
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json({
        id: user.id,
        login: user.login,
        token: jwt.sign({ id: user.id }, process.env.TOKEN_KEY),
    });
});

app.post(`/api/logout`, (req, res) => {
    if (!req.user) {
        return res.status(404).json({ message: 'User not found' });
    }
    tokenBlackList.push(req.token);
    return res.status(200).json({ message: 'Ok' });
});

app.get('/api/user', (req, res) => {
    if (req.user) {
        return res.status(200).json(req.user);
    }
    return res.status(401).json({ message: 'Not authorized' });
});

app.get('/api/tasks', (req, res) => {
    if (req.user) {
        return res.status(200).json(tasks.filter(v => v.userId === req.user.id));
    }
    return res.status(401).json({ message: 'Not authorized' });
});

app.post('/api/tasks', (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Not authorized' });
    }
    if (!req.body.title) {
        return res.status(400).json({ message: 'Not valid' });
    }
    const newId = 1 + tasks.reduce((acc, v) => Math.max(v.id, acc), 0);
    tasks.push({ id: newId, userId: req.user.id, title: req.body.title, isDone: false });
    return res.status(200).json({ message: 'Ok' });
});

app.put('/api/tasks/:id', (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Not authorized' });
    }
    if (!req.body.title) {
        return res.status(400).json({ message: 'Not valid' });
    }
    const task = tasks.find(v => v.id === +req.params.id);
    if (!task) {
        return res.status(404).json({ message: 'Not found' });
    }
    if (task.userId !== req.user.id) {
        return res.status(403).json({ message: 'Access Forbidden' });
    }
    task.title = req.body.title;
    task.isDone = !!req.body.isDone;
    return res.status(200).json({ message: 'Ok' });
});

app.delete('/api/tasks/:id', (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Not authorized' });
    }
    const task = tasks.find(v => v.id === +req.params.id);
    if (!task) {
        return res.status(404).json({ message: 'Not found' });
    }
    if (task.userId !== req.user.id) {
        return res.status(403).json({ message: 'Access Forbidden' });
    }
    tasks = tasks.filter(v => v.id !== +req.params.id);
    return res.status(200).json({ message: 'Ok' });
});

const port = process.env.PORT || 8888;
const host = process.env.HOST || '127.0.0.1';

app.listen(port, host, () => console.log(`Server is listening at http://${host}:${port}`));
