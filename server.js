require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { dbGet, dbAll, dbRun } = require('./database');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());

// Хранилище активных WebSocket соединений
const clients = new Map(); // phone -> ws

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// REST API Endpoints

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password required' });
    }

    // Проверка формата номера
    const phoneRegex = /^\+7\d{10}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ error: 'Invalid phone format. Use +7XXXXXXXXXX' });
    }

    // Проверка существующего пользователя
    const existingUser = await dbGet('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Хеширование пароля
    const passwordHash = await bcrypt.hash(password, 10);

    // Создание пользователя
    const result = await dbRun(
      'INSERT INTO users (phone, password_hash) VALUES (?, ?)',
      [phone, passwordHash]
    );

    // Генерация токена
    const token = jwt.sign({ userId: result.id, phone }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, phone });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Вход
app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password required' });
    }

    // Поиск пользователя
    const user = await dbGet('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Генерация токена
    const token = jwt.sign({ userId: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, phone: user.phone });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Добавление контакта
app.post('/api/check-user', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({ error: 'Phone required' });
    }

    // Проверка существования пользователя
    const user = await dbGet('SELECT id FROM users WHERE phone = ?', [phone]);
    
    if (user) {
      res.json({ exists: true, phone });
    } else {
      res.json({ exists: false, phone });
    }
  } catch (error) {
    console.error('Check user error:', error);
    res.status(500).json({ error: 'Failed to check user' });
  }
});

app.get('/healthz', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ========================================
// PING-PONG для поддержания соединения
// ========================================

// Интервал отправки ping (25 секунд - безопасно для Render)
const PING_INTERVAL = 25000;

// Таймаут для pong ответа (10 секунд)
const PONG_TIMEOUT = 10000;

// Периодическая отправка ping всем клиентам
const pingInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      // Проверяем, получили ли мы pong на предыдущий ping
      if (ws.isAlive === false) {
        console.log('Client not responding to ping, terminating connection');
        return ws.terminate();
      }

      // Помечаем клиента как "ожидающего pong"
      ws.isAlive = false;
      ws.ping();
      
      console.log('Ping sent to client');
    }
  });
}, PING_INTERVAL);

// Очистка интервала при остановке сервера
wss.on('close', () => {
  clearInterval(pingInterval);
});

// ========================================
// WebSocket сигнализация для WebRTC
// ========================================

wss.on('connection', (ws) => {
  let userPhone = null;

  // Изначально клиент считается живым
  ws.isAlive = true;

  // Обработка pong ответа от клиента
  ws.on('pong', () => {
    ws.isAlive = true;
    console.log('Pong received from client');
  });

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log('Received WebSocket message:', data.type, 'from:', data.from || data.phone, 'to:', data.to || 'N/A');

      switch (data.type) {
        case 'register':
          // Регистрация клиента в WebSocket
          userPhone = data.phone;
          clients.set(userPhone, ws);
          console.log(`Client registered: ${userPhone}`);
          console.log('Current active clients:', Array.from(clients.keys()));
          ws.send(JSON.stringify({ type: 'registered', phone: userPhone }));
          break;

        case 'call':
        case 'offer':
          // Инициация звонка
          const targetWs = clients.get(data.to);
          console.log('Processing call request:', {
            from: data.from,
            to: data.to,
            targetFound: !!targetWs,
            targetState: targetWs ? targetWs.readyState : 'N/A'
          });
          if (targetWs && targetWs.readyState === WebSocket.OPEN) {
            // Отправляем предложение звонка получателю
            targetWs.send(JSON.stringify({
              type: 'offer',
              from: data.from,
              offer: data.offer
            }));
            // Отправляем подтверждение звонящему
            ws.send(JSON.stringify({
              type: 'call-progress',
              to: data.to
            }));
            console.log(`Call offered from ${data.from} to ${data.to}`);
          } else {
            console.log('Call failed - target user offline or not found:', data.to);
            ws.send(JSON.stringify({
              type: 'call-failed',
              reason: 'User offline or not registered'
            }));
          }
          break;

        case 'answer':
          // Ответ на звонок
          const callerWs = clients.get(data.to);
          if (callerWs && callerWs.readyState === WebSocket.OPEN) {
            callerWs.send(JSON.stringify({
              type: 'answer',
              from: data.from,
              answer: data.answer
            }));
            console.log(`Call answered: ${data.from} -> ${data.to}`);
          }
          break;

        case 'ice-candidate':
          // Обмен ICE кандидатами
          const recipientWs = clients.get(data.to);
          if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
            recipientWs.send(JSON.stringify({
              type: 'ice-candidate',
              from: data.from,
              candidate: data.candidate
            }));
          }
          break;

        case 'end-call':
          // Завершение звонка
          const endCallWs = clients.get(data.to);
          if (endCallWs && endCallWs.readyState === WebSocket.OPEN) {
            endCallWs.send(JSON.stringify({
              type: 'call-ended',
              from: data.from
            }));
          }
          break;

        // Ответ на ping от клиента (если клиент тоже отправляет ping)
        case 'ping':
          ws.send(JSON.stringify({ type: 'pong' }));
          break;
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });

  ws.on('close', () => {
    if (userPhone) {
      clients.delete(userPhone);
      console.log(`Client disconnected: ${userPhone}`);
    }
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Запуск сервера
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server ready`);
  console.log(`Ping-pong keepalive enabled (interval: ${PING_INTERVAL}ms)`);
});

