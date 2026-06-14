require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

// --- PRISMA 7 DRIVER ADAPTER ---
const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
// ------------------------------------

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(cookieParser()); 

// --- CLOUD CORS POLICY ---
// 'origin: true' allows your Vercel frontend to connect dynamically
app.use(cors({
    origin: true, 
    credentials: true,               
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// --- SECURE AUTHENTICATION ENDPOINT ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body; 

    try {
        const user = await prisma.user.findUnique({ where: { email: username } });
        if (!user || !user.isActive) {
            return res.status(401).json({ error: 'Invalid credentials or account suspended.' });
        }

        const validPassword = await bcrypt.compare(password, user.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            process.env.JWT_SECRET || 'napstertec_master_key_998877', 
            { expiresIn: '8h' }
        );

        // CLOUD COOKIE PATCH: Cross-domain requires SameSite=None and Secure=true
        res.cookie('os_session', token, {
            httpOnly: true, 
            secure: true, 
            sameSite: 'none',
            path: '/', 
            maxAge: 8 * 60 * 60 * 1000 
        });

        res.json({ success: true, role: user.role, name: user.fullName });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Internal system failure.' });
    }
});

// --- SESSION VERIFICATION ENDPOINT ---
app.get('/api/auth/me', async (req, res) => {
    const token = req.cookies.os_session;
    if (!token) return res.status(401).json({ isAuthenticated: false });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'napstertec_master_key_998877');
        const user = await prisma.user.findUnique({ 
            where: { id: decoded.userId },
            select: { id: true, email: true, fullName: true, role: true, permissions: true }
        });
        
        if (!user || !user.isActive) return res.status(401).json({ isAuthenticated: false });
        
        res.json({ isAuthenticated: true, user });
    } catch (err) {
        res.status(401).json({ isAuthenticated: false });
    }
});

// --- LOGOUT ENDPOINT ---
app.post('/api/logout', (req, res) => {
    // Must mirror the cloud cookie settings to clear it successfully
    res.clearCookie('os_session', { path: '/', sameSite: 'none', secure: true });
    res.json({ success: true });
});

// --- HEALTH CHECK ENDPOINT (Useful for Render dashboard verification) ---
app.get('/', (req, res) => {
    res.json({ status: 'NapsterTec OS Engine is ONLINE', timestamp: new Date().toISOString() });
});

// --- INITIALIZE SERVER ---
app.listen(PORT, () => {
    console.log(`🚀 NapsterTec OS Engine live on port ${PORT}`);
});