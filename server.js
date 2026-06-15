require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());

// Because we aren't using cookies, CORS is much simpler and impossible to block
app.use(cors({
    origin: '*', // Accept traffic from absolutely anywhere
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// --- SECURE LOGIN: Issues Bearer Token ---
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

        // Send token DIRECTLY in the JSON payload, bypass cookies entirely
        res.json({ success: true, token, role: user.role, name: user.fullName });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Internal system failure.' });
    }
});

// --- SESSION VERIFICATION: Reads Bearer Token ---
app.get('/api/auth/me', async (req, res) => {
    // Extract token from the Authorization header (Format: "Bearer <token>")
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ isAuthenticated: false });
    }

    const token = authHeader.split(' ')[1];

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

app.listen(PORT, () => {
    console.log(`🚀 NapsterTec OS Engine live on port ${PORT}`);
});