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

// Accept traffic from your Vercel frontend natively
app.use(cors({
    origin: '*', 
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
            return res.status(401).json({ error: 'Invalid credentials.' });
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

        // Send token DIRECTLY to frontend memory, bypassing cookies
        res.json({ success: true, token, role: user.role, name: user.fullName });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Internal system failure.' });
    }
});

// --- SESSION VERIFICATION WITH BUG CATCHER ---
app.get('/api/auth/me', async (req, res) => {
    console.log("[BACKEND CATCHER] 🔍 Incoming request to /api/auth/me");
    
    const authHeader = req.headers.authorization;
    console.log("[BACKEND CATCHER] 🔑 Raw Auth Header received:", authHeader ? "YES (hidden for security)" : "NONE");

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error("[BACKEND CATCHER] ❌ FAILED: No valid Bearer token provided in header.");
        return res.status(401).json({ isAuthenticated: false, reason: "Missing token" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'napstertec_master_key_998877');
        console.log("[BACKEND CATCHER] ✅ Token successfully decoded for User ID:", decoded.userId);
        
        // The one and only user declaration
        const user = await prisma.user.findUnique({ 
            where: { id: decoded.userId },
            select: { 
                id: true, 
                email: true, 
                fullName: true, 
                role: true, 
                permissions: true,
                isActive: true // <-- The missing key that caused the rejection
            }
        });
        
        if (!user || !user.isActive) {
            console.error("[BACKEND CATCHER] ❌ FAILED: User not found in database or inactive.");
            return res.status(401).json({ isAuthenticated: false, reason: "User invalid" });
        }
        
        console.log("[BACKEND CATCHER] 🟢 SUCCESS: Access granted to", user.email);
        res.json({ isAuthenticated: true, user });
    } catch (err) {
        console.error("[BACKEND CATCHER] ❌ FAILED: JWT Verification Error:", err.message);
        res.status(401).json({ isAuthenticated: false, reason: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 NapsterTec OS Engine live on port ${PORT}`);
});

// --- TEAM MATRIX: RBAC PROTECTED ROUTE ---
app.get('/api/team', async (req, res) => {
    console.log("[BACKEND] 🔍 Fetching Team Matrix...");
    
    // 1. Check for the digital keycard
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Unauthorized access" });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 2. Decode the keycard to see WHO is asking
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'napstertec_master_key_998877');
        
        // 3. RBAC ENFORCEMENT: Only the Executive Technical Director can view the team
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') {
            console.error(`[SECURITY] 🚨 Access Denied. User ${decoded.userId} attempted to view Team Matrix without Executive clearance.`);
            return res.status(403).json({ error: "Insufficient clearance level." });
        }

        // 4. Fetch the team from Supabase (excluding sensitive password hashes)
        const team = await prisma.user.findMany({
            select: {
                id: true,
                fullName: true,
                email: true,
                role: true,
                permissions: true,
                isActive: true,
                createdAt: true
            },
            orderBy: { createdAt: 'desc' }
        });

        res.json({ success: true, team });
    } catch (err) {
        console.error("[BACKEND] ❌ Team Matrix Error:", err.message);
        res.status(500).json({ error: "Failed to retrieve team data." });
    }
});

// --- PROVISION NEW USER: RBAC PROTECTED ---
app.post('/api/team/provision', async (req, res) => {
    console.log("[BACKEND] ⚡ Provisioning new personnel...");
    
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Unauthorized access" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'napstertec_master_key_998877');
        
        // Strict RBAC Enforcement
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') {
            return res.status(403).json({ error: "Insufficient clearance. Only Directors can provision users." });
        }

        const { fullName, email, password, role } = req.body;

        if (!fullName || !email || !password || !role) {
            return res.status(400).json({ error: "Missing required personnel data." });
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: "Email already registered in system." });
        }

        // Encrypt the password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Provision the user in Supabase
        const newUser = await prisma.user.create({
            data: {
                fullName,
                email,
                passwordHash,
                role,
                permissions: role === 'BUSINESS_DEVELOPMENT' ? ['manage_leads'] : ['view_projects'] // Basic default permissions
            },
            select: { id: true, fullName: true, email: true, role: true, isActive: true, createdAt: true }
        });

        res.json({ success: true, user: newUser });
    } catch (err) {
        console.error("[BACKEND] ❌ Provisioning Error:", err.message);
        res.status(500).json({ error: "Failed to provision personnel." });
    }
});

// --- PUBLIC ROUTE: VISITOR TEAM PAGE ---
// Notice there is NO token verification here. This is open to the public internet.
app.get('/api/public/team', async (req, res) => {
    try {
        const team = await prisma.user.findMany({
            where: { isActive: true }, // Only show active employees
            select: {
                id: true,
                fullName: true,
                role: true,
                bio: true,
                profileImage: true
            },
            orderBy: { createdAt: 'asc' } // Keeps the founders at the top
        });

        res.json({ success: true, team });
    } catch (err) {
        console.error("[BACKEND] ❌ Public Team Route Error:", err.message);
        res.status(500).json({ error: "Failed to load public team data." });
    }
});