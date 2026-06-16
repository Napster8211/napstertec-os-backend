require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// --- PRISMA 7 CLOUD ADAPTER SETUP ---
const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('@prisma/client');

const connectionString = process.env.DATABASE_URL;
const pool = new Pool({ connectionString });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'napstertec_master_key_998877';

// --- SYSTEM MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// ==========================================
// --- MODULE 1: AUTHENTICATION & SECURITY ---
// ==========================================

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });
        
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        if (!user.isActive) {
            return res.status(403).json({ error: "Account suspended. Contact system administrator." });
        }

        const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ success: true, token, role: user.role });
    } catch (err) {
        console.error("[BACKEND] ❌ Login Error:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/api/auth/me', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await prisma.user.findUnique({
            where: { id: decoded.userId },
            select: { id: true, fullName: true, email: true, role: true, permissions: true }
        });

        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ success: true, user });
    } catch (err) {
        res.status(401).json({ error: "Invalid or expired token" });
    }
});

// ==========================================
// --- MODULE 2: TEAM & PROVISIONING MATRIX ---
// ==========================================

// Public Route: Read-only bridge for the visitor website
app.get('/api/public/team', async (req, res) => {
    try {
        const team = await prisma.user.findMany({
            where: { isActive: true },
            select: { id: true, fullName: true, role: true, bio: true, profileImage: true },
            orderBy: { createdAt: 'asc' }
        });
        res.json({ success: true, team });
    } catch (err) {
        console.error("[BACKEND] ❌ Public Team Route Error:", err.message);
        res.status(500).json({ error: "Failed to load public team data." });
    }
});

// Admin Route: Secure Team Matrix fetch
app.get('/api/team', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') {
            return res.status(403).json({ error: "Insufficient clearance level." });
        }

        const team = await prisma.user.findMany({
            select: { id: true, fullName: true, email: true, role: true, permissions: true, isActive: true, createdAt: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json({ success: true, team });
    } catch (err) {
        console.error("[BACKEND] ❌ Team Matrix Error:", err.message);
        res.status(500).json({ error: "Failed to retrieve team data." });
    }
});

// Admin Route: Upgraded Provisioning (Accepts Bio & Image)
app.post('/api/team/provision', async (req, res) => {
    console.log("[BACKEND] ⚡ Provisioning new personnel with extended data...");
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') {
            return res.status(403).json({ error: "Insufficient clearance." });
        }

        const { fullName, email, password, role, bio, profileImage } = req.body;

        if (!fullName || !email || !password || !role) {
            return res.status(400).json({ error: "Missing required personnel data." });
        }

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ error: "Email already registered in system." });

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await prisma.user.create({
            data: {
                fullName,
                email,
                passwordHash,
                role,
                bio: bio || null,
                profileImage: profileImage || null,
                permissions: role === 'BUSINESS_DEVELOPMENT' ? ['manage_leads'] : ['view_projects']
            },
            select: { id: true, fullName: true, email: true, role: true, isActive: true, createdAt: true }
        });

        res.json({ success: true, user: newUser });
    } catch (err) {
        console.error("[BACKEND] ❌ Provisioning Error:", err.message);
        res.status(500).json({ error: "Failed to provision personnel." });
    }
});

// ==========================================
// --- MODULE 3: CRM LEADS PIPELINE ---
// ==========================================

app.get('/api/leads', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        
        const leads = await prisma.lead.findMany({
            orderBy: { updatedAt: 'desc' },
            include: { assignedTo: { select: { fullName: true } } } 
        });
        res.json({ success: true, leads });
    } catch (err) {
        console.error("[BACKEND] ❌ CRM Fetch Error:", err.message);
        res.status(500).json({ error: "Failed to load CRM data." });
    }
});

app.post('/api/leads', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        
        const { companyName, contactPerson, email, phone } = req.body;
        if (!companyName || !email) return res.status(400).json({ error: "Company Name and Email are required." });

        const newLead = await prisma.lead.create({
            data: { companyName, contactPerson, email, phone, status: 'NEW_LEAD' }
        });
        res.json({ success: true, lead: newLead });
    } catch (err) {
        console.error("[BACKEND] ❌ CRM Create Error:", err.message);
        res.status(500).json({ error: "Failed to create new lead." });
    }
});

app.patch('/api/leads/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        
        const { id } = req.params;
        const { status } = req.body;

        const updatedLead = await prisma.lead.update({
            where: { id },
            data: { status }
        });
        res.json({ success: true, lead: updatedLead });
    } catch (err) {
        console.error("[BACKEND] ❌ CRM Update Error:", err.message);
        res.status(500).json({ error: "Failed to update lead status." });
    }
});

// --- SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`[SYSTEM] 🚀 NapsterTec OS Backend Online. Port: ${PORT}`);
});