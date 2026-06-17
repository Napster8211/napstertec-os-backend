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

app.post('/api/team/provision', async (req, res) => {
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
                fullName, email, passwordHash, role,
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

app.patch('/api/team/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') return res.status(403).json({ error: "Insufficient clearance." });

        const { id } = req.params;
        const { fullName, role, bio, profileImage, isActive } = req.body;

        const updatedUser = await prisma.user.update({
            where: { id },
            data: { 
                fullName, role, bio, profileImage, isActive,
                permissions: role === 'BUSINESS_DEVELOPMENT' ? ['manage_leads'] : ['view_projects']
            }
        });

        res.json({ success: true, user: updatedUser });
    } catch (err) {
        console.error("[BACKEND] ❌ Update Error:", err.message);
        res.status(500).json({ error: "Failed to update personnel dossier." });
    }
});

app.delete('/api/team/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'EXECUTIVE_TECHNICAL_DIRECTOR') return res.status(403).json({ error: "Insufficient clearance." });

        const { id } = req.params;
        await prisma.user.delete({ where: { id } });

        res.json({ success: true });
    } catch (err) {
        console.error("[BACKEND] ❌ Delete Error:", err.message);
        res.status(500).json({ error: "Failed to revoke keycard." });
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

// ==========================================
// --- MODULE 4: PROJECT EXECUTION MATRIX ---
// ==========================================

app.get('/api/projects', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        const projects = await prisma.project.findMany({
            orderBy: { updatedAt: 'desc' },
            include: { 
                lead: { select: { companyName: true, contactPerson: true } },
                team: { select: { id: true, fullName: true, role: true, profileImage: true } } 
            }
        });
        res.json({ success: true, projects });
    } catch (err) {
        console.error("[BACKEND] ❌ Project Fetch Error:", err.message);
        res.status(500).json({ error: "Failed to load project matrix." });
    }
});

app.post('/api/projects', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        const { title, description, leadId, deadline, teamIds, progress } = req.body;
        if (!title || !description) return res.status(400).json({ error: "Project Title and Description are required." });

        const newProject = await prisma.project.create({
            data: { 
                title, description,
                progress: progress || 0,
                deadline: deadline ? new Date(deadline) : null,
                lead: leadId ? { connect: { id: leadId } } : undefined,
                team: teamIds && teamIds.length > 0 ? { connect: teamIds.map(id => ({ id })) } : undefined
            }
        });
        res.json({ success: true, project: newProject });
    } catch (err) {
        console.error("[BACKEND] ❌ Project Create Error:", err.message);
        res.status(500).json({ error: "Failed to initialize project." });
    }
});

app.patch('/api/projects/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
        const { id } = req.params;
        const { status, repoUrl, deploymentUrl, progress } = req.body;

        const updatedProject = await prisma.project.update({
            where: { id },
            data: { status, repoUrl, deploymentUrl, progress }
        });
        res.json({ success: true, project: updatedProject });
    } catch (err) {
        console.error("[BACKEND] ❌ Project Update Error:", err.message);
        res.status(500).json({ error: "Failed to update project data." });
    }
});

// ==========================================
// --- MODULE 5: SECURE CLIENT PORTAL (UPGRADED) ---
// ==========================================

app.get('/api/client/project', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
        if (!user || user.role !== 'CLIENT') {
            return res.status(403).json({ error: "Restricted: Client clearance required." });
        }

        // UPGRADE: Fetch the project AND all the new enterprise relational data
        const project = await prisma.project.findFirst({
            where: { lead: { email: user.email } },
            include: { 
                lead: { select: { companyName: true, contactPerson: true } },
                team: { select: { fullName: true, role: true, profileImage: true } },
                activities: { orderBy: { timestamp: 'desc' } },
                documents: { orderBy: { createdAt: 'desc' }, include: { uploadedBy: { select: { fullName: true } } } },
                invoices: { orderBy: { issueDate: 'desc' } },
                milestones: { orderBy: { dueDate: 'asc' } },
                messages: { orderBy: { createdAt: 'asc' }, include: { sender: { select: { fullName: true, role: true } } } }
            }
        });

        res.json({ success: true, project });
    } catch (err) {
        console.error("[BACKEND] ❌ Client Portal Error:", err.message);
        res.status(500).json({ error: "Failed to load client telemetry." });
    }
});

// ==========================================
// --- MODULE 6: SUPPORT MATRIX (TICKETING) ---
// ==========================================

app.post('/api/client/tickets', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { subject, description, priority, projectId } = req.body;
        if (!subject || !description || !projectId) return res.status(400).json({ error: "Missing required ticket data." });

        const newTicket = await prisma.ticket.create({
            data: {
                subject, description, priority: priority || 'NORMAL',
                client: { connect: { id: decoded.userId } },
                project: { connect: { id: projectId } }
            }
        });

        res.json({ success: true, ticket: newTicket });
    } catch (err) {
        console.error("[BACKEND] ❌ Ticket Creation Error:", err.message);
        res.status(500).json({ error: "Failed to submit support ticket." });
    }
});

app.get('/api/tickets', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'CLIENT') return res.status(403).json({ error: "Restricted clearance." });

        const tickets = await prisma.ticket.findMany({
            orderBy: { createdAt: 'desc' },
            include: {
                client: { select: { fullName: true, email: true } },
                project: { select: { title: true } }
            }
        });

        res.json({ success: true, tickets });
    } catch (err) {
        console.error("[BACKEND] ❌ Ticket Fetch Error:", err.message);
        res.status(500).json({ error: "Failed to load support matrix." });
    }
});

app.patch('/api/tickets/:id', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role === 'CLIENT') return res.status(403).json({ error: "Restricted clearance." });

        const { id } = req.params;
        const { status } = req.body;

        const updatedTicket = await prisma.ticket.update({
            where: { id },
            data: { status }
        });
        res.json({ success: true, ticket: updatedTicket });
    } catch (err) {
        console.error("[BACKEND] ❌ Ticket Update Error:", err.message);
        res.status(500).json({ error: "Failed to update support ticket." });
    }
});

// ==========================================
// --- MODULE 7: ENTERPRISE DATA (MESSAGES) ---
// ==========================================

app.post('/api/client/messages', async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: "Unauthorized access" });

    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { content, projectId } = req.body;
        if (!content || !projectId) return res.status(400).json({ error: "Missing message content." });

        const newMessage = await prisma.message.create({
            data: {
                content,
                project: { connect: { id: projectId } },
                sender: { connect: { id: decoded.userId } }
            },
            include: { sender: { select: { fullName: true, role: true } } }
        });

        res.json({ success: true, message: newMessage });
    } catch (err) {
        console.error("[BACKEND] ❌ Message Creation Error:", err.message);
        res.status(500).json({ error: "Failed to send message." });
    }
});

// --- SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`[SYSTEM] 🚀 NapsterTec OS Backend Online. Port: ${PORT}`);
});