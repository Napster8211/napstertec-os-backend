require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

// --- PRISMA 7 DRIVER ADAPTER ---
const { Pool } = require('pg');
const { PrismaPg } = require('@prisma/adapter-pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
// ------------------------------------

async function main() {
    console.log("Initiating Genesis Sequence for Cloud Database...");

    // 1. Hash your master password
    const rawPassword = "secure_password_2026"; 
    const hashedPassword = await bcrypt.hash(rawPassword, 10);

    // 2. Inject the Executive Technical Director into the database
    const cto = await prisma.user.upsert({
        where: { email: 'hello@napstertec.com' },
        update: {},
        create: {
            email: 'hello@napstertec.com',
            passwordHash: hashedPassword,
            fullName: 'Napster',
            role: 'EXECUTIVE_TECHNICAL_DIRECTOR',
            permissions: [
                "manage_users",
                "manage_projects",
                "deploy_projects",
                "manage_servers",
                "access_security_logs",
                "manage_leads",
                "delete_leads"
            ],
            isActive: true,
        },
    });

    console.log(`✅ System Override Complete. Master Account created for: ${cto.email}`);
}

main()
    .catch((e) => {
        console.error("❌ Genesis Sequence Failed:");
        console.error(e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });