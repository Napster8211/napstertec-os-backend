const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

/**
 * Enterprise Security Middleware
 * @param {string[]} requiredPermissions - Array of permission strings required to access the route
 */
const authorize = (requiredPermissions = []) => {
    return async (req, res, next) => {
        try {
            // 1. Extract Token
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1];
            if (!token) return res.status(401).json({ error: 'Access Denied. Telemetry link severed.' });

            // 2. Verify Cryptographic Signature
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // 3. Fetch live user data from PostgreSQL to ensure they aren't deactivated
            const user = await prisma.user.findUnique({
                where: { id: decoded.userId },
                select: { id: true, role: true, permissions: true, isActive: true }
            });

            if (!user || !user.isActive) {
                return res.status(403).json({ error: 'User account terminated or suspended.' });
            }

            // 4. Mathematical RBAC Check
            if (requiredPermissions.length > 0) {
                const hasPermission = requiredPermissions.every(permission => 
                    user.permissions.includes(permission)
                );

                if (!hasPermission) {
                    // Automatically log the unauthorized attempt in the Audit Ledger
                    await prisma.auditLog.create({
                        data: {
                            action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
                            userId: user.id,
                            metadata: { route: req.originalUrl, required: requiredPermissions }
                        }
                    });
                    
                    return res.status(403).json({ error: 'Clearance level insufficient for this operation.' });
                }
            }

            // 5. Attach secure user payload to the request and proceed
            req.user = user;
            next();
            
        } catch (error) {
            return res.status(403).json({ error: 'Invalid or expired authentication token.' });
        }
    };
};

module.exports = authorize;