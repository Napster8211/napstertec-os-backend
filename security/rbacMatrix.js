// A central ledger defining exactly what each role can execute within the OS.
const RolePermissions = {
    EXECUTIVE_TECHNICAL_DIRECTOR: [
        "manage_users",
        "manage_projects",
        "deploy_projects",
        "manage_servers",
        "access_security_logs",
        "manage_leads",
        "delete_leads"
    ],
    BUSINESS_DEVELOPMENT: [
        "manage_leads",
        "view_projects",
        "create_proposals"
    ],
    MARKETING: [
        "view_leads",
        "manage_campaigns",
        "view_analytics"
    ],
    ENGINEER: [
        "view_projects",
        "update_project_status",
        "deploy_projects"
    ]
};

module.exports = { RolePermissions };