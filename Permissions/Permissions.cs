namespace JWTAuth
{
    public static class AppPermissions
    {
        public const string ManageUsers = "manage_users";
        public const string ViewUsers = "view_users";
        public const string AssignRoles = "assign_roles";
        public const string ManageRoles = "manage_roles";
        public const string ViewReports = "view_reports";
        public const string CreateReports = "create_reports";

        public static readonly string[] All = new[]
        {
            ManageUsers,
            ViewUsers,
            AssignRoles,
            ManageRoles,
            ViewReports,
            CreateReports
        };
    }
}
