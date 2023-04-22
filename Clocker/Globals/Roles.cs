namespace Clocker.Globals
{
    public static class Roles
    {
        public const string Admin = "admin";
        public const string Gerente = "gerente";
        public const string Vendedor = "vendedor";

        public static readonly List<string> AllRoles = new()
        {
            Admin,
            Gerente,
            Vendedor
        };
    }
}
