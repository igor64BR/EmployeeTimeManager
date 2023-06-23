namespace Clocker.Controllers.VMs.Authorization
{
    public class FormUserInput
    {
        // PUT User by Id
        public string UserName { get; set; } = string.Empty;

        // PUT CurrentUser
        public string CurrentPassword { get; set; } = string.Empty;

        // Shared
        public string Email { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public string PhoneNumber { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string PermissionName { get; set; } = string.Empty;
        public bool PasswordHasChanged { get; set; }
    }
}
