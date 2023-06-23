using Clocker.Entities.Users;

namespace Clocker.Controllers.VMs.Authorization
{
    public class UserInfo
    {
        public UserInfo(AppUser user, string role)
        {
            Id = user.Id;
            Name = user.Name;
            Email = user.Email;
            PhoneNumber = user.PhoneNumber;
            UserName = user.UserName;
            Address = user.Address;
            Permission = role;
        }

        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string UserName { get; set; }
        public string Address { get; set; }
        public string Permission { get; set; }
    }
}