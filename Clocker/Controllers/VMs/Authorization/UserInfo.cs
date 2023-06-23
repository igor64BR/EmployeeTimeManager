using Clocker.Entities.Users;

namespace Clocker.Controllers.VMs.Authorization
{
    public class UserInfo
    {
        public UserInfo(AppUser user)
        {
            Id = user.Id;
            Name = user.Name;
            Email = user.Email;
            PhoneNumber = user.PhoneNumber;
            UserName = user.UserName;
            Address = user.Address;
        }

        public Guid Id { get; internal set; }
        public string Name { get; internal set; }
        public string Email { get; internal set; }
        public string PhoneNumber { get; internal set; }
        public string UserName { get; internal set; }
        public string Address { get; internal set; }
    }
}