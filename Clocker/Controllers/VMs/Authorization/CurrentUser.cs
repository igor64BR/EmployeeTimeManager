namespace Clocker.Controllers.VMs.Authorization
{
    public class CurrentUser
    {
        public UserInfo User { get; set; }
        public IList<string> Roles { get; internal set; }
    }
}
