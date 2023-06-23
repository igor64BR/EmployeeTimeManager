using Clocker.Entities.Users;
using System.Linq.Expressions;
using System.Text.Json.Serialization;

namespace Clocker.Controllers.VMs.QueryParameters
{
    public class UserListFilter
    {
        [JsonPropertyName("q")]
        public string Name { get; set; } = string.Empty;

        public bool FilterByNanme => !string.IsNullOrEmpty(Name);

        public Expression<Func<AppUser, bool>> Predicate => user =>
            (!FilterByNanme || user.Name.ToLower().Contains(Name.ToLower()));
    }
}
