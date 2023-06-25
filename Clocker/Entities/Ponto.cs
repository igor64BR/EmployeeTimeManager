using Clocker.Entities.Users;
using Clocker.Globals;

namespace Clocker.Entities
{
    public class Ponto : Entity<Ponto>
    {
        public DateTime Date { get; set; }
        public TipoPonto Type { get; set; }

        public Guid UserId { get; set; }
        public AppUser? User { get; set; }
    }
}
