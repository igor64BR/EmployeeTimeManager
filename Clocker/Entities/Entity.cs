namespace Clocker.Entities
{
    public class Entity<T> where T : Entity<T>, new()
    {
        public Entity() => Id = Guid.NewGuid();

        public Guid Id { get; set; }
    }
}
