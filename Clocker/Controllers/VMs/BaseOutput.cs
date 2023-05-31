namespace Clocker.Controllers.VMs
{
    public class BaseOutput
    {
        public BaseOutput() => Errors = new List<string>();

        public BaseOutput(string error) => Errors = new List<string> { error };

        public BaseOutput(object data) : this() => Data = data;

        public BaseOutput(IEnumerable<string> errors) => Errors = errors;

        public object? Data { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}
