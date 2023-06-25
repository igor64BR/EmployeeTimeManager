using Clocker.Globals;
using Microsoft.AspNetCore.Identity;

namespace Clocker.Entities.Users
{
    public class AppUser : IdentityUser<Guid>
    {
        public AppUser()
        {
            Name = string.Empty;
            Address = string.Empty;
        }

        public string Name { get; internal set; }
        public string Address { get; set; }

        public ICollection<Ponto> Pontos { get; set; }

        public int GetHourCredits()
        {
            var totalHours = 0;
            var totalExpected = 0;

            foreach (var group in Pontos.GroupBy(x => x.Date))
            {
                totalHours += GetDayHours(group);
                totalExpected += 8;
            }

            return totalHours - totalExpected;
        }

        public static int GetDayHours(IGrouping<DateTime, Ponto> pontos)
        {
            var startTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Entrada);
            var lunchTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Almoco);

            var hasWorkedToday = startTime != null && lunchTime != null;

            if (!hasWorkedToday)
                return 0;

            var timeBeforeLunch = lunchTime!.Date.Hour - startTime!.Date.Hour;

            var lunchEnd = pontos.FirstOrDefault(x => x.Type == TipoPonto.Entrada);
            var endTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Almoco);

            if (lunchEnd == null || endTime == null)
                return timeBeforeLunch!;

            var timeAfterLunch = endTime.Date.Hour - lunchEnd.Date.Hour;

            return timeBeforeLunch + timeAfterLunch;
        }

        public int GetDayHours(DateTime date)
        {
            var pontos = Pontos.Where(x => x.Date.Date == date.Date);

            var startTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Entrada);
            var lunchTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Almoco);

            var hasWorkedToday = startTime != null && lunchTime != null;

            if (!hasWorkedToday)
                return 0;

            var timeBeforeLunch = lunchTime!.Date.Hour - startTime!.Date.Hour;

            var lunchEnd = pontos.FirstOrDefault(x => x.Type == TipoPonto.Entrada);
            var endTime = pontos.FirstOrDefault(x => x.Type == TipoPonto.Almoco);

            if (lunchEnd == null || endTime == null)
                return timeBeforeLunch!;

            var timeAfterLunch = endTime.Date.Hour - lunchEnd.Date.Hour;

            return timeBeforeLunch + timeAfterLunch;
        }
    }
}
