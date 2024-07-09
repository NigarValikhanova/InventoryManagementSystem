using Application.Extension.Identity;
using Domain.Entities.ActivitiyTracker;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.DataAccess
{
    public class AppDbContext(DbContextOptions<AppDbContext> options):IdentityDbContext<ApplicationUser>(options)
    {
        public DbSet<Tracker> ActivityTracker { get; set; }
    }
}
