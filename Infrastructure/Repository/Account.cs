using Application.DTO.Request.Identity;
using Application.Extension.Identity;
using Application.Interface.Identity;
using Infrastructure.DataAccess;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Mapster;
using Application.DTO.Response.Identity;
using Application.DTO.Response;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Infrastructure.Repository
{
    public class Account : IAccount
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public Account(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<ServiceResponse> CreateUserAsync(CreateUserRequestDTO model)
        {
            var user = await FindUserByEmail(model.Email);
            if (user != null)
                return new ServiceResponse(false, "Belə bir istifadəçi artıq mövcuddur");

            var newUser = new ApplicationUser()
            {
                UserName = model.Email,
                Email = model.Email,
                Name = model.Name
            };
            var result = CheckResult(await _userManager.CreateAsync(newUser, model.Password));
            if (!result.Flag)
                return result;
            else
                return await CreateUserClaims(model);
        }

        private async Task<ServiceResponse> CreateUserClaims(CreateUserRequestDTO model)
        {
            if (string.IsNullOrEmpty(model.Policy)) return new ServiceResponse(false, "Heç bir policy seçilməyib");
            Claim[] userClaims = null;
            if (model.Policy.Equals(Policy.AdminPolicy, StringComparison.OrdinalIgnoreCase))
            {
                userClaims = new Claim[]
                {
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "true"),
                    new Claim("Update", "true"),
                    new Claim("Delete", "true"),
                    new Claim("Read", "true"),
                    new Claim("ManageUser", "true")
                };
            }
            else if (model.Policy.Equals(Policy.ManagerPolicy, StringComparison.OrdinalIgnoreCase))
            {
                userClaims = new Claim[]
                {
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "Manager"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "true"),
                    new Claim("Update", "true"),
                    new Claim("Read", "true"),
                    new Claim("ManageUser", "false"),
                    new Claim("Delete", "false")
                };
            }
            else if (model.Policy.Equals(Policy.UserPolicy, StringComparison.OrdinalIgnoreCase))
            {
                userClaims = new Claim[]
                {
                    new Claim(ClaimTypes.Email, model.Email),
                    new Claim(ClaimTypes.Role, "User"),
                    new Claim("Name", model.Name),
                    new Claim("Create", "false"),
                    new Claim("Update", "false"),
                    new Claim("Read", "false"),
                    new Claim("ManageUser", "false"),
                    new Claim("Delete", "false")
                };
            }

            var user = await FindUserByEmail(model.Email);
            var result = CheckResult(await _userManager.AddClaimsAsync(user, userClaims));
            if (result.Flag)
                return new ServiceResponse(true, "İstifadəçi yaradıldı");
            else
                return result;
        }

        public async Task<ServiceResponse> LoginAsync(LoginUserRequestDTO model)
        {
            var user = await FindUserByEmail(model.Email);
            if (user is null) return new ServiceResponse(false, "İstifadəçi tapılmadı");

            var verifyPassword = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!verifyPassword.Succeeded) return new ServiceResponse(false, "Yalnış məlumatlar daxil edildi");

            var result = await _signInManager.PasswordSignInAsync(user, model.Password, false, false);
            if (!result.Succeeded)
                return new ServiceResponse(false, "Daxil olma zamanı bilinməyən bir xəta baş verdi");
            else
                return new ServiceResponse(true, null);
        }

        private async Task<ApplicationUser> FindUserByEmail(string email)
            => await _userManager.FindByEmailAsync(email);

        private async Task<ApplicationUser> FindUserById(string id)
            => await _userManager.FindByIdAsync(id);

        private static ServiceResponse CheckResult(IdentityResult result)
        {
            if (result.Succeeded) return new ServiceResponse(true, null);

            var errors = result.Errors.Select(_ => _.Description);
            return new ServiceResponse(false, string.Join(Environment.NewLine, errors));
        }

        public async Task<IEnumerable<GetUserWithClaimResponseDTO>> GetUsersWithClaimsAsync()
        {
            var UserList = new List<GetUserWithClaimResponseDTO>();
            var allUsers = await _userManager.Users.ToListAsync();
            if (allUsers.Count == 0) return UserList;

            foreach (var user in allUsers)
            {
                var currentUser = await _userManager.FindByIdAsync(user.Id);
                var getCurrentUserClaims = await _userManager.GetClaimsAsync(currentUser);

                if (getCurrentUserClaims.Any())
                    UserList.Add(new GetUserWithClaimResponseDTO()
                    {
                        UserId = user.Id,
                        Email = getCurrentUserClaims.FirstOrDefault(_ => _.Type == ClaimTypes.Email)?.Value,
                        RoleName = getCurrentUserClaims.FirstOrDefault(_ => _.Type == ClaimTypes.Role)?.Value,
                        Name = getCurrentUserClaims.FirstOrDefault(_ => _.Type == "Name")?.Value,
                        ManageUser = Convert.ToBoolean(getCurrentUserClaims.FirstOrDefault(_ => _.Type == "ManageUser")?.Value),
                        Create = Convert.ToBoolean(getCurrentUserClaims.FirstOrDefault(_ => _.Type == "Create")?.Value),
                        Update = Convert.ToBoolean(getCurrentUserClaims.FirstOrDefault(_ => _.Type == "Update")?.Value),
                        Delete = Convert.ToBoolean(getCurrentUserClaims.FirstOrDefault(_ => _.Type == "Delete")?.Value),
                        Read = Convert.ToBoolean(getCurrentUserClaims.FirstOrDefault(_ => _.Type == "Read")?.Value)
                    });
            }
            return UserList;
        }

        public async Task SetUpAsync() => await CreateUserAsync(new CreateUserRequestDTO()
        {
            Name = "administrator",
            Email = "admin@admin.com",
            Password = "Admin@123",
            Policy = Policy.AdminPolicy
        });

        public async Task<ServiceResponse> UpdateUserAsync(ChangeUserClaimRequestDTO model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null) return new ServiceResponse(false, "İstifadəçi tapılmadı");

            var oldUserClaims = await _userManager.GetClaimsAsync(user);
            var removeResult = IdentityResult.Success;
            foreach (var claim in oldUserClaims)
            {
                var result = await _userManager.RemoveClaimAsync(user, claim);
                if (!result.Succeeded)
                    removeResult = result;
            }

            var response = CheckResult(removeResult);
            if (!response.Flag)
                return new ServiceResponse(false, response.Message);

            Claim[] newUserClaims =
            {
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, model.RoleName),
                new Claim("Name", model.Name),
                new Claim("Create", model.Create.ToString()),
                new Claim("Update", model.Update.ToString()),
                new Claim("Read", model.Read.ToString()),
                new Claim("ManageUser", model.ManageUser.ToString()),
                new Claim("Delete", model.Delete.ToString())
            };

            var addNewClaims = await _userManager.AddClaimsAsync(user, newUserClaims);
            var outcome = CheckResult(addNewClaims);
            if (outcome.Flag)
                return new ServiceResponse(true, "İstifadəçi məlumatları dəyişdirildi");
            else
                return outcome;
        }
    }
}
