using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _token;
        public AccountController(DataContext context, ITokenService token)
        {
            _token = token;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto regDto)
        {

            if (await UserExists(username: regDto.userName.ToLower())) return BadRequest("User Exist Already");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {

                UserName = regDto.userName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(regDto.password)),
                PasswordSalt = hmac.Key
            };
            _context.User.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto{
                userName=user.UserName,
                token=_token.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.User.AnyAsync(x =>
            x.UserName == username.ToLower());

        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> login(LoginDto loginDto)
        {
            var user = await _context.User
            .SingleOrDefaultAsync(x => x.UserName == loginDto.userName);
            if (user == null) return Unauthorized("user invalid");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Pass");

            }
             
            return new UserDto{
                userName=user.UserName,
                token=_token.CreateToken(user)
            };

        }

    }
}