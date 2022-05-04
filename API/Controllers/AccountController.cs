using API.Data;
using API.Dtos;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext context;
        private readonly ITokenService tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            this.context = context;
            this.tokenService = tokenService;
        }
        [Route("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto register)
        {
            if (await IsUserExist(register.username)) return BadRequest("Username exist");
            using var hmac = new HMACSHA512();
            var appUser = new AppUser
            {
                UserName = register.username,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.password)),
                PasswordSalt = hmac.Key
            };
            context.Users.Add(appUser);
            await context.SaveChangesAsync();
            return new UserDto
            {
                Username = appUser.UserName,
                Token = tokenService.CreateToken(appUser)
            };
        }
        [Route("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var appUser = await context.Users.FirstOrDefaultAsync(u => u.UserName == loginDto.username);
            if (appUser == null)
            {
                return Unauthorized("User does not exist");
            }
            using var hmac = new HMACSHA512(appUser.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));
            for(int i=0; i< computedHash.Length;i++)
            {
                if (computedHash[i] != appUser.PasswordHash[i]) return Unauthorized("Invalid password");
            }
            return new UserDto
            {
                Username = appUser.UserName,
                Token = tokenService.CreateToken(appUser)
            };
        }

        private async Task<bool> IsUserExist(string username)
        {
            return await context.Users.AnyAsync(u => u.UserName == username.ToLower());
        }
    }
}
