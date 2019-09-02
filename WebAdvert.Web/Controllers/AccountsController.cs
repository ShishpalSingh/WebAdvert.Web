using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public AccountsController(
            SignInManager<CognitoUser> signInManager,
            UserManager<CognitoUser> userManager,
            CognitoUserPool pool
            )
        {
            this._signInManager = signInManager;
            this._userManager = userManager;
            this._pool = pool;
        }

        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = this._pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("User Exists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);
                var createdUser = await this._userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

                if (createdUser.Succeeded)
                {
                    RedirectToAction("Confirm");
                }
                else
                {
                    foreach (var item in createdUser.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                }
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await this._userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user == null)
                {
                    ModelState.AddModelError("Not Found", "A user with the given email address was not found");
                    return View(model);
                }
                var result = await (this._userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                }
            }
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RemeberMe, false)
                    .ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match.");
                }
            }
            return View("Login", model);
        }
    }
}