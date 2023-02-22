using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata.Ecma335;

namespace IdentityManager.Controllers
{
  public class AccountController : Controller
  {
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
      _userManager = userManager;
      _signInManager = signInManager;
    }

    public IActionResult Index()
    {
      return View();
    }

    #region login
    [HttpGet]
    public async Task<IActionResult> Login(string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      LoginViewModel loginViewModel = new();
      return View(loginViewModel);
    }

    [HttpPost]
    [AutoValidateAntiforgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      if (!((await _userManager.FindByNameAsync(model.Email)) == null))
      {
        if ((await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false)).Succeeded)
        {
          if (!string.IsNullOrEmpty(returnUrl))
            return LocalRedirect(returnUrl);

          return RedirectToAction("Index", "Home");
        }
        ModelState.AddModelError(String.Empty, "Incorrect password");
        return View(model);
      }

      ModelState.AddModelError(String.Empty, "User doesn't exist");
      return View(model);
    }
    #endregion

    #region register
    [HttpGet]
    public async Task<IActionResult> Register(string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      RegisterViewModel registerViewModel = new();
      return View(registerViewModel);
    }

    [HttpPost]
    [AutoValidateAntiforgeryToken]
    public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
    {
      ViewData["ReturnUrl"] = returnUrl;
      if (ModelState.IsValid)
      {
        ApplicationUser user = new()
        {
          UserName = model.Email,
          Email = model.Email,
          Name = model.Name
        };

        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
          await _signInManager.SignInAsync(user, isPersistent: false);
          if (!string.IsNullOrEmpty(returnUrl))
            LocalRedirect(returnUrl);

          return RedirectToAction("Index", "Home");
        };
        AddErrors(result);        
      }

      return View(model);
    }

    #endregion
    [HttpGet]
    public async Task<IActionResult> Logout()
    {
      await _signInManager.SignOutAsync();
      return RedirectToAction("Index", "Home");
    }
    #region logout
    
    #endregion
    private void AddErrors(IdentityResult result)
    {
      foreach (var error in result.Errors)
      {
        ModelState.AddModelError(String.Empty, error.Description);
      }
    }
  }
}