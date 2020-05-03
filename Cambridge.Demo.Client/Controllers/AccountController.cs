using System.Collections.Generic;
using System.Linq;
using System.Net;
using Cambridge.Demo.Client.Config;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;

namespace Cambridge.Demo.Client.Controllers
{
	[Authorize]
	public class AccountController : Controller
	{
		readonly IdentitySettings _identitySettings;

		public AccountController(IdentitySettings identitySettings)
		{
			_identitySettings = identitySettings;
		}

		public IActionResult Login()
		{
			return RedirectToAction("Index", "Home");
		}

		public async Task Logout()
		{
			var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

			if (refreshToken != null)
			{
				var httpClient = new HttpClient();

				var revokationResult = await httpClient.RevokeTokenAsync(new TokenRevocationRequest
				{
					Address = _identitySettings.RevocationEndpoint,
					ClientId = _identitySettings.ClientId,
					ClientSecret = _identitySettings.ClientSecret,
					Token = refreshToken,
				});
				if (!revokationResult.IsError)
				{
					await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
					await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
				}
			}

			await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
		}

		/// <summary>
		/// refers to https://docs.microsoft.com/en-us/xamarin/essentials/web-authenticator?tabs=android
		/// </summary>
		/// <returns></returns>

		[AllowAnonymous]
		[HttpGet]
		public async Task Mobile()
		{
			var auth = await HttpContext.AuthenticateAsync();

			if (!auth.Succeeded || 
			    auth?.Principal == null ||
			    string.IsNullOrEmpty(auth.Properties.GetTokenValue("access_token")))
			{
				await HttpContext.ChallengeAsync();
			}
			else
			{
				var qs = new Dictionary<string, string>
				{
					{ "access_token", auth.Properties.GetTokenValue("access_token") },
					{ "refresh_token", auth.Properties.GetTokenValue("refresh_token") ?? string.Empty },
					{ "expires", (auth.Properties.ExpiresUtc?.ToUnixTimeSeconds() ?? -1).ToString() }
				};
				var url = "orsosteauthapp://#" + string.Join(
					          "&",
					          qs.Where(kvp => !string.IsNullOrEmpty(kvp.Value) && kvp.Value != "-1")
						          .Select(kvp => $"{WebUtility.UrlEncode(kvp.Key)}={WebUtility.UrlEncode(kvp.Value)}"));

				Request.HttpContext.Response.Redirect(url);
			}
		}

		[AllowAnonymous]
		public IActionResult AccessDenied(string error)
		{
			ViewData["Error"] = error;
			return View();
		}
	}
}