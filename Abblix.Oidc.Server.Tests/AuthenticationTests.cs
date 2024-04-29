// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;
using Xunit;


namespace Abblix.Oidc.Server.Tests;

public sealed class AuthenticationTests: IDisposable
{
	private Config _config;
	private CookieContainer _cookies;
	private OidcClient _oidcClient;

	public AuthenticationTests()
	{
		InitializeAsync().Wait();
	}

    private async Task InitializeAsync()
	{
		_config = new Config();

		_cookies = new CookieContainer();

		_oidcClient = await OidcClient.Create(
			new HttpClient(
				new HttpClientHandler
				{
					CookieContainer = _cookies,
					UseCookies = true,
					AllowAutoRedirect = false,
				})
			{
				BaseAddress = _config.BaseUrl,
			});
	}

	public void Dispose()
	{
		_oidcClient?.Dispose();
	}

	[Fact(Skip  = "not ready")]
	public async Task BasicFlowTest()
	{
		var query = new Dictionary<string, string>(StringComparer.Ordinal)
		{
			{ "client_id", _config.AccountManagementApp.ClientId },
			{ "redirect_uri", _config.AccountManagementApp.RedirectUri.AbsoluteUri },
			{ "response_type", "id_token" },
			{ "scope", "openid profile" },
			{ "response_mode", "form_post" },
			{ "nonce", Guid.NewGuid().ToString() },
			{ "state", Guid.NewGuid().ToString() },
			{ "ui_locales", string.Empty },
		};

		using var tokenResponse = await _oidcClient.Authorize(query);
		Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

		await AssertIdToken("connect/authorize", tokenResponse);
	}

	[Fact(Skip  = "not ready")]
	public async Task RefreshTokenTest()
	{
		var client = _config.ApClientSampleCode;

		var scope = string.Join(" ", "openid", "profile", "offline_access");

		// signin/start
		//var session = await _oidcClient.SignInStart(_config.AccountManagementApp.ClientId);

		// signin/proceed
		//await SignInProceed(session.SessionId, rememberMe: false);

		// connect/authorize
		string code;

		var query = new Dictionary<string, string>(StringComparer.Ordinal)
		{
			{ "client_id", client.ClientId },
			{ "redirect_uri", client.RedirectUri.ToString() },
			{ "response_type", "code" },
			{ "grant_type", "password" },
			{ "scope", scope },
		};

		using (var redirectResponse = await _oidcClient.Authorize(query))
		{
			Assert.Equal(HttpStatusCode.Redirect, redirectResponse.StatusCode);
			code = HttpUtility.ParseQueryString(redirectResponse.Headers.Location!.Query)["code"];
			Assert.NotNull(code);
		}

		string accessToken1;
		string refreshToken;
		using (var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
				{
					{ "client_id", client.ClientId },
					{ "client_secret", client.ClientSecret },
					{ "grant_type", "authorization_code" },
					{ "scope", scope },
					{ "redirect_uri", client.RedirectUri.ToString() },
					{ "code", code },
				}))
		{
			(accessToken1, refreshToken, _) = await _oidcClient.GetToken(content);
		}

		await Task.Delay(TimeSpan.FromSeconds(5));

		// connect/token #2: using refresh_token
		string accessToken;
		string tokenType;
		using (var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
				{
					{ "client_id", client.ClientId },
					{ "client_secret", client.ClientSecret },
					{ "grant_type", "refresh_token" },
					{ "scope", scope },
					{ "refresh_token", refreshToken },
				}))
		{
			(accessToken, _, tokenType) = await _oidcClient.GetToken(content);
		}

		Assert.NotEqual(accessToken1, accessToken);

		// connect/userinfo
		var userInfo = await _oidcClient.GetUserInfo(tokenType, accessToken);

		Assert.Equal(
			new[] { "sub" },
			userInfo.RootElement.EnumerateObject().Select(claim => claim.Name).ToArray()
		);
	}

	private async Task AssertIdToken(string expectedPath, HttpResponseMessage response)
	{
		AssertUri(expectedPath, response.RequestMessage!.RequestUri);
		Assert.Equal(HttpStatusCode.OK, response.StatusCode);

		var tokenForm = XDocument.Parse(await response.Content.ReadAsStringAsync());
		var idToken = tokenForm.Descendants("input").Single(e => e.Attribute("name")?.Value == "id_token").Attribute("value")?.Value;
		Assert.False(string.IsNullOrEmpty(idToken), "idToken is empty");
	}

	private void AssertUri(string expectedPath, Uri actualUri)
	{
		var logonPageUriBase = UriBase(actualUri);
		Assert.Equal(new Uri(_config.BaseUrl, expectedPath).AbsoluteUri.ToLowerInvariant(), logonPageUriBase.ToLowerInvariant());

		static string UriBase(Uri uri) => uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);
	}

	[Fact(Skip = "grant_type=password not supported by default")]
	public async Task GrantTypePasswordTest()
	{
		var query = new Dictionary<string, string>(StringComparer.Ordinal)
		{
			{ "client_id", _config.ApClientSampleCode.ClientId },
			{ "client_secret", _config.ApClientSampleCode.ClientSecret },
			{ "grant_type", "password" },
			{ "scope", string.Join(" ", "profile", "email", "offline_access") },
			{ "username", _config.Login },
			{ "password", _config.Password },
		};

		using var content = new FormUrlEncodedContent(query);
		await _oidcClient.GetToken(content);
	}
}
