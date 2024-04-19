// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;



namespace Abblix.Oidc.Server.Tests;

public class OidcClient : IDisposable
{
	public static async Task<OidcClient> Create(HttpClient client)
	{
		var result = new OidcClient(client);
		await result.DiscoverEndpoints();
		return result;
	}

	private OidcClient(HttpClient client)
	{
		_client = client;
	}

	public void Dispose()
	{
		_client?.Dispose();
	}

	private async Task DiscoverEndpoints()
	{
		var discoveryResponse = JsonDocument.Parse(await _client.GetStringAsync(".well-known/openid-configuration"));

		Uri Discover(string name) => new(discoveryResponse.RootElement.GetProperty(name).GetString());

		_authorizationEndpoint = Discover("authorization_endpoint");
		_tokenEndpoint = Discover("token_endpoint");
		_userInfoEndpoint = Discover("userinfo_endpoint");
	}

	public async Task<HttpResponseMessage> Authorize(IDictionary<string, string> parameters)
	{
		using var content = new FormUrlEncodedContent(parameters);

		return await _client.PostAsync(_authorizationEndpoint, content);
	}

	// connect/token
	public async Task<(string accessToken, string refreshToken, string tokenType)> GetToken(HttpContent request)
	{
		using var tokenResponse = await _client.PostAsync(_tokenEndpoint, request);

		//await AssertExpectedStatusCode(tokenResponse, HttpStatusCode.OK);
		//await AssertExpectedContentMediaType(tokenResponse, "application/json");

		JsonDocument response;
		using (var tokenContent = tokenResponse.Content)
		{
			await using var stream = await tokenContent.ReadAsStreamAsync();
			response = await JsonDocument.ParseAsync(stream);
		}

		string GetString(string name)
			=> response.RootElement.TryGetProperty(name, out var value)
				? value.GetString()
				: throw new InvalidOperationException($"{name} is null");

		var accessToken = GetString("access_token");
		var refreshToken = GetString("refresh_token");
		var tokenType = GetString("token_type");

		var tokenParts = accessToken.Split('.');
		if (tokenParts.Length != 3)
		{
			throw new InvalidOperationException($"token must contain 3 part but contains {tokenParts.Length}");
		}

		var payload = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(tokenParts[1])));

		var expected = new[] { "nbf", "exp", "iss", "client_id", "sub", "auth_time", "idp", "scope", "sid", "jti", "iat" };
		var actual = (from claim in payload.RootElement.EnumerateObject() select claim.Name).ToArray();

		var missingClaims = expected.Except(actual).ToArray();
		if (0 < missingClaims.Length)
		{
			throw new InvalidOperationException($"The following claims are missing: {string.Join(", ", missingClaims)}");
		}

		var unexpectedClaims = actual.Except(expected).ToArray();
		if (0 < unexpectedClaims.Length)
		{
			throw new InvalidOperationException($"The following claims are unexpected: {string.Join(", ", unexpectedClaims)}");
		}

		return (accessToken, refreshToken, tokenType);
	}

	// connect/userinfo
	public async Task<JsonDocument> GetUserInfo(string tokenType, string accessToken)
	{
		var authenticationHeaderValue = new AuthenticationHeaderValue(tokenType, accessToken);

		using var request = new HttpRequestMessage(HttpMethod.Get, _userInfoEndpoint)
		{
			Headers = { Authorization = authenticationHeaderValue },
		};

		using var userInfoResponse = await _client.SendAsync(request);

		//await AssertExpectedStatusCode(userInfoResponse, HttpStatusCode.OK);
		//await AssertExpectedContentMediaType(userInfoResponse, MediaTypeNames.Application.Json);

		await using var stream = await userInfoResponse.Content.ReadAsStreamAsync();
		return await JsonDocument.ParseAsync(stream);
	}

	private readonly HttpClient _client;

	private Uri _authorizationEndpoint;
	private Uri _tokenEndpoint;
	private Uri _userInfoEndpoint;
}
