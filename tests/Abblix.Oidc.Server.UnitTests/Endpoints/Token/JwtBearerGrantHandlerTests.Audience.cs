// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

public partial class JwtBearerGrantHandlerTests
{
	/// <summary>
	/// RFC 10070 section 4, case A: for the authorization grant "an authorization server MAY be identified by either
	/// its issuer identifier or its token endpoint URL", so an assertion naming either one is addressed here in both
	/// policies, beside any other audience it names. The token endpoint URL is the one on the issuer's authority: the
	/// URL the request reached and the application URI on the request's host name whatever host the caller sent, and
	/// are refused in both. Asked of the audience check the handler hands the JWT validator, since a validator double
	/// never runs it.
	/// </summary>
	[Theory]
	[InlineData(true, nameof(TokenEndpointUri), true)]
	[InlineData(true, nameof(TenantIssuer), true)]
	[InlineData(true, nameof(RequestTokenEndpointUri), false)]
	[InlineData(true, nameof(ApplicationUri), false)]
	[InlineData(false, nameof(TokenEndpointUri), true)]
	[InlineData(false, nameof(TenantIssuer), true)]
	[InlineData(false, nameof(RequestTokenEndpointUri), false)]
	[InlineData(false, nameof(ApplicationUri), false)]
	public async Task AnAudienceNamingThisServer_IsAcceptedAsThePolicyAllows(bool strict, string named, bool accepted)
	{
		var validateAudience = await AudienceCheckAsync(strict);

		var audience = named switch
		{
			nameof(TokenEndpointUri) => TokenEndpointUri,
			nameof(TenantIssuer) => TenantIssuer,
			nameof(RequestTokenEndpointUri) => RequestTokenEndpointUri,
			nameof(ApplicationUri) => ApplicationUri,
			_ => throw new ArgumentOutOfRangeException(nameof(named), named, null),
		};

		Assert.Equal(accepted, await validateAudience([audience]));
		Assert.Equal(accepted, await validateAudience(["https://another-server.example.com", audience]));
	}

	/// <summary>
	/// RFC 10070 section 4: "applications MUST compare the audience values using the Simple String Comparison method
	/// defined in Section 6.2.1 of [RFC3986]", so the server's own addresses spelled otherwise, in another case, with
	/// a trailing slash or a default port, are not this server.
	/// </summary>
	[Theory]
	[MemberData(nameof(ThisServerSpelledOtherwise))]
	public async Task AnAudienceSpellingThisServerOtherwise_IsRefused(string audience)
	{
		foreach (var strict in new[] { true, false })
		{
			var validateAudience = await AudienceCheckAsync(strict);
			Assert.False(await validateAudience([audience]), $"accepted with strict={strict}");
		}
	}

	public static TheoryData<string> ThisServerSpelledOtherwise() =>
	[
		"https://AUTH.example.com/token",
		TokenEndpointUri + "/",
		"https://auth.example.com:443/token",
		TenantIssuer + "/",
	];

	/// <summary>
	/// For an issuer written with its default port and an upper-case host, the token endpoint is accepted on the
	/// issuer's authority both normalized, as discovery publishes it, and as the issuer writes it, beside the issuer as
	/// written; each is compared as written, so a third spelling of the same host, and the issuer normalized, are
	/// refused.
	/// </summary>
	[Theory]
	[InlineData("https://issuer.example.com/token", true)]
	[InlineData("https://ISSUER.example.com:443/token", true)]
	[InlineData(IssuerWithItsDefaultPort, true)]
	[InlineData("https://issuer.example.com:443/token", false)]
	[InlineData("https://issuer.example.com", false)]
	public async Task AnIssuerWrittenWithItsDefaultPort_IsNamedEitherWayItIsWritten(string audience, bool accepted)
	{
		var tenant = new TestIssuer { Issuer = new Uri(IssuerWithItsDefaultPort) }.ToTenant();
		var validateAudience = await AudienceCheckAsync(strict: true, tenant: tenant);

		Assert.Equal(accepted, await validateAudience([audience]));
	}

	private const string IssuerWithItsDefaultPort = "https://ISSUER.example.com:443";

	/// <summary>
	/// A policy built without a service provider cannot resolve the token endpoint, so the issuer identifier alone
	/// names this server.
	/// </summary>
	[Fact]
	public async Task WithoutAServiceProvider_OnlyTheIssuerNamesThisServer()
	{
		var validateAudience = await AudienceCheckAsync(strict: true, resolveEndpoints: false);

		Assert.True(await validateAudience([TenantIssuer]));
		Assert.False(await validateAudience([TokenEndpointUri]));
	}

	// The token endpoint on the issuer's authority, and as the request names it, on a host and port of the caller's
	private const string TokenEndpointUri = "https://auth.example.com/token";
	private const string RequestTokenEndpointUri = "https://authorization-server.example.com:8443/token";
	private const string ApplicationUri = "https://authorization-server.example.com:8443";
	private static string TenantIssuer => SingleIssuer.Tenant.Issuer.OriginalString;

	/// <summary>
	/// The audience check the handler hands the JWT validator for an assertion presented at
	/// <see cref="SingleIssuer.Tenant"/>, under the strict or the permissive policy, over a transport resolving the
	/// token endpoint on the request's host, or over a policy built without a way to resolve it.
	/// </summary>
	private static async Task<ValidationParameters.ValidateAudienceDelegate> AudienceCheckAsync(
		bool strict, bool resolveEndpoints = true, TenantDefinition? tenant = null)
	{
		var (handler, mocks) = CreateHandler(
			tokenEndpoint: RequestTokenEndpointUri,
			applicationUri: ApplicationUri,
			strictAudienceValidation: strict,
			resolveEndpoints: resolveEndpoints);
		ValidationParameters? captured = null;
		mocks.JwtValidator
			.Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
			.Callback(new Action<string, ValidationParameters>((_, p) => captured = p))
			.ReturnsAsync((Result<JsonWebToken, JwtValidationError>)new JwtValidationError(JwtError.InvalidToken, "not the subject of this test"));

		await handler.AuthorizeAsync(
			tenant ?? SingleIssuer.Tenant,
			new TokenRequest { GrantType = GrantTypes.JwtBearer, Assertion = Assertion },
			new ClientInfo(ClientId),
			TestContext.Current.CancellationToken);

		return captured!.ValidateAudience!;
	}
}
