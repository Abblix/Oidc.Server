// Abblix OIDC Client Library
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

using System.Net;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.UserInfo;
using Abblix.Oidc.Client.UnitTests.Features.Discovery;

namespace Abblix.Oidc.Client.UnitTests.Features.UserInfo;

/// <summary>
/// Reading the UserInfo endpoint, and refusing what it says when the claims are not about the user this
/// login authenticated.
/// </summary>
public class UserInfoServiceTests
{
    private const string Issuer = "https://provider.example.com";
    private const string Endpoint = $"{Issuer}/userinfo";
    private const string Subject = "248289761001";

    private static (IUserInfoService Service, StubHttpMessageHandler Handler) Create(
        string body,
        HttpStatusCode statusCode = HttpStatusCode.OK,
        string? userInfoEndpoint = Endpoint)
    {
        var handler = new StubHttpMessageHandler(body, statusCode);

        var service = new UserInfoService(
            new ConfiguredMetadataProvider(new ProviderMetadata
            {
                Issuer = Issuer,
                UserInfoEndpoint = userInfoEndpoint,
            }),
            new StubHttpClientFactory(handler));

        return (service, handler);
    }

    /// <summary>
    /// The ordinary case: claims about the expected user come back as they were stated.
    /// </summary>
    [Fact]
    public async Task ReturnsTheClaimsForTheExpectedSubject()
    {
        var (service, handler) = Create(
            $$"""{"sub":"{{Subject}}","name":"Jane Doe","email":"jane@example.com"}""");

        var claims = await service.GetAsync(
            "the-access-token", Subject, TestContext.Current.CancellationToken);

        Assert.Equal("Jane Doe", claims["name"]?.GetValue<string>());
        Assert.Equal(Endpoint, Assert.Single(handler.RequestedAddresses).ToString());
    }

    /// <summary>
    /// The check the endpoint exists to need. OpenID Connect Core 1.0 section 5.3.2: "the Client MUST
    /// verify that the sub Claim in the UserInfo Response is identical to the sub Claim in the ID Token;
    /// if they do not match, the UserInfo Response values MUST NOT be used."
    /// </summary>
    /// <remarks>
    /// An access token names no user by itself, so a client that took the answer at face value would
    /// attach whatever came back to the session it was building. A response about somebody else is how
    /// another user's claims end up in this user's session.
    /// </remarks>
    [Fact]
    public async Task RefusesClaimsAboutADifferentSubject()
    {
        var (service, _) = Create($$"""{"sub":"somebody-else","name":"Mallory"}""");

        await Assert.ThrowsAsync<UserInfoException>(
            () => service.GetAsync("the-access-token", Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A response naming no subject cannot be shown to belong to this login either, so it is refused
    /// rather than accepted for lack of a contradiction.
    /// </summary>
    [Fact]
    public async Task RefusesClaimsWithNoSubject()
    {
        var (service, _) = Create("""{"name":"Jane Doe"}""");

        await Assert.ThrowsAsync<UserInfoException>(
            () => service.GetAsync("the-access-token", Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The comparison is exact - two subjects differing only by case are two different users, since
    /// nothing in the specification licenses folding them together.
    /// </summary>
    [Fact]
    public async Task TheSubjectComparisonIsExact()
    {
        // A subject carrying letters, unlike the numeric one the other tests use, so that the two spellings
        // this test compares actually differ.
        const string mixedCaseSubject = "Jane.Doe";

        var (service, _) = Create($$"""{"sub":"{{mixedCaseSubject.ToUpperInvariant()}}"}""");

        await Assert.ThrowsAsync<UserInfoException>(
            () => service.GetAsync(
                "the-access-token", mixedCaseSubject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The access token goes in the Authorization header as a bearer credential, which RFC 6750 section
    /// 2.1 prefers over the alternatives that put it in a query string where logs and referrers keep it.
    /// </summary>
    [Fact]
    public async Task PresentsTheTokenAsABearerCredential()
    {
        var (service, handler) = Create($$"""{"sub":"{{Subject}}"}""");

        await service.GetAsync("the-access-token", Subject, TestContext.Current.CancellationToken);

        var authorization = Assert.Single(handler.RequestedAuthorizations);
        Assert.NotNull(authorization);
        Assert.Equal("Bearer", authorization.Scheme);
        Assert.Equal("the-access-token", authorization.Parameter);
    }

    /// <summary>
    /// A refused token surfaces as a typed failure rather than an empty claim set, so a caller cannot
    /// mistake "the provider would not say" for "the provider said nothing about this user".
    /// </summary>
    [Fact]
    public async Task ARefusedTokenIsAFailure()
    {
        var (service, _) = Create("""{"error":"invalid_token"}""", HttpStatusCode.Unauthorized);

        await Assert.ThrowsAsync<UserInfoException>(
            () => service.GetAsync("the-access-token", Subject, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A provider publishing no UserInfo endpoint is refused with that as the reason, rather than a
    /// request to nowhere.
    /// </summary>
    [Fact]
    public async Task AProviderWithNoUserInfoEndpointIsRefused()
    {
        var (service, _) = Create("{}", userInfoEndpoint: null);

        await Assert.ThrowsAsync<UserInfoException>(
            () => service.GetAsync("the-access-token", Subject, TestContext.Current.CancellationToken));
    }
}
