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
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// End-to-end integration tests for the <see cref="IRegisterClientHandler"/> pipeline through
/// the canonical <c>AddOidcServices</c> bootstrap. Locks the server-level support gates
/// (<c>SupportedResponseTypeValidator</c>, <c>SupportedGrantTypeValidator</c>) at the
/// resolved-via-DI layer rather than per-validator level — verifying not only that the
/// validators exist, but that they participate in the registration pipeline a host actually
/// invokes via <c>IRegisterClientHandler</c>. Construction of the registration request goes
/// through the public DTO; resolution goes through DI; rejections come back as OidcError
/// per OIDC DCR §3.2.2.
/// </summary>
public class RegisterClientHandlerIntegrationTests
{
    private static IServiceProvider BuildProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();

        // Host-level infrastructure prerequisites every real ASP.NET host registers — the DI
        // analog of AddLogging. Oidc.Server's Storages depend on IDistributedCache; the
        // CachingSecureHttpFetcherDecorator depends on IMemoryCache; the password grant
        // handler depends on a host-supplied IUserCredentialsAuthenticator. The host chooses
        // each implementation — memory-backed caches are the canonical unit-test choices,
        // and the authenticator is stubbed because ROPC scenarios in this suite don't
        // actually authenticate.
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        services.AddOidcServices(opts =>
        {
            opts.Issuer = "https://test.example.com";

            // Generate an in-memory RS256 signing key for the registration access token the
            // success-path test asserts on. Production hosts feed real certificates here;
            // tests need only a freshly minted key — RsaJsonWebKey is a self-contained PoCo
            // so this stays a simple Add without any further DI plumbing.
            opts.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];

            // Anonymous registration: opt out of RFC 7591 §3 initial access token gating so
            // the test focuses on the response_types / grant_types support gates added by
            // this PR. With RequireInitialAccessToken = true the InitialAccessTokenValidator
            // fires first and short-circuits with «invalid_token» before any support gate
            // sees the request — masking the very behaviour we want to verify.
            opts.RequireInitialAccessToken = false;
        });
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private static ClientRegistrationRequest CreateRequest(
        string[][]? responseTypes = null,
        string[]? grantTypes = null) => new()
    {
        RedirectUris = [new Uri("https://client.example.com/callback")],
        ResponseTypes = responseTypes ?? [[ResponseTypes.Code]],
        GrantTypes = grantTypes ?? [GrantTypes.AuthorizationCode],
    };

    /// <summary>
    /// Default registration with the Code Flow defaults must succeed against a stock host:
    /// no opt-ins required, <c>response_types=["code"]</c> + <c>grant_types=["authorization_code"]</c>
    /// is supported by every OIDC server.
    /// </summary>
    [Fact]
    public async Task HandleAsync_DefaultCodeFlowRequest_ReturnsSuccess()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var result = await handler.HandleAsync(CreateRequest());

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// Without <c>EnableImplicitFlow()</c> the host advertises only the Code Flow. A client
    /// trying to register with <c>response_types=["token"]</c> + <c>grant_types=["implicit"]</c>
    /// must be rejected at registration time with <c>invalid_client_metadata</c> per OIDC DCR
    /// §3.2 — the gap <c>SupportedResponseTypeValidator</c> closes, surfaced through the
    /// full handler pipeline.
    /// </summary>
    [Fact]
    public async Task HandleAsync_TokenResponseType_WithoutEnableImplicitFlow_RejectsAtRegistration()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.Implicit]);

        var result = await handler.HandleAsync(request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains(ResponseTypes.Token, error.ErrorDescription);
    }

    /// <summary>
    /// Once the host opts into Implicit Flow, the same registration that was rejected above
    /// must now succeed. Locks the symmetric «opt-in surface flows through to
    /// registration-time gating» contract.
    /// </summary>
    [Fact]
    public async Task HandleAsync_TokenResponseType_WithEnableImplicitFlow_Succeeds()
    {
        var provider = BuildProvider(s => s.EnableImplicitFlow());
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.Implicit]);

        var result = await handler.HandleAsync(request);

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// The same opt-in story for ROPC: without <c>EnablePasswordGrant()</c>, registration
    /// with <c>grant_types=["password"]</c> alongside the default Code Flow response_types
    /// is rejected. The grant lives at the token endpoint and isn't tied to a response_type,
    /// so this exercises <c>SupportedGrantTypeValidator</c> independently of the response-
    /// type gate.
    /// </summary>
    [Fact]
    public async Task HandleAsync_PasswordGrant_WithoutEnablePasswordGrant_RejectsAtRegistration()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Password]);

        var result = await handler.HandleAsync(request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains(GrantTypes.Password, error.ErrorDescription);
    }

    /// <summary>
    /// Symmetric to the above: with the host opted into ROPC, the password grant is
    /// supported and registration succeeds end-to-end through the full handler pipeline.
    /// </summary>
    [Fact]
    public async Task HandleAsync_PasswordGrant_WithEnablePasswordGrant_Succeeds()
    {
        var provider = BuildProvider(s => s.EnablePasswordGrant());
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Password]);

        var result = await handler.HandleAsync(request);

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }
}
