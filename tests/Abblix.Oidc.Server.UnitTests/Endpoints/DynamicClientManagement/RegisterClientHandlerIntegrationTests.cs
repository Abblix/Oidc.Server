// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// End-to-end integration tests for the <see cref="IRegisterClientHandler"/> pipeline through
/// the canonical <c>AddOidcServices</c> bootstrap. Locks the server-level support gates
/// (<c>SupportedResponseTypeValidator</c>, <c>SupportedGrantTypeValidator</c>) at the
/// resolved-via-DI layer rather than per-validator level - verifying not only that the
/// validators exist, but that they participate in the registration pipeline a host actually
/// invokes via <c>IRegisterClientHandler</c>. Construction of the registration request goes
/// through the public DTO; resolution goes through DI; rejections come back as OidcError
/// per OIDC DCR section 3.3, Client Registration Error Response.
/// </summary>
public class RegisterClientHandlerIntegrationTests
{
    private static IServiceProvider BuildProvider(
        Action<IServiceCollection>? configure = null,
        Action<OidcOptions>? configureOptions = null,
        Action<IServiceCollection>? afterServer = null)
    {
        var services = new ServiceCollection();

        // Host-level infrastructure prerequisites every real ASP.NET host registers - the DI
        // analog of AddLogging. Oidc.Server's Storages depend on IDistributedCache; the
        // CachingSecureHttpFetcherDecorator depends on IMemoryCache; the password grant
        // handler depends on a host-supplied IUserCredentialsAuthenticator. The host chooses
        // each implementation - memory-backed caches are the canonical unit-test choices,
        // and the authenticator is stubbed because ROPC scenarios in this suite don't
        // actually authenticate.
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());

        // Dynamic client registration is opt-in (off in the OidcEndpoints.Base set); register it explicitly
        // so this suite's DCR handlers and validators resolve.
        services.AddDynamicClientRegistration();

        // Apply per-test opt-ins (e.g. EnablePasswordGrant) BEFORE AddOidcServices: a grant handler must be
        // registered before AddOidcCore composes the handlers, otherwise the ordering guard rejects it.
        configure?.Invoke(services);

        services.AddOidcServices(opts =>
        {
            // Generate an in-memory RS256 signing key for the registration access token the
            // success-path test asserts on. Production hosts feed real certificates in this
            // slot, but tests need only a freshly minted key. RsaJsonWebKey is a self-contained
            // POCO, so this stays a simple Add without any further DI plumbing.
            opts.Tenants.Add(new TenantDefinition
            {
                Id = TestIssuer.TenantId,
                Issuer = TestConstants.DefaultIssuer,
                ClientSecretEncryption = new ClientSecretEncryptionSettings
                {
                    Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                },
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],

                // Pairwise subjects, whose sector identifier document a registration may name for the server to fetch
                PairwiseSubject = new PairwiseSubjectSettings
                {
                    Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                },
            });

            // Anonymous registration: opt out of RFC 7591 section 3 initial access token gating so
            // the test focuses on the response_types / grant_types support gates added by
            // this PR. With RequireInitialAccessToken = true the InitialAccessTokenValidator
            // fires first and short-circuits with «invalid_token» before any support gate
            // sees the request - masking the very behavior we want to verify.
            opts.RequireInitialAccessToken = false;

            // A test that exercises the initial access token gate re-enables it here.
            configureOptions?.Invoke(opts);
        });

        // Registrations that have to win over the server's own, which a typed HTTP client adds unconditionally
        afterServer?.Invoke(services);

        return services.ResolveToTheDeclaredTenant().BuildServiceProvider();
    }

    /// <summary>
    /// Names the grant types new clients may request, which a client needs for any grant beyond the authorization
    /// code and the refresh token of the default list, so a test reaches the gate it is about.
    /// </summary>
    private static Action<OidcOptions> Granting(params string[] grantTypes)
        => opts => opts.NewClientOptions = opts.NewClientOptions with { AllowedGrantTypes = grantTypes };

    private static ClientRegistrationRequest CreateRequest(
        string[][]? responseTypes = null,
        string[]? grantTypes = null) => new()
    {
        RedirectUris = [new Uri("https://client.example.com/callback")],
        ResponseTypes = responseTypes ?? [[ResponseTypes.Code]],
        GrantTypes = grantTypes ?? [GrantTypes.AuthorizationCode],
    };

    private static ClientRegistrationRequest CreateDpopBoundRequest() => new()
    {
        RedirectUris = [new Uri("https://client.example.com/callback")],
        ResponseTypes = [[ResponseTypes.Code]],
        GrantTypes = [GrantTypes.AuthorizationCode],
        DpopBoundAccessTokens = true,
    };

    /// <summary>
    /// An initial access token is revoked by its identifier, recorded in the token registry: it registers a client
    /// until then, and is refused from the moment it is recorded.
    /// </summary>
    [Fact]
    public async Task AnInitialAccessTokenRevokedByItsIdentifier_IsRefusedAtRegistration()
    {
        var provider = BuildProvider(configureOptions: opts => opts.RequireInitialAccessToken = true);
        var tenant = provider.GetRequiredService<ITenantAccessor>().CurrentTenant();
        var issued = await provider.GetRequiredService<IInitialAccessTokenService>().IssueTokenAsync(
            tenant, "registration-portal", provider.GetRequiredService<TimeProvider>().GetUtcNow(), TimeSpan.FromMinutes(5));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        ClientRegistrationRequest Presenting() => CreateRequest() with
        {
            AuthorizationHeaderLines = [new System.Net.Http.Headers.AuthenticationHeaderValue(TokenTypes.Bearer, issued.EncodedJwt).ToString()],
        };

        Assert.True((await handler.HandleAsync(tenant, Presenting())).TryGetSuccess(out _));

        await provider.GetRequiredService<ITokenRegistry>().SetStatusAsync(
            tenant,
            issued.Token.Payload.JwtId.NotNull(nameof(JsonWebTokenPayload.JwtId)),
            JsonWebTokenStatus.Revoked,
            issued.Token.Payload.ExpiresAt.NotNull(nameof(JsonWebTokenPayload.ExpiresAt)));

        Assert.True((await handler.HandleAsync(tenant, Presenting())).TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidToken, error.Error);
    }

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

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), CreateRequest());

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// Without <c>EnableImplicitFlow()</c> the host advertises only the Code Flow. A client
    /// trying to register with <c>response_types=["token"]</c> + <c>grant_types=["implicit"]</c>
    /// must be rejected at registration time with <c>invalid_client_metadata</c> per OIDC DCR
    /// section 3.2 - the gap <c>SupportedResponseTypeValidator</c> closes, surfaced through the
    /// full handler pipeline.
    /// </summary>
    [Fact]
    public async Task HandleAsync_TokenResponseType_WithoutEnableImplicitFlow_RejectsAtRegistration()
    {
        var provider = BuildProvider(configureOptions: Granting(GrantTypes.Implicit));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.Implicit]);

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains(ResponseTypes.Token, error.ErrorDescription);
    }

    /// <summary>
    /// Once the host opts into Implicit Flow, the same registration that was rejected in
    /// <see cref="HandleAsync_TokenResponseType_WithoutEnableImplicitFlow_RejectsAtRegistration"/>
    /// must now succeed. Locks the symmetric «opt-in surface flows through to
    /// registration-time gating» contract.
    /// </summary>
    [Fact]
    public async Task HandleAsync_TokenResponseType_WithEnableImplicitFlow_Succeeds()
    {
        var provider = BuildProvider(s => s.EnableImplicitFlow(), Granting(GrantTypes.Implicit));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            responseTypes: [[ResponseTypes.Token]],
            grantTypes: [GrantTypes.Implicit]);

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

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
        var provider = BuildProvider(configureOptions: Granting(GrantTypes.AuthorizationCode, GrantTypes.Password));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Password]);

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Contains(GrantTypes.Password, error.ErrorDescription);
    }

    /// <summary>
    /// Symmetric to <see cref="HandleAsync_PasswordGrant_WithoutEnablePasswordGrant_RejectsAtRegistration"/>:
    /// with the host opted into ROPC, the password grant is
    /// supported and registration succeeds end-to-end through the full handler pipeline.
    /// </summary>
    [Fact]
    public async Task HandleAsync_PasswordGrant_WithEnablePasswordGrant_Succeeds()
    {
        var provider = BuildProvider(
            s => s.EnablePasswordGrant(),
            Granting(GrantTypes.AuthorizationCode, GrantTypes.Password));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest(
            grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.Password]);

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// RFC 9449 Section 5.2: a registration request carrying <c>dpop_bound_access_tokens=true</c>
    /// must round-trip into the persisted
    /// <see cref="Abblix.Oidc.Server.Features.ClientInformation.ClientInfo.RequireDPoP"/> flag and be echoed on the success
    /// response (RFC 7591 Section 3.2.1) so the client can confirm the binding.
    /// </summary>
    [Fact]
    public async Task HandleAsync_DpopBoundAccessTokensTrue_RoundTripsAndEchoes()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var clientInfoProvider = provider.GetRequiredService<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>();

        var request = CreateDpopBoundRequest();

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out var success),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
        Assert.True(success.Metadata.DpopBoundAccessTokens);

        var stored = (await clientInfoProvider.FindClientAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), success.ClientId))
            .GetSuccess();
        Assert.True(stored.RequireDPoP);
    }

    /// <summary>
    /// RFC 9449 section 5.2: when the client metadata omits <c>dpop_bound_access_tokens</c>, the
    /// effective value is <c>false</c>. Locks the default-on-omission contract end-to-end.
    /// </summary>
    [Fact]
    public async Task HandleAsync_DpopBoundAccessTokensOmitted_DefaultsFalse()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var clientInfoProvider = provider.GetRequiredService<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>();

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), CreateRequest());

        Assert.True(result.TryGetSuccess(out var success));
        Assert.False(success.Metadata.DpopBoundAccessTokens);

        var stored = (await clientInfoProvider.FindClientAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), success.ClientId))
            .GetSuccess();
        Assert.False(stored.RequireDPoP);
    }

    /// <summary>
    /// RFC 9700 section 2.1.1 requires an authorization server to enforce PKCE for public clients, and this server
    /// requires it of every client that can receive a code. A registration request that says nothing about
    /// <c>pkce_required</c> must therefore leave the stored client on the server's own default rather than
    /// carrying a weaker one in from the request model: the flag is nullable precisely so that "not stated"
    /// stays distinguishable from "stated false", and a non-null default on the request would be copied onto
    /// the client and silently win.
    /// </summary>
    [Fact]
    public async Task HandleAsync_PkceRequiredOmitted_StoredClientStillRequiresPkce()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var clientInfoProvider = provider.GetRequiredService<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>();

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), CreateRequest());

        Assert.True(result.TryGetSuccess(out var success));

        var stored = (await clientInfoProvider.FindClientAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), success.ClientId))
            .GetSuccess();
        Assert.True(stored.PkceRequired is null or true);
    }

    /// <summary>
    /// The counterpart of <see cref="HandleAsync_PkceRequiredOmitted_StoredClientStillRequiresPkce"/>: a
    /// registration request that explicitly opts out still opts out,
    /// so the nullable default restores the server's own value without taking the choice away from a client
    /// that states one.
    /// </summary>
    [Fact]
    public async Task HandleAsync_PkceRequiredFalse_StoredClientOptsOut()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var clientInfoProvider = provider.GetRequiredService<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>();

        var request = CreateRequest();
        request = request with { PkceRequired = false };

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out var success));

        var stored = (await clientInfoProvider.FindClientAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), success.ClientId))
            .GetSuccess();
        Assert.False(stored.PkceRequired);
    }

    /// <summary>
    /// RFC 7591 section 3.2.1: the registration response echoes registered client metadata so the
    /// client can confirm what was stored without a follow-up read. Locks that the
    /// extended echo (added alongside DPoP) actually surfaces a representative subset of
    /// fields - <c>redirect_uris</c>, <c>token_endpoint_auth_method</c>, and the
    /// DPoP-binding flag - rather than only the minimal pre-extension surface.
    /// </summary>
    [Fact]
    public async Task HandleAsync_RegistrationResponse_EchoesRegisteredMetadata()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateDpopBoundRequest();

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.NotNull(success.Metadata.RedirectUris);
        Assert.Single(success.Metadata.RedirectUris);
        Assert.Equal(new Uri("https://client.example.com/callback"), success.Metadata.RedirectUris[0]);
        Assert.True(success.Metadata.DpopBoundAccessTokens);
    }

    /// <summary>
    /// RFC 9701 section 6: the registration response echoes a registered <c>introspection_signed_response_alg</c>, while a
    /// client that did not register one (the implicit <c>none</c> default) gets no such field in the response.
    /// </summary>
    [Fact]
    public async Task HandleAsync_RegistrationResponse_EchoesIntrospectionSignedResponseAlg()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var withAlg = CreateRequest() with { IntrospectionSignedResponseAlg = SigningAlgorithms.RS256 };
        Assert.True((await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), withAlg)).TryGetSuccess(out var registered));
        Assert.Equal(SigningAlgorithms.RS256, registered.Metadata.IntrospectionSignedResponseAlg);

        var withoutAlg = CreateRequest();
        Assert.True((await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), withoutAlg)).TryGetSuccess(out var registeredDefault));
        Assert.Null(registeredDefault.Metadata.IntrospectionSignedResponseAlg);
    }

    /// <summary>
    /// RFC 9126 section 6 / RFC 9101 section 10.5 / RFC 8705 section 3.4: the per-client FAPI-grade enforcement flags
    /// round-trip through registration into the stored ClientInfo and are echoed on the response
    /// (RFC 7591 section 3.2.1).
    /// </summary>
    [Fact]
    public async Task HandleAsync_FapiEnforcementFlags_RoundTripAndEcho()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var clientInfoProvider = provider.GetRequiredService<Abblix.Oidc.Server.Features.ClientInformation.IClientInfoProvider>();

        var request = CreateRequest() with
        {
            RequirePushedAuthorizationRequests = true,
            RequireSignedRequestObject = true,
            TlsClientCertificateBoundAccessTokens = true,
        };

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.True(success.Metadata.RequirePushedAuthorizationRequests);
        Assert.True(success.Metadata.RequireSignedRequestObject);
        Assert.True(success.Metadata.TlsClientCertificateBoundAccessTokens);

        var stored = (await clientInfoProvider.FindClientAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), success.ClientId))
            .GetSuccess();
        Assert.True(stored.RequirePushedAuthorizationRequests);
        Assert.True(stored.RequireSignedRequestObject);
        Assert.True(stored.TlsClientCertificateBoundAccessTokens);
    }

    /// <summary>
    /// RFC 7591 section 3: with the initial access token gate enabled, a client presenting a token minted
    /// by this server's own <see cref="IInitialAccessTokenService"/> must be allowed to register.
    /// The minted token carries no <c>aud</c> (registration authorizes at the issuer itself), so this
    /// exercises the mint-side and validate-side option sets composing end to end: the validator must
    /// not require an audience the mint deliberately omits.
    /// </summary>
    [Fact]
    public async Task HandleAsync_WithMintedInitialAccessToken_Succeeds()
    {
        var provider = BuildProvider(configureOptions: opts => opts.RequireInitialAccessToken = true);
        var handler = provider.GetRequiredService<IRegisterClientHandler>();
        var initialAccessTokenService = provider.GetRequiredService<IInitialAccessTokenService>();
        var timeProvider = provider.GetRequiredService<TimeProvider>();

        var token = await initialAccessTokenService.IssueTokenAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(),
            subject: "registration-portal",
            issuedAt: timeProvider.GetUtcNow(),
            expiresIn: TimeSpan.FromHours(1));

        var request = CreateRequest() with
        {
            AuthorizationHeaderLines = [new System.Net.Http.Headers.AuthenticationHeaderValue(TokenTypes.Bearer, token.EncodedJwt).ToString()],
        };

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    private static ClientRegistrationRequest MachineClientRequest() => CreateRequest(
        responseTypes: [],
        grantTypes: [GrantTypes.ClientCredentials]);

    /// <summary>
    /// A registration the host's grant types refuse costs the server no fetch of what it names: the sector identifier
    /// document a pairwise client points at is not requested.
    /// </summary>
    [Fact]
    public async Task ARegistrationTheHostsGrantTypesRefuse_MakesNoOutboundRequest()
    {
        var fetches = new CountingFetcher();
        var provider = BuildProvider(afterServer: services => services.AddSingleton<ISecureHttpFetcher>(fetches));
        var request = MachineClientRequest() with
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifierUri = new Uri("https://sector.example.com/redirect_uris.json"),
        };

        var result = await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.Equal(0, fetches.Count);
    }

    /// <summary>
    /// The same registration within the host's grant types reaches the sector identifier fetch, so the test above
    /// counts the fetch a refusal saves.
    /// </summary>
    [Fact]
    public async Task ARegistrationWithinTheHostsGrantTypes_FetchesItsSectorIdentifier()
    {
        var fetches = new CountingFetcher();
        var provider = BuildProvider(
            configureOptions: Granting(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials),
            afterServer: services => services.AddSingleton<ISecureHttpFetcher>(fetches));
        var request = MachineClientRequest() with
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifierUri = new Uri("https://sector.example.com/redirect_uris.json"),
        };

        await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.Equal(1, fetches.Count);
    }

    /// <summary>
    /// Counts the fetches asked of it and answers each with a refusal.
    /// </summary>
    private sealed class CountingFetcher : ISecureHttpFetcher
    {
        private int _count;

        public int Count => _count;

        public Task<Result<T, OidcError>> FetchAsync<T>(Uri uri, bool refetch = false)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult<Result<T, OidcError>>(
                new OidcError(ErrorCodes.InvalidClientMetadata, "The document is not served"));
        }
    }

    /// <summary>
    /// While anybody may register and the host keeps the default grant types, a client asking for a grant no end user
    /// takes part in is refused by the pipeline a host invokes.
    /// </summary>
    [Fact]
    public async Task AMachineClient_RegisteringOpenlyUnderTheDefaultGrantTypes_IsRefused()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var result = await handler.HandleAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), MachineClientRequest());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// While the host lists no resources, a registered client may get an access token for no resource, and the
    /// response says so.
    /// </summary>
    [Fact]
    public async Task AClientRegisteringOpenlyUnderTheDefaultResources_IsAllowedNoResource()
    {
        var provider = BuildProvider();
        var tenant = provider.GetRequiredService<ITenantAccessor>().CurrentTenant();

        var result = await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(tenant, CreateRequest());

        Assert.True(result.TryGetSuccess(out var success));
        Assert.Equal([], success.Metadata.AllowedResources!);
        var stored = await provider.GetRequiredService<IClientInfoProvider>().FindClientAsync(tenant, success.ClientId);
        Assert.True(stored.TryGetSuccess(out var client));
        Assert.False(client.MayGetTokenFor(new Uri("https://orders.example.com")));
    }

    /// <summary>
    /// A host naming the grant types decides them under open registration too.
    /// </summary>
    [Fact]
    public async Task AMachineClient_RegisteringOpenlyWithinTheHostsSet_IsRegistered()
    {
        var provider = BuildProvider(
            configureOptions: Granting(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials));
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var result = await handler.HandleAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), MachineClientRequest());

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// <paramref name="request"/> carrying an initial access token the tenant of <paramref name="provider"/> issued.
    /// </summary>
    private static async Task<ClientRegistrationRequest> WithInitialAccessToken(
        IServiceProvider provider,
        ClientRegistrationRequest request)
    {
        var token = await provider.GetRequiredService<IInitialAccessTokenService>().IssueTokenAsync(
            provider.GetRequiredService<ITenantAccessor>().CurrentTenant(),
            "registration-portal",
            provider.GetRequiredService<TimeProvider>().GetUtcNow(),
            TimeSpan.FromHours(1));
        return request with
        {
            AuthorizationHeaderLines = [new System.Net.Http.Headers.AuthenticationHeaderValue(TokenTypes.Bearer, token.EncodedJwt).ToString()],
        };
    }

    /// <summary>
    /// The settings for new clients have one place, <see cref="OidcOptions.NewClientOptions"/>: the server registers no
    /// service of their own a host could set without effect.
    /// </summary>
    [Fact]
    public void TheSettingsForNewClients_AreNoServiceOfTheirOwn()
        => Assert.Null(BuildProvider().GetService<NewClientOptions>());

    /// <summary>
    /// A client presenting an initial access token is held to the host's grant types as any other: under the default
    /// list, the authorization code and the refresh token, a machine client is refused.
    /// </summary>
    [Fact]
    public async Task AMachineClient_RegisteringWithAnInitialAccessTokenUnderTheDefaultGrantTypes_IsRefused()
    {
        var provider = BuildProvider(configureOptions: opts => opts.RequireInitialAccessToken = true);
        var tenant = provider.GetRequiredService<ITenantAccessor>().CurrentTenant();
        var request = await WithInitialAccessToken(provider, MachineClientRequest());

        var result = await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(tenant, request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// The same client registers with an initial access token once the host lists its grant.
    /// </summary>
    [Fact]
    public async Task AMachineClient_RegisteringWithAnInitialAccessTokenWithinTheHostsSet_IsRegistered()
    {
        var provider = BuildProvider(configureOptions: opts =>
        {
            opts.RequireInitialAccessToken = true;
            Granting(GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials)(opts);
        });
        var tenant = provider.GetRequiredService<ITenantAccessor>().CurrentTenant();
        var request = await WithInitialAccessToken(provider, MachineClientRequest());

        var result = await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(tenant, request);

        Assert.True(result.TryGetSuccess(out _),
            $"Expected success but got error: {(result.TryGetFailure(out var err) ? err.ErrorDescription : "<unknown>")}");
    }

    /// <summary>
    /// A client registering with an initial access token and naming no resource is given the host's list, empty by
    /// default, so it may get an access token for no resource.
    /// </summary>
    [Fact]
    public async Task AClientRegisteringWithAnInitialAccessTokenUnderTheDefaultResources_IsAllowedNoResource()
    {
        var provider = BuildProvider(configureOptions: opts => opts.RequireInitialAccessToken = true);
        var tenant = provider.GetRequiredService<ITenantAccessor>().CurrentTenant();
        var request = await WithInitialAccessToken(provider, CreateRequest());

        var result = await provider.GetRequiredService<IRegisterClientHandler>().HandleAsync(tenant, request);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.Equal([], success.Metadata.AllowedResources!);
        var stored = await provider.GetRequiredService<IClientInfoProvider>().FindClientAsync(tenant, success.ClientId);
        Assert.True(stored.TryGetSuccess(out var client));
        Assert.False(client.MayGetTokenFor(new Uri("https://orders.example.com")));
    }

    /// <summary>
    /// OIDC Core section 10.1: HS* signing keys on the client_secret, which this server stores only as a
    /// hash - registration asking for an HMAC-signed id_token must be rejected at DCR time instead
    /// of failing with a server error on the first issued token.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.HS256)]
    [InlineData(SigningAlgorithms.HS512)]
    public async Task HandleAsync_HmacIdTokenSignedResponseAlg_RejectsAtRegistration(string algorithm)
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest() with { IdTokenSignedResponseAlg = algorithm };

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
    }

    /// <summary>
    /// RFC 7591 section 3.2.1: the response carries grant_types, response_types and scope read back from
    /// the stored registration. Without them a client cannot learn the server-assigned defaults
    /// (authorization_code / code) when its request omitted these fields - the DCR conformance
    /// profile checks exactly this.
    /// </summary>
    [Fact]
    public async Task HandleAsync_RegistrationResponse_EchoesGrantResponseTypesAndScope()
    {
        var provider = BuildProvider();
        var handler = provider.GetRequiredService<IRegisterClientHandler>();

        var request = CreateRequest() with { Scope = [Scopes.OpenId, Scopes.Profile] };

        var result = await handler.HandleAsync(provider.GetRequiredService<ITenantAccessor>().CurrentTenant(), request);

        Assert.True(result.TryGetSuccess(out var success));
        Assert.Equal([GrantTypes.AuthorizationCode], success.Metadata.GrantTypes!);
        Assert.Equal([[ResponseTypes.Code]], success.Metadata.ResponseTypes);
        Assert.Equal([Scopes.OpenId, Scopes.Profile], success.Metadata.Scope!);
    }
}
