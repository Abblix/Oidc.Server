// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Unit tests for <see cref="TokenExchangeGrantHandler"/> -- RFC 8693 Token Exchange. After slice 2
/// the handler dispatches per-format subject token validation through keyed
/// <see cref="ISubjectTokenResolver"/> registrations; these tests stub the resolver via
/// in-memory DI and assert the handler's pipeline (allowlist, actor rejection, dispatch,
/// grant assembly) without involving JWT validation.
/// </summary>
public partial class TokenExchangeGrantHandlerTests
{
    private const string ClientId = "test-client";
    private const string SubjectTokenWire = "header.payload.signature";
    private const string TestSubject = "user-7";
    private const string TestSessionId = "test-session";
    private static readonly DateTimeOffset TestAuthenticationTime = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);


    /// <summary>
    /// RFC 8693 section 2.1 / RFC 6749 section 5.2: a request without subject_token or subject_token_type is the
    /// caller's protocol error and yields invalid_request - previously it threw and surfaced as
    /// HTTP 500.
    /// </summary>
    [Theory]
    [InlineData(null, TokenExchangeTokenTypes.AccessToken)]
    [InlineData(SubjectTokenWire, null)]
    public async Task AuthorizeAsync_MissingRequiredParameter_ReturnsInvalidRequest(
        string? subjectToken, string? subjectTokenType)
    {
        var handler = CreateHandlerWithoutResolvers();
        var request = new TokenRequest
        {
            GrantType = GrantTypes.TokenExchange,
            SubjectToken = subjectToken,
            SubjectTokenType = subjectTokenType is null ? null : new Uri(subjectTokenType),
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, ClientWithAllowlist(null), Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task ValidSubjectToken_DispatchedToTypedResolver_ReturnsAuthorizedGrant()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: "https://issuer", Scope: [Scopes.OpenId], AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
        Assert.Equal(ClientId, grant.Context.ClientId);
    }

    [Fact]
    public async Task SubjectTokenAuthorizationDetails_ForwardedToContext_ByteExact()
    {
        const string adWire = """[{"type":"payment_initiation","actions":["initiate"]}]""";
        var adNode = (JsonArray)JsonNode.Parse(adWire)!;
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetails: adNode)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.AuthorizationDetails);
        Assert.Equal(adWire, grant.Context.AuthorizationDetails.ToJsonString());
    }

    /// <summary>
    /// The DPoP key and the certificate the subject token is bound to bind the exchange grant, so the token endpoint
    /// requires a proof of them (RFC 9449 section 5, RFC 8705 section 4).
    /// </summary>
    [Fact]
    public async Task TheSubjectTokensBinding_BindsTheExchangeGrant()
    {
        var ctx = new SubjectTokenContext(TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
        {
            SessionId = TestSessionId,
            AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
            ProofKeyThumbprint = "the-dpop-key-thumbprint",
            CertificateSha256Thumbprint = "the-certificate-thumbprint",
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("the-dpop-key-thumbprint", grant.Context.ProofKeyThumbprint);
        Assert.Equal("the-certificate-thumbprint", grant.Context.CertificateSha256Thumbprint);
    }

    [Fact]
    public async Task UnregisteredSubjectTokenType_RejectsWithInvalidRequest()
    {
        // No resolver registered for the request's type. ALLOWLIST is null so the per-client
        // check passes through, but the keyed lookup at the resolver step fails.
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(null);
        var request = ExchangeRequest(TokenExchangeTokenTypes.Saml2);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("saml2", error.ErrorDescription);
        Assert.Contains("not supported", error.ErrorDescription);
    }

    /// <summary>
    /// A token type is an identifier compared as written (RFC 8693 section 3), so the same URI spelled with another
    /// case of its scheme reaches no resolver registered under the usual spelling.
    /// </summary>
    [Fact]
    public async Task ATokenTypeSpelledOtherwise_ReachesNoResolver()
    {
        var ctx = new SubjectTokenContext(TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(UpperCaseScheme(TokenExchangeTokenTypes.AccessToken)),
            ClientWithAllowlist(null),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    /// <summary>
    /// The client's allow list is compared with the token type as written, so a type allowed in one spelling is
    /// refused in another even when a resolver answers that other spelling.
    /// </summary>
    [Fact]
    public async Task ATokenTypeSpelledOtherwise_IsNotInTheAllowList()
    {
        var spelledOtherwise = UpperCaseScheme(TokenExchangeTokenTypes.AccessToken);
        var ctx = new SubjectTokenContext(TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(spelledOtherwise, ctx);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(spelledOtherwise),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    private static string UpperCaseScheme(string uri)
        => string.Concat(uri[..uri.IndexOf(':')].ToUpperInvariant(), uri[uri.IndexOf(':')..]);

    [Fact]
    public async Task EmptyAllowlist_RejectsEveryRequest()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist();  // empty -> deny-all
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("not permitted", error.ErrorDescription);
    }

    [Fact]
    public async Task SubjectTokenTypeNotInAllowlist_Rejected()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.IdToken);  // only id_token allowed
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allow list", error.ErrorDescription);
    }

    /// <summary>
    /// The exchanged grant carries the subject_token's refresh token family, so revoking that family refuses the
    /// exchanged token too; a subject_token belonging to no family leaves the exchange in none.
    /// </summary>
    [Theory]
    [InlineData("grant_of_the_subject_token")]
    [InlineData(null)]
    public async Task ExchangedGrant_CarriesTheSubjectTokensFamily(string? grantId)
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
            GrantId = grantId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(grantId, grant.GrantId);
    }

    /// <summary>
    /// A token obtained by exchange expires no later than its subject_token, within a refresh token family or not, so
    /// an exchange never extends the authority it hands on.
    /// </summary>
    [Theory]
    [InlineData("grant_of_the_subject_token")]
    [InlineData(null)]
    public async Task ExchangedGrant_ExpiresNoLaterThanTheSubjectToken(string? grantId)
    {
        var subjectExpiresAt = new DateTimeOffset(2024, 1, 15, 13, 0, 0, TimeSpan.Zero);
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
            GrantId = grantId,
            ExpiresAt = subjectExpiresAt,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(subjectExpiresAt, grant.ExpiresNoLaterThan);
    }

    [Fact]
    public async Task DelegationFlow_BuildsActClaimWithActorSubject()
    {
        // Single-hop delegation: subject_token has no prior act chain. Result: act = { sub: <actor> }.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null) { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null) { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        // A token of the caller's own, told apart from every other, so each resolution can be shown to have
        // received it: an exchange spends nothing, so a resolver making a remote call may stop when the caller does.
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), caller.Token);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
        Assert.NotNull(grant.Context.Actor);
        Assert.Equal("svc-worker-7", grant.Context.Actor["sub"]!.GetValue<string>());
        Assert.Null(grant.Context.Actor["act"]);
        resolverMock.Verify(r => r.ResolveAsync(TestTenant.Matched, clientInfo, It.IsAny<IClientInfoProvider>(), SubjectTokenWire, It.IsAny<Uri>(), caller.Token), Times.Once);
        resolverMock.Verify(r => r.ResolveAsync(TestTenant.Matched, clientInfo, It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), caller.Token), Times.Once);
    }

    /// <summary>
    /// The exchanged token belongs to the session of its subject_token and never to the actor's, so revoking the end
    /// user's session reaches a delegated token too.
    /// </summary>
    [Fact]
    public async Task ExchangedToken_BelongsToTheSubjectTokensSession_NotTheActors()
    {
        const string subjectSession = "subject-session";
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
            { SessionId = subjectSession, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null)
            { SessionId = "actor-session", AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant, request, ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(subjectSession, grant.AuthSession.SessionId);
    }

    /// <summary>
    /// The exchanged token tells of the sign-in its subject_token tells of - when, by which context class and by which
    /// methods - and never of the actor's, so an exchange does not pass for a new sign-in.
    /// </summary>
    [Fact]
    public async Task ExchangedToken_TellsOfTheSubjectTokensSignIn_NotTheActors()
    {
        var subjectSignedInAt = new DateTimeOffset(2024, 1, 15, 9, 30, 0, TimeSpan.Zero);
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId,
            AuthenticationTime = subjectSignedInAt,
            AuthContextClassRef = "urn:example:acr:subject",
            AuthenticationMethodReferences = ["pwd", "otp"],
            OriginalClientId = ClientId,
        };
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null)
        {
            SessionId = "actor-session",
            AuthenticationTime = subjectSignedInAt.AddHours(1),
            AuthContextClassRef = "urn:example:acr:actor",
            AuthenticationMethodReferences = ["hwk"],
            OriginalClientId = ClientId,
        };
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant, request, ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(subjectSignedInAt, grant.AuthSession.AuthenticationTime);
        Assert.Equal("urn:example:acr:subject", grant.AuthSession.AuthContextClassRef);
        Assert.Equal(["pwd", "otp"], grant.AuthSession.AuthenticationMethodReferences!);
    }

    /// <summary>
    /// The exchanged token names the identity provider of the sign-in its subject_token belongs to, whichever kind
    /// of token that is; only a subject_token naming none falls back to the party that issued it.
    /// </summary>
    [Theory]
    [InlineData("https://upstream.example.com", "https://issuer.example.com", "https://upstream.example.com")]
    [InlineData(null, "https://issuer.example.com", "https://issuer.example.com")]
    public async Task ExchangedToken_NamesTheSignInsIdentityProvider(
        string? identityProvider, string issuer, string expected)
    {
        var subject = new SubjectTokenContext("alice", issuer, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId,
            AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
            IdentityProvider = identityProvider,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(expected, grant.AuthSession.IdentityProvider);
    }

    [Fact]
    public async Task ChainedDelegation_PrependsExistingActChain()
    {
        // Subject_token already carries an act chain: { sub: prev-actor }. New actor wraps it:
        // result act = { sub: new-actor, act: { sub: prev-actor } }.
        var existingChain = new JsonObject { ["sub"] = "prev-actor" };
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null) { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, Act = existingChain, OriginalClientId = ClientId };
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null) { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("svc-worker-7", grant.Context.Actor!["sub"]!.GetValue<string>());
        var nested = grant.Context.Actor["act"] as JsonObject;
        Assert.NotNull(nested);
        Assert.Equal("prev-actor", nested["sub"]!.GetValue<string>());
    }

    /// <summary>
    /// A delegated subject_token exchanged without an actor_token still acts for somebody else, so the issued token
    /// carries its act chain unchanged rather than presenting the delegate as the user acting directly.
    /// </summary>
    [Fact]
    public async Task ADelegatedSubjectToken_ExchangedWithoutAnActor_KeepsItsActChain()
    {
        var existingChain = new JsonObject
        {
            [IanaClaimTypes.Sub] = "current-actor",
            [IanaClaimTypes.Act] = new JsonObject { [IanaClaimTypes.Sub] = "prior-actor" },
        };
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId,
            AuthenticationTime = TestAuthenticationTime,
            Act = existingChain,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken),
            Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.True(JsonNode.DeepEquals(existingChain, grant.Context.Actor));
        Assert.NotSame(existingChain, grant.Context.Actor);
    }

    [Fact]
    public async Task ActorTokenWithoutType_Rejected()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = "actor.jwt",  // type missing
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("together", error.ErrorDescription);
    }

    [Fact]
    public async Task ActorTokenTypeWithoutToken_Rejected()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),  // value missing
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("together", error.ErrorDescription);
    }

    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, ErrorCodes.InvalidRequest)]
    [InlineData(ErrorCodes.InvalidGrant, ErrorCodes.InvalidRequest)]
    [InlineData(ErrorCodes.ServerError, ErrorCodes.ServerError)]
    [InlineData(ErrorCodes.TemporarilyUnavailable, ErrorCodes.TemporarilyUnavailable)]
    public async Task ActorResolverFailure_PropagatedWithPrefix(string resolverError, string expectedError)
    {
        // actor_token resolution failure is wrapped so the wire client can distinguish actor
        // problems from subject problems even though both map to invalid_request.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null) { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OidcError(resolverError, "actor expired"));

        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(expectedError, error.Error);
        Assert.Contains("actor_token", error.ErrorDescription);
        Assert.Contains("actor expired", error.ErrorDescription);
    }

    /// <summary>
    /// RFC 8693 section 2.2.2: when "the subject_token ... [is] invalid for any reason, or [is] unacceptable based
    /// on policy ... The value of the "error" parameter MUST be the "invalid_request" error code", so a resolver a
    /// host registers that rejects the token reaches the wire with invalid_request whatever code it answered with.
    /// A resolver that could not judge the token at all (server_error, temporarily_unavailable) says nothing about
    /// the token, so its answer reaches the client unchanged rather than telling it to discard a token that may be
    /// fine.
    /// </summary>
    [Theory]
    [InlineData(ErrorCodes.InvalidRequest, ErrorCodes.InvalidRequest)]
    [InlineData(ErrorCodes.InvalidGrant, ErrorCodes.InvalidRequest)]
    [InlineData(ErrorCodes.ServerError, ErrorCodes.ServerError)]
    [InlineData(ErrorCodes.TemporarilyUnavailable, ErrorCodes.TemporarilyUnavailable)]
    public async Task ResolverFailure_Propagated(string resolverError, string expectedError)
    {
        var (handler, resolverMock) = CreateHandlerWithResolverMock(TokenExchangeTokenTypes.AccessToken);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), SubjectTokenWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OidcError(resolverError, "subject expired"));
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(expectedError, error.Error);
        Assert.Contains(TokenRequest.Parameters.SubjectToken, error.ErrorDescription);
    }

    [Fact]
    public async Task ClientWithNullAllowlist_AcceptsAnyResolvedTokenType()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.IdToken, ctx);
        var clientInfo = ClientWithAllowlist(null);  // tri-state: no constraint
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
    }

    [Fact]
    public async Task RequestScope_OverridesSubjectScope()
    {
        var subjectScope = new[] { Scopes.OpenId, Scopes.Profile, Scopes.Email };
        var requestScope = new[] { Scopes.OpenId };  // narrow to one
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: subjectScope, AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = requestScope };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(requestScope, grant.Context.Scope);
    }

    /// <summary>
    /// 2b: when the request omits scope, the handler falls back to the subject_token's scope. The
    /// explicit request.Scope path is gated against the requesting client's AllowedScopes by
    /// ScopeValidator in the token pipeline, but the fallback path is not - so an inherited scope the
    /// broker client was never registered for must be filtered out rather than leaking into the token.
    /// </summary>
    [Fact]
    public async Task InheritedSubjectScope_FilteredToRequestingClientAllowedScopes()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: [Scopes.OpenId, Scopes.Profile, "admin"], AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
            AllowedScopes = [Scopes.OpenId, Scopes.Profile], // NOT registered for "admin"
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken); // no explicit scope -> fallback

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.DoesNotContain("admin", grant.Context.Scope);
        Assert.Equal([Scopes.OpenId, Scopes.Profile], grant.Context.Scope);
    }

    /// <summary>
    /// Companion to <see cref="InheritedSubjectScope_FilteredToRequestingClientAllowedScopes"/>: a null
    /// (tri-state "no per-client restriction") AllowedScopes leaves the inherited scope untouched,
    /// matching ScopeManager.Validate's treatment of the explicit path. Locks that the 2b filter does
    /// not over-restrict clients that intentionally run without a scope allow-list.
    /// </summary>
    [Fact]
    public async Task InheritedSubjectScope_WithNullAllowedScopes_PassesThroughUnfiltered()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: [Scopes.OpenId, "admin"], AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
            AllowedScopes = null, // no per-client restriction
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal([Scopes.OpenId, "admin"], grant.Context.Scope);
    }

    /// <summary>
    /// 2a: when the subject_token carries a scope, an explicitly requested scope is bound to it, so an
    /// exchange cannot amplify authority beyond the presented token (least-privilege). Here the client
    /// asks for "read admin" against a subject token that only holds "read"; "admin" is dropped.
    /// </summary>
    [Fact]
    public async Task RequestScope_IntersectedWithSubjectScope_WhenSubjectCarriesScope()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: ["read"], AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = ["read", "admin"] };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.DoesNotContain("admin", grant.Context.Scope);
        Assert.Equal(["read"], grant.Context.Scope);
    }

    /// <summary>
    /// 2a binds a requested scope to a subject token carrying an empty scope as to any other scope it carries, so
    /// a token granted no scope is not exchanged for one holding a scope.
    /// </summary>
    [Fact]
    public async Task RequestScope_BoundToAnEmptySubjectScope()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: [], AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = ["api:read"] };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Empty(grant.Context.Scope);
    }

    /// <summary>
    /// 2a must not break the RFC 8693 id_token → access_token scenario: an id_token subject token carries
    /// no scope claim, which imposes no scope upper bound, so an explicitly requested scope passes through
    /// unchanged instead of being intersected down to nothing.
    /// </summary>
    [Fact]
    public async Task RequestScope_PreservedWhenSubjectTokenHasNoScope()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
            { SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime, OriginalClientId = ClientId };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = ["api:read"] };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(["api:read"], grant.Context.Scope);
    }

    // ───────────────────────────────────────────────────────────────────────
    // PR #135 review findings -- TDD reproduction tests.
    // S1: cross-client subject_token reuse (confused-deputy)
    // S1-second: forwarded AD bypasses requesting client's allowlist
    // S2: requested_token_type / audience / resource silently dropped
    // S3: JWT typ-header cross-type confusion
    // C2 / C3 verified incidentally where applicable.
    // ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task S1_SubjectToken_issued_to_different_client_rejected_by_default()
    {
        // Subject token was issued to client-A; client-B presents it for exchange.
        // Default policy MUST reject -- otherwise any leaked AS-signed token is exchangeable
        // by any client (confused deputy).
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = "client-A",
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requestingClient = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken); // ClientId = "test-client"
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, requestingClient, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("issued to a different client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task S1_SubjectToken_with_undeterminable_origin_rejected_by_default()
    {
        // A subject_token whose issuing client cannot be read is the case the confused-deputy check
        // cannot decide, so it must refuse rather than skip: a token shaped to hide its origin would
        // otherwise clear the guard that a token naming another client fails.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = null,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requestingClient = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, requestingClient, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("could not be determined", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task S1_SubjectToken_with_undeterminable_origin_allowed_when_client_opted_in()
    {
        // The opt-out covers both shapes the guard refuses: a token issued to another client, and one
        // whose issuer cannot be read at all. A broker trusted with the first is trusted with the second.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = null,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var brokerClient = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
            CrossClientSubjectTokenExchange = CrossClientSubjectTokenExchange.Any,
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, brokerClient, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
    }

    [Fact]
    public async Task S1_SubjectToken_cross_client_allowed_when_client_opted_in()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = "client-A",
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var brokerClient = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
            CrossClientSubjectTokenExchange = CrossClientSubjectTokenExchange.Any,  // explicit opt-in for broker scenarios
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, brokerClient, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
    }

    [Fact]
    public async Task S1_SubjectToken_same_client_accepted_without_opt_in()
    {
        // Baseline: when subject_token's original client == requesting client (the normal
        // self-exchange case), default policy accepts without opt-in.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requestingClient = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, requestingClient, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
    }

    [Fact]
    public async Task S1_second_ForwardedAD_not_in_requesting_client_allowlist_rejected()
    {
        // Subject_token carries authorization_details with type "payment_initiation".
        // Requesting client's AuthorizationDetailsTypes allowlist excludes "payment_initiation".
        // The handler MUST reject -- without this check, Client A's expensive grants would
        // flow into Client B even if Client B was never authorised to use them.
        var ad = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], ad)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientWithDifferentAllowlist = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.AccessToken)],
            AuthorizationDetailsTypes = ["account_information"],  // does NOT include payment_initiation
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientWithDifferentAllowlist, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("payment_initiation", error.ErrorDescription);
    }

    [Fact]
    public async Task S2_Audience_parameter_propagates_when_allowlisted()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        // Default-deny: the requested audiences must be on the client's audience allowlist.
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com", "https://api2.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Audiences = ["https://api1.example.com", "https://api2.example.com"],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(request.Audiences, grant.Context.Audiences);
    }

    [Fact]
    public async Task Audience_rejected_when_client_has_no_allowlist()
    {
        // Default-deny: a client that requests an audience without an explicit
        // TokenExchangeAllowedAudiences allowlist is rejected with invalid_target. Otherwise the
        // client could mint a token for any target service it names in the issued token's aud.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken); // no audience allowlist
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Audiences = ["https://victim.example.com"],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
    }

    [Fact]
    public async Task Audience_rejected_when_not_in_allowlist()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            // One allowlisted, two not - the whole request must be rejected and EVERY disallowed
            // audience reported, so the client can fix them all in one round-trip.
            Audiences = ["https://api1.example.com", "https://api2.example.com", "https://api3.example.com"],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
        Assert.Contains("api2.example.com", error.ErrorDescription);
        Assert.Contains("api3.example.com", error.ErrorDescription);
        Assert.DoesNotContain("api1.example.com", error.ErrorDescription);
    }

    [Fact]
    public async Task Resource_rejected_when_not_in_declared_audience_allowlist()
    {
        // RFC 8707 resource values land in the issued token's aud claim exactly like RFC 8693
        // audience values do, so a client restricted to api1 must not escape to api2 simply by
        // renaming the parameter from audience to resource.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Resources = [new Uri("https://api2.example.com")],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
        Assert.Contains("api2.example.com", error.ErrorDescription);
    }

    [Fact]
    public async Task Resource_and_audience_propagate_when_both_in_declared_allowlist()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com", "https://api2.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Audiences = ["https://api1.example.com"],
            Resources = [new Uri("https://api2.example.com")],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(request.Audiences, grant.Context.Audiences);
        Assert.Equal(request.Resources, grant.Context.Resources);
    }

    [Fact]
    public async Task S2_Resource_parameter_propagates_to_AuthorizationContext()
    {
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Resources = [new Uri("https://api.example.com")],
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.Resources);
        Assert.Single(grant.Context.Resources);
        Assert.Equal(request.Resources[0], grant.Context.Resources[0]);
    }

    [Fact]
    public async Task S2_RequestedTokenType_other_than_access_token_rejected_explicitly()
    {
        // Slice 1 issues only access_token. A client asking for id_token / refresh_token / jwt
        // must be rejected loudly rather than silently downgraded -- otherwise the client
        // assumes it got what it asked for and breaks downstream.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            RequestedTokenType = TokenExchangeTokenTypes.IdToken,
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("requested_token_type", error.ErrorDescription);
    }

    [Fact]
    public async Task C3_ActorTokenType_not_in_allowlist_rejected_same_as_subject()
    {
        // The TokenExchangeAllowedSubjectTokenTypes allowlist applies symmetrically to actor
        // tokens -- if the client is not permitted to exchange access_token as a SUBJECT, they
        // are not permitted to use access_token as an ACTOR either.
        var subject = new SubjectTokenContext("alice", null, [Scopes.OpenId], null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        const string actorWire = "actor.jwt";
        var actor = new SubjectTokenContext("svc-worker", null, null, null)
        {
            SessionId = TestSessionId, AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = ClientId,
        };
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.IdToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), actorWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);

        // Client allowlist only id_token (subject); actor_token_type=access_token NOT in allowlist.
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [new Uri(TokenExchangeTokenTypes.IdToken)],
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = new Uri(TokenExchangeTokenTypes.AccessToken),  // not in allowlist
        };

        var result = await handler.AuthorizeAsync(SingleIssuer.Tenant, request, clientInfo, Mock.Of<IClientInfoProvider>(), TestContext.Current.CancellationToken);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allow list", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    // ──── helpers ────

    private static (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock) CreateHandlerWith(
        string tokenType, SubjectTokenContext resolvedContext)
    {
        var (handler, resolverMock) = CreateHandlerWithResolverMock(tokenType);
        resolverMock
            .Setup(r => r.ResolveAsync(TestTenant.Matched, It.IsAny<ClientInfo>(), It.IsAny<IClientInfoProvider>(), SubjectTokenWire, It.IsAny<Uri>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(resolvedContext);
        return (handler, resolverMock);
    }

    private static (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock)
        CreateHandlerWithResolverMock(string tokenType)
    {
        var resolverMock = new Mock<ISubjectTokenResolver>(MockBehavior.Strict);

        var services = new ServiceCollection();
        services.AddKeyedSingleton(tokenType, resolverMock.Object);
        var sp = services.BuildServiceProvider();

        var handler = new TokenExchangeGrantHandler(sp);
        return (handler, resolverMock);
    }

    private static TokenExchangeGrantHandler CreateHandlerWithoutResolvers()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        return new TokenExchangeGrantHandler(sp);
    }

    private static ClientInfo ClientWithAllowlist(params string[]? allowlist) =>
        new(ClientId) { TokenExchangeAllowedSubjectTokenTypes = allowlist?.Select(type => new Uri(type)).ToArray() };

    private static TokenRequest ExchangeRequest(string subjectTokenType) => new()
    {
        GrantType = GrantTypes.TokenExchange,
        SubjectToken = SubjectTokenWire,
        SubjectTokenType = subjectTokenType is null ? null : new Uri(subjectTokenType),
    };
}
