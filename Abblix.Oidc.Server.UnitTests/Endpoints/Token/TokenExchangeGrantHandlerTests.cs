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
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
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
public class TokenExchangeGrantHandlerTests
{
    private const string ClientId = "test-client";
    private const string SubjectTokenWire = "header.payload.signature";
    private const string TestSubject = "user-7";
    private const string TestSessionId = "test-session";

    private readonly Mock<ISessionIdGenerator> _sessionIdGenerator = new(MockBehavior.Strict);
    private readonly FakeTimeProvider _timeProvider = new();

    public TokenExchangeGrantHandlerTests()
    {
        _sessionIdGenerator.Setup(g => g.GenerateSessionId()).Returns(TestSessionId);
    }

    /// <summary>
    /// RFC 8693 §2.1 / RFC 6749 §5.2: a request without subject_token or subject_token_type is the
    /// caller's protocol error and yields invalid_request — previously it threw and surfaced as
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
            SubjectTokenType = subjectTokenType,
        };

        var result = await handler.AuthorizeAsync(request, ClientWithAllowlist(null));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
    }

    [Fact]
    public async Task ValidSubjectToken_DispatchedToTypedResolver_ReturnsAuthorizedGrant()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: "https://issuer", Scope: ["openid"], AuthorizationDetails: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

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
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetails: adNode);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.AuthorizationDetails);
        Assert.Equal(adWire, grant.Context.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task UnregisteredSubjectTokenType_RejectsWithInvalidRequest()
    {
        // No resolver registered for the request's type. ALLOWLIST is null so the per-client
        // check passes through, but the keyed lookup at the resolver step fails.
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist(null);
        var request = ExchangeRequest("urn:ietf:params:oauth:token-type:saml2");

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("saml2", error.ErrorDescription);
        Assert.Contains("not supported", error.ErrorDescription);
    }

    [Fact]
    public async Task EmptyAllowlist_RejectsEveryRequest()
    {
        var handler = CreateHandlerWithoutResolvers();
        var clientInfo = ClientWithAllowlist();  // empty -> deny-all
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

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

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allow list", error.ErrorDescription);
    }

    [Fact]
    public async Task DelegationFlow_BuildsActClaimWithActorSubject()
    {
        // Single-hop delegation: subject_token has no prior act chain. Result: act = { sub: <actor> }.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null);
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null);
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(actorWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
        Assert.NotNull(grant.Context.Actor);
        Assert.Equal("svc-worker-7", grant.Context.Actor!["sub"]!.GetValue<string>());
        Assert.Null(grant.Context.Actor["act"]);
    }

    [Fact]
    public async Task ChainedDelegation_PrependsExistingActChain()
    {
        // Subject_token already carries an act chain: { sub: prev-actor }. New actor wraps it:
        // result act = { sub: new-actor, act: { sub: prev-actor } }.
        var existingChain = new JsonObject { ["sub"] = "prev-actor" };
        var subject = new SubjectTokenContext("alice", null, ["openid"], null) { Act = existingChain };
        var actor = new SubjectTokenContext("svc-worker-7", null, null, null);
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(actorWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("svc-worker-7", grant.Context.Actor!["sub"]!.GetValue<string>());
        var nested = grant.Context.Actor["act"] as JsonObject;
        Assert.NotNull(nested);
        Assert.Equal("prev-actor", nested!["sub"]!.GetValue<string>());
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

        var result = await handler.AuthorizeAsync(request, clientInfo);

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
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,  // value missing
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("together", error.ErrorDescription);
    }

    [Fact]
    public async Task ActorResolverFailure_PropagatedWithPrefix()
    {
        // actor_token resolution failure is wrapped so the wire client can distinguish actor
        // problems from subject problems even though both map to invalid_request.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null);
        const string actorWire = "actor.jwt";
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(actorWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidRequest, "actor expired"));

        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("actor_token", error.ErrorDescription);
        Assert.Contains("actor expired", error.ErrorDescription);
    }

    [Fact]
    public async Task ResolverFailure_Propagated()
    {
        // Resolver returns an OidcError -- the handler propagates it without rewrapping so
        // resolver-specific failure descriptions reach the wire client (RFC 8693 §2.2.2 maps
        // every error to invalid_request at the wire, but the description preserves diagnostic
        // detail).
        var (handler, resolverMock) = CreateHandlerWithResolverMock(TokenExchangeTokenTypes.AccessToken);
        resolverMock
            .Setup(r => r.ResolveAsync(SubjectTokenWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidRequest, "subject expired"));
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Equal("subject expired", error.ErrorDescription);
    }

    [Fact]
    public async Task ClientWithNullAllowlist_AcceptsAnyResolvedTokenType()
    {
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.IdToken, ctx);
        var clientInfo = ClientWithAllowlist(null);  // tri-state: no constraint
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(TestSubject, grant.AuthSession.Subject);
    }

    [Fact]
    public async Task RequestScope_OverridesSubjectScope()
    {
        var subjectScope = new[] { "openid", "profile", "email" };
        var requestScope = new[] { "openid" };  // narrow to one
        var ctx = new SubjectTokenContext(
            Subject: TestSubject, Issuer: null, Scope: subjectScope, AuthorizationDetails: null);
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, ctx);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with { Scope = requestScope };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(requestScope, grant.Context.Scope);
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
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = "client-A",
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requestingClient = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken); // ClientId = "test-client"
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, requestingClient);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("issued to a different client", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task S1_SubjectToken_cross_client_allowed_when_client_opted_in()
    {
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = "client-A",
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var brokerClient = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [TokenExchangeTokenTypes.AccessToken],
            AllowCrossClientSubjectTokenExchange = true,  // explicit opt-in for broker scenarios
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, brokerClient);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("alice", grant.AuthSession.Subject);
    }

    [Fact]
    public async Task S1_SubjectToken_same_client_accepted_without_opt_in()
    {
        // Baseline: when subject_token's original client == requesting client (the normal
        // self-exchange case), default policy accepts without opt-in.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requestingClient = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, requestingClient);

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
        var subject = new SubjectTokenContext("alice", null, ["openid"], ad)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientWithDifferentAllowlist = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [TokenExchangeTokenTypes.AccessToken],
            AuthorizationDetailsTypes = ["account_information"],  // does NOT include payment_initiation
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientWithDifferentAllowlist);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("payment_initiation", error.ErrorDescription);
    }

    [Fact]
    public async Task S2_Audience_parameter_propagates_when_allowlisted()
    {
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        // Default-deny: the requested audiences must be on the client's audience allowlist.
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com", "https://api2.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Audiences = ["https://api1.example.com", "https://api2.example.com"],
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(request.Audiences, grant.Context.Audiences);
    }

    [Fact]
    public async Task Audience_rejected_when_client_has_no_allowlist()
    {
        // Default-deny: a client that requests an audience without an explicit
        // TokenExchangeAllowedAudiences allowlist is rejected with invalid_target. Otherwise the
        // client could mint a token for any target service it names in the issued token's aud.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken); // no audience allowlist
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Audiences = ["https://victim.example.com"],
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
    }

    [Fact]
    public async Task Audience_rejected_when_not_in_allowlist()
    {
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        clientInfo.TokenExchangeAllowedAudiences = ["https://api1.example.com"];
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            // One allowlisted, two not — the whole request must be rejected and EVERY disallowed
            // audience reported, so the client can fix them all in one round-trip.
            Audiences = ["https://api1.example.com", "https://api2.example.com", "https://api3.example.com"],
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidTarget, error.Error);
        Assert.Contains("api2.example.com", error.ErrorDescription);
        Assert.Contains("api3.example.com", error.ErrorDescription);
        Assert.DoesNotContain("api1.example.com", error.ErrorDescription);
    }

    [Fact]
    public async Task S2_Resource_parameter_propagates_to_AuthorizationContext()
    {
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            Resources = [new Uri("https://api.example.com")],
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.NotNull(grant.Context.Resources);
        Assert.Single(grant.Context.Resources!);
        Assert.Equal(request.Resources[0], grant.Context.Resources![0]);
    }

    [Fact]
    public async Task S2_RequestedTokenType_other_than_access_token_rejected_explicitly()
    {
        // Slice 1 issues only access_token. A client asking for id_token / refresh_token / jwt
        // must be rejected loudly rather than silently downgraded -- otherwise the client
        // assumes it got what it asked for and breaks downstream.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken) with
        {
            RequestedTokenType = TokenExchangeTokenTypes.IdToken,
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("requested_token_type", error.ErrorDescription);
    }

    [Fact]
    public async Task S3_IdTokenTyp_rejected_when_subject_token_type_is_access_token()
    {
        // A JWT minted as id_token (typ=id+jwt) presented under subject_token_type=access_token
        // is a cross-type confusion: id_tokens carry identity assertions, not authorisation,
        // and may have different audience expectations. Reject even though signature validates.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.IdToken,  // typ mismatch
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var clientInfo = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken);
        var request = ExchangeRequest(TokenExchangeTokenTypes.AccessToken);

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("typ", error.ErrorDescription);
    }

    [Fact]
    public async Task C3_ActorTokenType_not_in_allowlist_rejected_same_as_subject()
    {
        // The TokenExchangeAllowedSubjectTokenTypes allowlist applies symmetrically to actor
        // tokens -- if the client is not permitted to exchange access_token as a SUBJECT, they
        // are not permitted to use access_token as an ACTOR either.
        var subject = new SubjectTokenContext("alice", null, ["openid"], null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        const string actorWire = "actor.jwt";
        var actor = new SubjectTokenContext("svc-worker", null, null, null)
        {
            OriginalClientId = ClientId,
            JwtTokenType = JwtTypes.AccessToken,
        };
        var (handler, resolverMock) = CreateHandlerWith(TokenExchangeTokenTypes.IdToken, subject);
        resolverMock
            .Setup(r => r.ResolveAsync(actorWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(actor);

        // Client allowlist only id_token (subject); actor_token_type=access_token NOT in allowlist.
        var clientInfo = new ClientInfo(ClientId)
        {
            TokenExchangeAllowedSubjectTokenTypes = [TokenExchangeTokenTypes.IdToken],
        };
        var request = ExchangeRequest(TokenExchangeTokenTypes.IdToken) with
        {
            ActorToken = actorWire,
            ActorTokenType = TokenExchangeTokenTypes.AccessToken,  // not in allowlist
        };

        var result = await handler.AuthorizeAsync(request, clientInfo);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidRequest, error.Error);
        Assert.Contains("allow list", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    // ──── helpers ────

    private (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock) CreateHandlerWith(
        string tokenType, SubjectTokenContext resolvedContext)
    {
        var (handler, resolverMock) = CreateHandlerWithResolverMock(tokenType);
        resolverMock
            .Setup(r => r.ResolveAsync(SubjectTokenWire, It.IsAny<CancellationToken>()))
            .ReturnsAsync(resolvedContext);
        return (handler, resolverMock);
    }

    private (TokenExchangeGrantHandler Handler, Mock<ISubjectTokenResolver> ResolverMock)
        CreateHandlerWithResolverMock(string tokenType)
    {
        var resolverMock = new Mock<ISubjectTokenResolver>(MockBehavior.Strict);

        var services = new ServiceCollection();
        services.AddKeyedSingleton(tokenType, resolverMock.Object);
        var sp = services.BuildServiceProvider();

        var handler = new TokenExchangeGrantHandler(sp, _sessionIdGenerator.Object, _timeProvider);
        return (handler, resolverMock);
    }

    private TokenExchangeGrantHandler CreateHandlerWithoutResolvers()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        return new TokenExchangeGrantHandler(sp, _sessionIdGenerator.Object, _timeProvider);
    }

    private static ClientInfo ClientWithAllowlist(params string[]? allowlist) =>
        new(ClientId) { TokenExchangeAllowedSubjectTokenTypes = allowlist };

    private static TokenRequest ExchangeRequest(string subjectTokenType) => new()
    {
        GrantType = GrantTypes.TokenExchange,
        SubjectToken = SubjectTokenWire,
        SubjectTokenType = subjectTokenType,
    };
}
