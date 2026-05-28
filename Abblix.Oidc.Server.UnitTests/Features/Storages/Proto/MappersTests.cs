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
using System.Globalization;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages.Proto.Mappers;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Xunit;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages.Proto;

/// <summary>
/// Unit tests for protobuf mapper extension methods verifying correct conversion
/// between C# types and protobuf messages.
/// </summary>
public class MappersTests
{
    [Theory]
    [InlineData(JsonWebTokenStatus.Unknown)]
    [InlineData(JsonWebTokenStatus.Used)]
    [InlineData(JsonWebTokenStatus.Revoked)]
    public void JsonWebTokenStatusMapper_ToProto_CorrectMapping(JsonWebTokenStatus status)
    {
        // Act
        var proto = status.ToProto();

        // Assert
        Assert.NotNull(proto);
        var result = proto.FromProto();
        Assert.Equal(status, result);
    }

    [Fact]
    public void TokenInfoMapper_ToProto_PreservesAllFields()
    {
        // Arrange
        var tokenInfo = new TokenInfo("jwt-abc123", DateTimeOffset.Parse("2025-12-31T23:59:59.123Z", CultureInfo.InvariantCulture));

        // Act
        var proto = tokenInfo.ToProto();

        // Assert
        Assert.Equal(tokenInfo.JwtId, proto.JwtId);
        Assert.NotNull(proto.ExpiresAt);

        var result = proto.FromProto();
        Assert.Equal(tokenInfo.JwtId, result.JwtId);
        // Protobuf Timestamp has microsecond precision, so we check within 1ms
        Assert.Equal(tokenInfo.ExpiresAt.ToUnixTimeMilliseconds(), result.ExpiresAt.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void RequestedClaimsMapper_ToProto_HandlesComplexClaims()
    {
        // Arrange
        var claims = new RequestedClaims
        {
            UserInfo = new()
            {
                ["email"] = new RequestedClaimDetails
                {
                    Essential = true,
                    Value = "user@example.com",
                },
                ["name"] = new RequestedClaimDetails
                {
                    Values = ["John", "Jane"],
                },
            },
            IdToken = new()
            {
                ["sub"] = new RequestedClaimDetails { Essential = false },
            },
        };

        // Act
        var proto = claims.ToProto();

        // Assert
        Assert.NotNull(proto);
        Assert.Equal(2, proto.UserInfo.Count);
        Assert.Single(proto.IdToken);

        var result = RequestedClaimsMapper.FromProto(proto);
        Assert.NotNull(result);
        Assert.NotNull(result.UserInfo);
        Assert.NotNull(result.IdToken);
        Assert.Equal(2, result.UserInfo.Count);
        Assert.True(result.UserInfo["email"].Essential);
        Assert.NotNull(result.UserInfo["name"].Values);
    }

    [Fact]
    public void RequestedClaimsMapper_ToProto_HandlesEmptyClaims()
    {
        // Arrange
        var claims = new RequestedClaims
        {
            UserInfo = null,
            IdToken = null,
        };

        // Act
        var proto = claims.ToProto();

        // Assert
        Assert.NotNull(proto);
        Assert.Empty(proto.UserInfo);
        Assert.Empty(proto.IdToken);
    }

    [Fact]
    public void AuthSessionMapper_ToProto_PreservesAllOptionalFields()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "google")
        {
            AuthContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            AffectedClientIds = ["client-1", "client-2", "client-3"],
            AuthenticationMethodReferences = ["pwd", "mfa", "face"],
            Email = "user@example.com",
            EmailVerified = true,
            AdditionalClaims = new JsonObject
            {
                ["tenant"] = "tenant-123",
                ["roles"] = new JsonArray("admin", "user"),
                ["count"] = 42,
            },
        };

        // Act
        var proto = session.ToProto();

        // Assert
        Assert.Equal(session.Subject, proto.Subject);
        Assert.Equal(session.SessionId, proto.SessionId);
        Assert.Equal(session.IdentityProvider, proto.IdentityProvider);
        Assert.Equal(session.AuthContextClassRef, proto.AuthContextClassRef);
        Assert.Equal(3, proto.AffectedClientIds.Count);
        Assert.Equal(3, proto.AuthenticationMethodReferences.Count);
        Assert.Equal(session.Email, proto.Email);
        Assert.True(proto.EmailVerified);
        Assert.NotNull(proto.AdditionalClaims);

        var result = proto.FromProto();
        Assert.Equal(session.Subject, result.Subject);
        Assert.Equal(session.Email, result.Email);
        Assert.Equal(session.EmailVerified, result.EmailVerified);
        Assert.NotNull(result.AdditionalClaims);
        Assert.Equal(42, result.AdditionalClaims["count"]!.GetValue<int>());
    }

    [Fact]
    public void AuthSessionMapper_ToProto_HandlesMinimalFields()
    {
        // Arrange - only required fields
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, null!);

        // Act
        var proto = session.ToProto();

        // Assert
        Assert.Equal(session.Subject, proto.Subject);
        Assert.Equal(string.Empty, proto.IdentityProvider); // null becomes empty string

        var result = proto.FromProto();
        Assert.Equal(session.Subject, result.Subject);
        Assert.Null(result.AuthContextClassRef);
        Assert.Empty(result.AffectedClientIds);
        Assert.Null(result.AuthenticationMethodReferences);
    }

    [Fact]
    public void AuthorizationContextMapper_ToProto_HandlesUriConversion()
    {
        // Arrange
        var context = new AuthorizationContext(
            "client-123",
            [TestConstants.DefaultScope, "profile"],
            null)
        {
            RedirectUri = new Uri("https://example.com/callback?state=xyz"),
            Resources =
            [
                new Uri("https://api.example.com/v1"),
                new Uri("https://api2.example.com/v2")
            ],
        };

        // Act
        var proto = context.ToProto();

        // Assert
        Assert.Equal("https://example.com/callback?state=xyz", proto.RedirectUri);
        Assert.Equal(2, proto.Resources.Count);

        var result = AuthorizationContextMapper.FromProto(proto);
        Assert.Equal(context.RedirectUri, result.RedirectUri);
        Assert.NotNull(result.Resources);
        Assert.Equal(2, result.Resources.Length);
        Assert.Equal(context.Resources![0], result.Resources[0]);
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_AuthorizationDetails_ByteExact()
    {
        // The wire shape we want preserved through protobuf storage — member order, a
        // type-specific extension payload (PSD2-style instructedAmount object), and
        // mixed-type values. After ToProto -> FromProto the JsonArray must serialise
        // back to the SAME wire JSON byte-for-byte (no key reordering, no whitespace
        // drift from a typed deserialise / re-serialise cycle).
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate","status"],"locations":["https://api.bank.example/payments"],"instructedAmount":{"currency":"EUR","amount":"500.00"},"creditorAccount":{"iban":"DE02100100109307118603"}},{"type":"account_information","identifier":"acct-001"}]""";

        var rawArray = (System.Text.Json.Nodes.JsonArray)System.Text.Json.Nodes.JsonNode.Parse(wireJson)!;
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            AuthorizationDetails = rawArray,
        };

        // Act
        var proto = context.ToProto();
        var result = AuthorizationContextMapper.FromProto(proto);

        // Assert — byte-exact preservation through the proto string field.
        Assert.NotNull(result.AuthorizationDetails);
        Assert.Equal(wireJson, result.AuthorizationDetails!.ToJsonString());
        Assert.Equal(wireJson, proto.AuthorizationDetailsJson);
    }

    [Fact]
    public void AuthorizationRequestMapper_RoundTrips_AuthorizationDetails_ByteExact()
    {
        // PAR storage path: the request body submitted at /par persists into protobuf
        // and is re-materialised when the client redirects to /authorize with the
        // request_uri. Byte-exact preservation is required all the way through.
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        var rawArray = (System.Text.Json.Nodes.JsonArray)System.Text.Json.Nodes.JsonNode.Parse(wireJson)!;
        var request = new Abblix.Oidc.Server.Model.AuthorizationRequest
        {
            ClientId = "client-123",
            AuthorizationDetails = rawArray,
        };

        var proto = request.ToProto();
        var result = proto.FromProto();

        Assert.Equal(wireJson, proto.AuthorizationDetailsJson);
        Assert.NotNull(result.AuthorizationDetails);
        Assert.Equal(wireJson, result.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public void AuthorizationRequestMapper_RoundTrips_NullAuthorizationDetails()
    {
        var request = new Abblix.Oidc.Server.Model.AuthorizationRequest { ClientId = "client-123" };

        var proto = request.ToProto();
        var result = proto.FromProto();

        Assert.False(proto.HasAuthorizationDetailsJson);
        Assert.Null(result.AuthorizationDetails);
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_NullAuthorizationDetails()
    {
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);

        var proto = context.ToProto();
        var result = AuthorizationContextMapper.FromProto(proto);

        Assert.False(proto.HasAuthorizationDetailsJson);
        Assert.Null(result.AuthorizationDetails);
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_EmptyAuthorizationDetails_OmittedFromProto()
    {
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            AuthorizationDetails = new System.Text.Json.Nodes.JsonArray(),
        };

        var proto = context.ToProto();

        // Empty array is treated identically to null in protobuf storage — no point
        // persisting an empty marker that yields the same observable behaviour.
        Assert.False(proto.HasAuthorizationDetailsJson);
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_Actor_ByteExact()
    {
        // RFC 8693 §4.1 act claim. The simplest delegation shape: { sub: actor-id } with no
        // nested act member. After ToProto -> FromProto the JsonObject must serialise back
        // to the same wire JSON byte-for-byte.
        const string actorJson = """{"sub":"svc-worker-7","client_id":"svc-fleet"}""";
        var actor = (JsonObject)System.Text.Json.Nodes.JsonNode.Parse(actorJson)!;

        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            Actor = actor,
        };

        var proto = context.ToProto();
        var result = AuthorizationContextMapper.FromProto(proto);

        Assert.Equal(actorJson, proto.ActorJson);
        Assert.NotNull(result.Actor);
        Assert.Equal(actorJson, result.Actor!.ToJsonString());
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_ChainedActor_PreservesNestedAct()
    {
        // Two-hop delegation: outer actor is svc-frontline, inner actor (act.act) is the
        // earlier svc-backend. Verifies the nested chain survives the storage round-trip
        // unchanged -- byte-for-byte, including member order at every depth.
        const string chainedActorJson =
            """{"sub":"svc-frontline","act":{"sub":"svc-backend"}}""";
        var actor = (JsonObject)System.Text.Json.Nodes.JsonNode.Parse(chainedActorJson)!;

        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            Actor = actor,
        };

        var proto = context.ToProto();
        var result = AuthorizationContextMapper.FromProto(proto);

        Assert.NotNull(result.Actor);
        Assert.Equal(chainedActorJson, result.Actor!.ToJsonString());
        // The nested act member must remain a JsonObject (not coerced into a string).
        Assert.IsType<JsonObject>(result.Actor["act"]);
    }

    [Fact]
    public void AuthorizationContextMapper_RoundTrips_NullActor()
    {
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);

        var proto = context.ToProto();
        var result = AuthorizationContextMapper.FromProto(proto);

        Assert.False(proto.HasActorJson);
        Assert.Null(result.Actor);
    }

    [Fact]
    public void AuthorizationContextMapper_PreUpgradeWireBytes_DeserializeWithNullNewFields()
    {
        // BACKWARD COMPAT: simulates storage records written before tags 11 (authorization_details_json)
        // and 12 (actor_json) existed. We construct a proto with only the original first-10 fields set
        // and serialise to the wire bytes that pre-upgrade code would have produced. A current reader
        // must deserialise those bytes cleanly, with the new fields surfacing as null on the C# record.
        // Proto3 optional fields are designed to behave this way, but a regression test pins the
        // observable behaviour so future schema additions can't accidentally break old storage.
        var preUpgradeProto = new Abblix.Oidc.Server.Features.Storages.Proto.AuthorizationContext
        {
            ClientId = "client-123",
            CertificateSha256Thumbprint = "x5tValue",
            ProofKeyThumbprint = "jktValue",
            RedirectUri = "https://example.com/cb",
            Nonce = "n-0S6_WzA2Mj",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "S256",
        };
        preUpgradeProto.Scope.Add("openid");
        preUpgradeProto.Resources.Add("https://api.example.com");

        // Round-trip through actual wire bytes so we're testing the protobuf parser, not a
        // shortcut through in-memory object identity.
        var wireBytes = Google.Protobuf.MessageExtensions.ToByteArray(preUpgradeProto);
        var rehydratedProto = Abblix.Oidc.Server.Features.Storages.Proto.AuthorizationContext.Parser
            .ParseFrom(wireBytes);

        var result = AuthorizationContextMapper.FromProto(rehydratedProto);

        // Original fields preserved byte-for-byte through the wire round-trip.
        Assert.Equal("client-123", result.ClientId);
        Assert.Equal("x5tValue", result.CertificateSha256Thumbprint);
        Assert.Equal("jktValue", result.ProofKeyThumbprint);
        Assert.Equal(new Uri("https://example.com/cb"), result.RedirectUri);
        Assert.Equal("n-0S6_WzA2Mj", result.Nonce);

        // New fields tolerate the absence of their tags -- this is the backward-compat invariant.
        Assert.False(rehydratedProto.HasAuthorizationDetailsJson);
        Assert.False(rehydratedProto.HasActorJson);
        Assert.Null(result.AuthorizationDetails);
        Assert.Null(result.Actor);
    }

    [Fact]
    public void AuthorizationContextMapper_NewWireBytes_PreserveBothAuthorizationDetailsAndActor()
    {
        // FORWARD COMPAT proof: a context populated with both new fields serialises and
        // re-parses byte-exactly. Together with the previous test, this pins the wire shape
        // both with the new fields present and absent.
        const string adWire = """[{"type":"payment_initiation","actions":["initiate"]}]""";
        const string actorWire = """{"sub":"svc-actor"}""";

        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            AuthorizationDetails = (System.Text.Json.Nodes.JsonArray)System.Text.Json.Nodes.JsonNode.Parse(adWire)!,
            Actor = (JsonObject)System.Text.Json.Nodes.JsonNode.Parse(actorWire)!,
        };

        var wireBytes = Google.Protobuf.MessageExtensions.ToByteArray(context.ToProto());
        var rehydratedProto = Abblix.Oidc.Server.Features.Storages.Proto.AuthorizationContext.Parser
            .ParseFrom(wireBytes);
        var result = AuthorizationContextMapper.FromProto(rehydratedProto);

        Assert.True(rehydratedProto.HasAuthorizationDetailsJson);
        Assert.True(rehydratedProto.HasActorJson);
        Assert.Equal(adWire, result.AuthorizationDetails!.ToJsonString());
        Assert.Equal(actorWire, result.Actor!.ToJsonString());
    }

    [Fact]
    public void AuthorizationContextMapper_ToProto_HandlesPkce()
    {
        // Arrange
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null)
        {
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "S256",
            Nonce = "n-0S6_WzA2Mj",
        };

        // Act
        var proto = context.ToProto();

        // Assert
        Assert.Equal(context.CodeChallenge, proto.CodeChallenge);
        Assert.Equal(context.CodeChallengeMethod, proto.CodeChallengeMethod);
        Assert.Equal(context.Nonce, proto.Nonce);

        var result = AuthorizationContextMapper.FromProto(proto);
        Assert.Equal(context.CodeChallenge, result.CodeChallenge);
        Assert.Equal(context.CodeChallengeMethod, result.CodeChallengeMethod);
        Assert.Equal(context.Nonce, result.Nonce);
    }

    [Fact]
    public void AuthorizedGrantMapper_ToProto_HandlesIssuedTokens()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context)
        {
            IssuedTokens =
            [
                new TokenInfo("access-123", DateTimeOffset.UtcNow.AddHours(1)),
                new TokenInfo("refresh-456", DateTimeOffset.UtcNow.AddDays(30)),
                new TokenInfo("id-789", DateTimeOffset.UtcNow.AddHours(1))
            ],
        };

        // Act
        var proto = grant.ToProto();

        // Assert
        Assert.Equal(3, proto.IssuedTokens.Count);
        Assert.Equal("access-123", proto.IssuedTokens[0].JwtId);

        var result = proto.FromProto();
        Assert.NotNull(result.IssuedTokens);
        Assert.Equal(3, result.IssuedTokens.Length);
        Assert.Equal(grant.IssuedTokens[0].JwtId, result.IssuedTokens[0].JwtId);
    }

    [Fact]
    public void AuthorizedGrantMapper_ToProto_HandlesNullTokens()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context); // No IssuedTokens

        // Act
        var proto = grant.ToProto();

        // Assert
        Assert.Empty(proto.IssuedTokens);

        var result = proto.FromProto();
        Assert.Null(result.IssuedTokens);
    }

    [Fact]
    public void AuthorizationRequestMapper_ToProto_HandlesCultureInfo()
    {
        // Arrange
        var request = new AuthorizationRequest
        {
            Scope = [TestConstants.DefaultScope],
            UiLocales =
            [
                new CultureInfo("en-US"),
                new CultureInfo("fr-FR"),
                new CultureInfo("de-DE")
            ],
            ClaimsLocales = [new CultureInfo("en-GB")],
        };

        // Act
        var proto = request.ToProto();

        // Assert
        Assert.Equal(3, proto.UiLocales.Count);
        Assert.Equal("en-US", proto.UiLocales[0]);
        Assert.Equal("fr-FR", proto.UiLocales[1]);
        Assert.Single(proto.ClaimsLocales);

        var result = proto.FromProto();
        Assert.NotNull(result.UiLocales);
        Assert.Equal(3, result.UiLocales.Length);
        Assert.Equal("en-US", result.UiLocales[0].Name);
        Assert.Equal("fr-FR", result.UiLocales[1].Name);
        Assert.NotNull(result.ClaimsLocales);
        Assert.Equal("en-GB", result.ClaimsLocales[0].Name);
    }

    [Fact]
    public void AuthorizationRequestMapper_ToProto_HandlesMaxAge()
    {
        // Arrange
        var request = new AuthorizationRequest
        {
            Scope = [TestConstants.DefaultScope],
            MaxAge = TimeSpan.FromMinutes(30),
        };

        // Act
        var proto = request.ToProto();

        // Assert
        Assert.NotNull(proto.MaxAge);

        var result = proto.FromProto();
        Assert.NotNull(result.MaxAge);
        Assert.Equal(TimeSpan.FromMinutes(30), result.MaxAge);
    }

    [Fact]
    public void AuthorizationRequestMapper_ToProto_HandlesAllOptionalFields()
    {
        // Arrange
        var request = new AuthorizationRequest
        {
            Scope = [TestConstants.DefaultScope, "profile", "email"],
            Claims = new RequestedClaims
            {
                IdToken = new() { ["email"] = new RequestedClaimDetails { Essential = true } },
            },
            ResponseType = ["code", "id_token"],
            ClientId = "client-123",
            RedirectUri = new Uri(TestConstants.DefaultRedirectUri),
            State = "state-xyz",
            ResponseMode = "form_post",
            Nonce = "nonce-abc",
            Display = "popup",
            Prompt = "login consent",
            MaxAge = TimeSpan.FromMinutes(15),
            IdTokenHint = "eyJhbGc...",
            LoginHint = "user@example.com",
            AcrValues = ["urn:mace:incommon:iap:silver"],
            CodeChallenge = "challenge",
            CodeChallengeMethod = "S256",
            Request = "eyJhbGc...",
            RequestUri = new Uri("https://example.com/request.jwt"),
            Resources = [new Uri("https://api.example.com")],
        };

        // Act
        var proto = request.ToProto();

        // Assert - verify all fields are serialized
        Assert.Equal(3, proto.Scope.Count);
        Assert.NotNull(proto.Claims);
        Assert.Equal(2, proto.ResponseType.Count);
        Assert.Equal("client-123", proto.ClientId);
        Assert.Equal(TestConstants.DefaultRedirectUri, proto.RedirectUri);
        Assert.Equal("state-xyz", proto.State);
        Assert.Equal("form_post", proto.ResponseMode);
        Assert.Equal("nonce-abc", proto.Nonce);
        Assert.Equal("popup", proto.Display);
        Assert.Equal("login consent", proto.Prompt);
        Assert.NotNull(proto.MaxAge);
        Assert.Equal("eyJhbGc...", proto.IdTokenHint);
        Assert.Equal("user@example.com", proto.LoginHint);
        Assert.Single(proto.AcrValues);
        Assert.Equal("challenge", proto.CodeChallenge);
        Assert.Equal("S256", proto.CodeChallengeMethod);
        Assert.Equal("eyJhbGc...", proto.Request);
        Assert.Equal("https://example.com/request.jwt", proto.RequestUri);
        Assert.Single(proto.Resources);

        var result = proto.FromProto();
        Assert.Equal(request.ClientId, result.ClientId);
        Assert.Equal(request.State, result.State);
        Assert.Equal(request.Nonce, result.Nonce);
    }

    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Pending)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    public void BackChannelAuthenticationRequestMapper_ToProto_HandlesStatus(
        BackChannelAuthenticationStatus status)
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context);
        var request = new BackChannelAuthenticationRequest(grant, DateTimeOffset.UtcNow.AddMinutes(5)) { Status = status };

        // Act
        var proto = request.ToProto();

        // Assert
        var result = proto.FromProto();
        Assert.Equal(status, result.Status);
    }

    [Fact]
    public void BackChannelAuthenticationRequestMapper_ToProto_HandlesNextPollAt()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context);
        var nextPoll = DateTimeOffset.UtcNow.AddSeconds(45);
        var request = new BackChannelAuthenticationRequest(grant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            NextPollAt = nextPoll,
            Status = BackChannelAuthenticationStatus.Pending,
        };

        // Act
        var proto = request.ToProto();

        // Assert
        Assert.NotNull(proto.NextPollAt);

        var result = proto.FromProto();
        Assert.NotNull(result.NextPollAt);
        // Compare with millisecond precision
        Assert.Equal(nextPoll.ToUnixTimeMilliseconds(), result.NextPollAt.Value.ToUnixTimeMilliseconds());
    }

    [Fact]
    public void BackChannelAuthenticationRequestMapper_ToProto_HandlesNullNextPollAt()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context);
        var request = new BackChannelAuthenticationRequest(grant, DateTimeOffset.UtcNow.AddMinutes(5)); // NextPollAt is null

        // Act
        var proto = request.ToProto();

        // Assert
        var result = proto.FromProto();
        Assert.Null(result.NextPollAt);
    }
}
