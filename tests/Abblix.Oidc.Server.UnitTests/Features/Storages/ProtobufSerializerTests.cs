// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Storages.Proto;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Logging;
using Xunit;
using AuthorizationContext = Abblix.Oidc.Server.Common.AuthorizationContext;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;
using AuthorizedGrant = Abblix.Oidc.Server.Endpoints.Token.Interfaces.AuthorizedGrant;
using AuthSession = Abblix.Oidc.Server.Features.UserAuthentication.AuthSession;
using BackChannelAuthenticationRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using BackChannelAuthenticationStatus = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationStatus;
using JsonWebTokenStatus = Abblix.Oidc.Server.Features.Tokens.Revocation.JsonWebTokenStatus;
using RequestedClaimDetails = Abblix.Oidc.Server.Model.RequestedClaimDetails;
using RequestedClaims = Abblix.Oidc.Server.Model.RequestedClaims;
using TokenInfo = Abblix.Oidc.Server.Endpoints.Token.Interfaces.TokenInfo;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// Unit tests for <see cref="ProtobufSerializer"/> verifying protobuf serialization
/// round-trip for all OIDC storage types.
/// </summary>
public class ProtobufSerializerTests
{
    private readonly ProtobufSerializer _serializer = new();

    /// <summary>
    /// The next-poll instant survives a round trip.
    /// </summary>
    [Fact]
    public void Serialize_PollSchedule_RoundTrip()
    {
        var instant = DateTimeOffset.Parse("2026-01-01T12:00:05Z", CultureInfo.InvariantCulture);

        var bytes = _serializer.Serialize(new PollSchedule { NextPollAt = instant.ToTimestamp() });
        var result = _serializer.Deserialize<PollSchedule>(bytes);

        Assert.NotNull(result);
        Assert.Equal(instant, result.NextPollAt.ToDateTimeOffset());
    }

    /// <summary>
    /// The value a session's outstanding logout question was asked with survives a round trip; without it no
    /// answer would ever match and no logout could be confirmed.
    /// </summary>
    [Fact]
    public void Serialize_LogoutConfirmation_RoundTrip()
    {
        var result = _serializer.Deserialize<LogoutConfirmation>(
            _serializer.Serialize(new LogoutConfirmation { Confirmation = "the-value-that-asks" }));

        Assert.NotNull(result);
        Assert.Equal("the-value-that-asks", result.Confirmation);
    }

    /// <summary>
    /// One recorded verification attempt survives a round trip.
    /// </summary>
    [Fact]
    public void Serialize_RateLimitAttempt_RoundTrip()
    {
        var instant = DateTimeOffset.Parse("2026-01-01T12:00:00Z", CultureInfo.InvariantCulture);

        var bytes = _serializer.Serialize(new RateLimitAttempt { At = instant.ToTimestamp() });
        var result = _serializer.Deserialize<RateLimitAttempt>(bytes);

        Assert.NotNull(result);
        Assert.Equal(instant, result.At.ToDateTimeOffset());
    }

    /// <summary>
    /// A rate-limit generation survives a round trip.
    /// </summary>
    /// <remarks>
    /// One is the value a reader gets for a generation nobody has written yet, so it is the boundary the row
    /// below sits against; three hundred is past the first byte a number occupies on the wire, which the small
    /// values never reach.
    /// </remarks>
    [Theory]
    [InlineData(1)]
    [InlineData(300)]
    public void Serialize_RateLimitGeneration_RoundTrip(int value)
    {
        var result = _serializer.Deserialize<RateLimitGeneration>(
            _serializer.Serialize(new RateLimitGeneration { Value = value }));

        Assert.NotNull(result);
        Assert.Equal(value, result.Value);
    }

    /// <summary>
    /// A generation of zero is written as nothing at all, and this serializer reads nothing as no record - so the
    /// two are one state, and a fixture that keeps them apart is holding behavior no deployment has.
    /// </summary>
    /// <remarks>
    /// The empty payload is the wire format: a number at its default value is not written. Reading it back as
    /// absent is this serializer's own decision, taken for every shape at once, so a deployment that supplies its
    /// own storage need not share it. Nothing writes a zero here in any case - generations start at one and only
    /// climb - which is why the rows that matter are the fixtures, not this one.
    /// </remarks>
    [Fact]
    public void ARateLimitGenerationOfZero_IsWrittenAsNothingAndReadBackAsNoRecord()
    {
        var bytes = _serializer.Serialize(new RateLimitGeneration { Value = 0 });

        Assert.Empty(bytes);
        Assert.Null(_serializer.Deserialize<RateLimitGeneration>(bytes));
    }

    /// <summary>
    /// A recorded client of a session and the generation it belongs to survive a round trip.
    /// </summary>
    [Fact]
    public void Serialize_SessionClientRecords_RoundTrip()
    {
        var end = DateTimeOffset.Parse("2026-01-01T12:00:00Z", CultureInfo.InvariantCulture);

        var client = _serializer.Deserialize<Abblix.Oidc.Server.Features.Storages.Proto.SessionClient>(
            _serializer.Serialize(new Abblix.Oidc.Server.Features.Storages.Proto.SessionClient { ClientId = "client-1" }));
        var generation = _serializer.Deserialize<Abblix.Oidc.Server.Features.Storages.Proto.SessionClientsGeneration>(
            _serializer.Serialize(new Abblix.Oidc.Server.Features.Storages.Proto.SessionClientsGeneration { Id = "g-1", ExpiresAt = end.ToTimestamp() }));

        Assert.Equal("client-1", client?.ClientId);
        Assert.Equal("g-1", generation?.Id);
        Assert.Equal(end, generation?.ExpiresAt.ToDateTimeOffset());
    }

    /// <summary>
    /// None of the shapes stored as they are reaches the JSON fallback, which is the reason they have
    /// definitions at all.
    /// </summary>
    /// <remarks>
    /// The fallback works and would carry them, so a round trip alone says nothing here - it passes either
    /// way. What it costs is a warning carrying an exception on every write, and one of these is written on
    /// every poll of every device and every decoupled authentication. A warning an operator sees that often
    /// is a warning they stop reading.
    /// <para>
    /// Every value here is a non-default one, because a message at its defaults is written as nothing and read
    /// back without the reader ever being consulted - so a row built on defaults would say nothing about the
    /// half it looks like it covers.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheShapesStoredAsThemselves_DoNotReachTheJsonFallback()
    {
        var recorder = new RecordingLoggerFactory();
        var composite = new CompositeBinarySerializer(
            recorder.CreateLogger<CompositeBinarySerializer>(),
            new ProtobufSerializer(),
            new JsonBinarySerializer());

        var instant = DateTimeOffset.Parse("2026-01-01T12:00:00Z", CultureInfo.InvariantCulture);

        composite.Deserialize<RevocationCutoff>(
            composite.Serialize(new RevocationCutoff { Cutoff = instant.ToTimestamp() }));
        composite.Deserialize<PollSchedule>(
            composite.Serialize(new PollSchedule { NextPollAt = instant.ToTimestamp() }));
        composite.Deserialize<RateLimitAttempt>(
            composite.Serialize(new RateLimitAttempt { At = instant.ToTimestamp() }));
        composite.Deserialize<RateLimitGeneration>(
            composite.Serialize(new RateLimitGeneration { Value = 2 }));
        composite.Deserialize<Abblix.Oidc.Server.Features.Storages.Proto.SessionClient>(
            composite.Serialize(new Abblix.Oidc.Server.Features.Storages.Proto.SessionClient { ClientId = "client-1" }));
        composite.Deserialize<Abblix.Oidc.Server.Features.Storages.Proto.SessionClientsGeneration>(
            composite.Serialize(new Abblix.Oidc.Server.Features.Storages.Proto.SessionClientsGeneration { Id = "g-1", ExpiresAt = instant.ToTimestamp() }));
        composite.Deserialize<LogoutConfirmation>(
            composite.Serialize(new LogoutConfirmation { Confirmation = "the-value-that-asks" }));

        Assert.Empty(recorder.Entries);
    }

    [Theory]
    [InlineData(JsonWebTokenStatus.Unknown)]
    [InlineData(JsonWebTokenStatus.Used)]
    [InlineData(JsonWebTokenStatus.Revoked)]
    public void Serialize_JsonWebTokenStatus_RoundTrip(JsonWebTokenStatus status)
    {
        // Act
        var bytes = _serializer.Serialize(status);
        var result = _serializer.Deserialize<JsonWebTokenStatus>(bytes);

        // Assert
        Assert.Equal(status, result);
    }

    [Fact]
    public void Serialize_TokenInfo_RoundTrip()
    {
        // Arrange
        var tokenInfo = new TokenInfo("jwt-123", DateTimeOffset.Parse("2025-12-31T23:59:59Z", CultureInfo.InvariantCulture));

        // Act
        var bytes = _serializer.Serialize(tokenInfo);
        var result = _serializer.Deserialize<TokenInfo>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(tokenInfo.JwtId, result.JwtId);
        Assert.Equal(tokenInfo.ExpiresAt, result.ExpiresAt);
    }

    [Fact]
    public void Serialize_RequestedClaims_RoundTrip()
    {
        // Arrange
        var claims = new RequestedClaims
        {
            UserInfo = new()
            {
                ["email"] = new RequestedClaimDetails { Essential = true },
                ["name"] = new RequestedClaimDetails { Value = "John Doe" },
            },
            IdToken = new()
            {
                ["sub"] = new RequestedClaimDetails { Essential = true },
                ["roles"] = new RequestedClaimDetails { Values = ["admin", "user"] },
            },
        };

        // Act
        var bytes = _serializer.Serialize(claims);
        var result = _serializer.Deserialize<RequestedClaims>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.UserInfo);
        Assert.NotNull(result.IdToken);
        Assert.Equal(2, result.UserInfo.Count);
        Assert.Equal(2, result.IdToken.Count);
        Assert.True(result.UserInfo["email"].Essential);
        Assert.True(result.IdToken["sub"].Essential);
    }

    [Fact]
    public void Serialize_AuthSession_RoundTrip()
    {
        // Arrange
        var session = new AuthSession(
            "user-123",
            "session-456",
            DateTimeOffset.Parse("2025-01-15T10:30:00Z", CultureInfo.InvariantCulture),
            "local")
        {
            AuthContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AuthenticationMethodReferences = ["pwd", "mfa"],
            Email = "user@example.com",
            EmailVerified = true,
            AdditionalClaims = new JsonObject
            {
                ["tenant_id"] = "tenant-123",
                ["roles"] = new JsonArray("admin", "user"),
            },
        };

        // Act
        var bytes = _serializer.Serialize(session);
        var result = _serializer.Deserialize<AuthSession>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Subject, result.Subject);
        Assert.Equal(session.SessionId, result.SessionId);
        Assert.Equal(session.AuthenticationTime, result.AuthenticationTime);
        Assert.Equal(session.IdentityProvider, result.IdentityProvider);
        Assert.Equal(session.AuthContextClassRef, result.AuthContextClassRef);
        Assert.Equal(session.AuthenticationMethodReferences, result.AuthenticationMethodReferences);
        Assert.Equal(session.Email, result.Email);
        Assert.Equal(session.EmailVerified, result.EmailVerified);
        Assert.NotNull(result.AdditionalClaims);
        Assert.Equal("tenant-123", result.AdditionalClaims["tenant_id"]!.ToString());
    }

    [Fact]
    public void Serialize_AuthorizationContext_RoundTrip()
    {
        // Arrange
        var context = new AuthorizationContext(
            "client-123",
            [TestConstants.DefaultScope, "profile", "email"],
            new RequestedClaims
            {
                IdToken = new() { ["sub"] = new RequestedClaimDetails { Essential = true } },
            })
        {
            CertificateSha256Thumbprint = "abc123def456",
            RedirectUri = TestConstants.DefaultRedirectUri,
            Nonce = "nonce-789",
            CodeChallenge = "challenge-xyz",
            CodeChallengeMethod = "S256",
            Resources = [new Uri("https://api.example.com")],
        };

        // Act
        var bytes = _serializer.Serialize(context);
        var result = _serializer.Deserialize<AuthorizationContext>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(context.ClientId, result.ClientId);
        Assert.Equal(context.Scope, result.Scope);
        Assert.Equal(context.CertificateSha256Thumbprint, result.CertificateSha256Thumbprint);
        Assert.Equal(context.RedirectUri, result.RedirectUri);
        Assert.Equal(context.Nonce, result.Nonce);
        Assert.Equal(context.CodeChallenge, result.CodeChallenge);
        Assert.Equal(context.CodeChallengeMethod, result.CodeChallengeMethod);
        Assert.NotNull(result.Resources);
        Assert.Single(result.Resources);
        Assert.Equal(context.Resources![0], result.Resources[0]);
    }

    [Fact]
    public void Serialize_AuthorizedGrant_RoundTrip()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context)
        {
            IssuedTokens =
            [
                new TokenInfo("access-token-1", DateTimeOffset.UtcNow.AddHours(1)),
                new TokenInfo("refresh-token-1", DateTimeOffset.UtcNow.AddDays(30))
            ],
        };

        // Act
        var bytes = _serializer.Serialize(grant);
        var result = _serializer.Deserialize<AuthorizedGrant>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(grant.AuthSession.Subject, result.AuthSession.Subject);
        Assert.Equal(grant.Context.ClientId, result.Context.ClientId);
        Assert.NotNull(result.IssuedTokens);
        Assert.Equal(2, result.IssuedTokens.Length);
        Assert.Equal(grant.IssuedTokens[0].JwtId, result.IssuedTokens[0].JwtId);
    }

    [Fact]
    public void Serialize_AuthorizationRequest_RoundTrip()
    {
        // Arrange
        var request = new AuthorizationRequest
        {
            Scope = [TestConstants.DefaultScope, "profile", "email"],
            ResponseType = ["code"],
            ClientId = "client-123",
            RedirectUri = TestConstants.DefaultRedirectUri,
            State = "state-xyz",
            ResponseMode = "query",
            Nonce = "nonce-abc",
            Display = "page",
            Prompt = "consent",
            MaxAge = TimeSpan.FromMinutes(30),
            UiLocales = [new CultureInfo("en-US"), new CultureInfo("fr-FR")],
            ClaimsLocales = [new CultureInfo("en-US")],
            IdTokenHint = "eyJhbGc...",
            LoginHint = "user@example.com",
            AcrValues = ["urn:mace:incommon:iap:silver"],
            CodeChallenge = "challenge-xyz",
            CodeChallengeMethod = "S256",
            Request = "eyJhbGc...",
            RequestUri = new Uri("https://example.com/request.jwt"),
            Resources = [new Uri("https://api.example.com")],
            Claims = new RequestedClaims
            {
                IdToken = new() { ["email"] = new RequestedClaimDetails { Essential = true } },
            },
        };

        // Act
        var bytes = _serializer.Serialize(request);
        var result = _serializer.Deserialize<AuthorizationRequest>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(request.Scope, result.Scope);
        Assert.Equal(request.ResponseType, result.ResponseType);
        Assert.Equal(request.ClientId, result.ClientId);
        Assert.Equal(request.RedirectUri, result.RedirectUri);
        Assert.Equal(request.State, result.State);
        Assert.Equal(request.ResponseMode, result.ResponseMode);
        Assert.Equal(request.Nonce, result.Nonce);
        Assert.Equal(request.Display, result.Display);
        Assert.Equal(request.Prompt, result.Prompt);
        Assert.Equal(request.MaxAge, result.MaxAge);
        Assert.NotNull(result.UiLocales);
        Assert.Equal(2, result.UiLocales.Length);
        Assert.Equal("en-US", result.UiLocales[0].Name);
        Assert.Equal("fr-FR", result.UiLocales[1].Name);
        Assert.Equal(request.IdTokenHint, result.IdTokenHint);
        Assert.Equal(request.LoginHint, result.LoginHint);
        Assert.Equal(request.AcrValues, result.AcrValues);
        Assert.Equal(request.CodeChallenge, result.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, result.CodeChallengeMethod);
        Assert.Equal(request.Request, result.Request);
        Assert.Equal(request.RequestUri, result.RequestUri);
        Assert.NotNull(result.Resources);
        Assert.Single(result.Resources);
        Assert.NotNull(result.Claims);
    }

    [Theory]
    [InlineData(BackChannelAuthenticationStatus.Pending)]
    [InlineData(BackChannelAuthenticationStatus.Denied)]
    [InlineData(BackChannelAuthenticationStatus.Authenticated)]
    public void Serialize_BackChannelAuthenticationRequest_RoundTrip(BackChannelAuthenticationStatus status)
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        var context = new AuthorizationContext("client-123", [TestConstants.DefaultScope], null);
        var grant = new AuthorizedGrant(session, context);
        var bcRequest = new BackChannelAuthenticationRequest(grant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            Status = status,
        };

        // Act
        var bytes = _serializer.Serialize(bcRequest);
        var result = _serializer.Deserialize<BackChannelAuthenticationRequest>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(bcRequest.Status, result.Status);
        Assert.Equal(bcRequest.AuthorizedGrant.AuthSession.Subject, result.AuthorizedGrant.AuthSession.Subject);
    }

    [Fact]
    public void Serialize_RequestedClaims_WithOneEmptyCollection_RoundTrip()
    {
        // Arrange - RequestedClaims with minimal content
        var claims = new RequestedClaims
        {
            UserInfo = new Dictionary<string, RequestedClaimDetails>
            {
                ["email"] = new RequestedClaimDetails { Essential = true }
            },
            IdToken = null,
        };

        // Act
        var bytes = _serializer.Serialize(claims);
        var result = _serializer.Deserialize<RequestedClaims>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.UserInfo);
        Assert.Single(result.UserInfo);
        Assert.Null(result.IdToken);
    }

    [Fact]
    public void Deserialize_EmptyBytes_ReturnsDefault()
    {
        // Act
        var result = _serializer.Deserialize<TokenInfo>([]);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Serialize_UnsupportedType_ThrowsException()
    {
        // Arrange
        var unsupported = new { Value = "test" };

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => _serializer.Serialize(unsupported));
        Assert.Contains("not supported for protobuf serialization", ex.Message);
    }

    [Fact]
    public void Deserialize_UnsupportedType_ThrowsException()
    {
        // Arrange
        var bytes = new byte[] { 1, 2, 3 };

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => _serializer.Deserialize<int>(bytes));
        Assert.Contains("not supported for protobuf deserialization", ex.Message);
    }

    [Fact]
    public void Serialize_AuthSession_MinimalFields_RoundTrip()
    {
        // Arrange - only required fields
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");

        // Act
        var bytes = _serializer.Serialize(session);
        var result = _serializer.Deserialize<AuthSession>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Subject, result.Subject);
        Assert.Equal(session.SessionId, result.SessionId);
        Assert.Null(result.AuthContextClassRef);
        Assert.Null(result.Email);
        Assert.Null(result.EmailVerified);
        Assert.Null(result.AdditionalClaims);
    }

    /// <summary>
    /// A session stored by a release that kept the session's clients inside it, as field 6, still reads back.
    /// </summary>
    /// <remarks>
    /// Such a session sits inside every authorization code issued before an upgrade.
    /// </remarks>
    [Fact]
    public void Deserialize_AuthSessionStoredWithAClientList_StillReads()
    {
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local");
        const string clientId = "client-1";

        // Field 6, wire type 2 (length-delimited): the tag byte is (6 << 3) | 2.
        byte[] clientListField = [(6 << 3) | 2, (byte)clientId.Length, ..System.Text.Encoding.ASCII.GetBytes(clientId)];
        byte[] stored = [.._serializer.Serialize(session), ..clientListField];

        var result = _serializer.Deserialize<AuthSession>(stored);

        Assert.Equal(session.SessionId, result?.SessionId);
    }

    [Fact]
    public void Serialize_CompareWithJsonSerializer_ProducesSmaller()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local")
        {
            AuthenticationMethodReferences = ["pwd", "mfa", "otp"],
            Email = "user@example.com",
        };

        var jsonSerializer = new JsonBinarySerializer();

        // Act
        var protobufBytes = _serializer.Serialize(session);
        var jsonBytes = jsonSerializer.Serialize(session);

        // Assert - Protobuf should be smaller
        Assert.True(protobufBytes.Length < jsonBytes.Length,
            $"Protobuf ({protobufBytes.Length} bytes) should be smaller than JSON ({jsonBytes.Length} bytes)");
    }
}
