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
using System.Globalization;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.Storages;
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
        var tokenInfo = new TokenInfo("jwt-123", DateTimeOffset.Parse("2025-12-31T23:59:59Z"));

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
            DateTimeOffset.Parse("2025-01-15T10:30:00Z"),
            "local")
        {
            AuthContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AffectedClientIds = ["client-1", "client-2"],
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
        Assert.Equal(session.AffectedClientIds, result.AffectedClientIds);
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
            ["openid", "profile", "email"],
            new RequestedClaims
            {
                IdToken = new() { ["sub"] = new RequestedClaimDetails { Essential = true } },
            })
        {
            X509CertificateSha256Thumbprint = "abc123def456",
            RedirectUri = new Uri("https://example.com/callback"),
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
        Assert.Equal(context.X509CertificateSha256Thumbprint, result.X509CertificateSha256Thumbprint);
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
        var context = new AuthorizationContext("client-123", ["openid"], null);
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
            Scope = ["openid", "profile", "email"],
            ResponseType = ["code"],
            ClientId = "client-123",
            RedirectUri = new Uri("https://example.com/callback"),
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
        var context = new AuthorizationContext("client-123", ["openid"], null);
        var grant = new AuthorizedGrant(session, context);
        var bcRequest = new BackChannelAuthenticationRequest(grant, DateTimeOffset.UtcNow.AddMinutes(5))
        {
            NextPollAt = DateTimeOffset.UtcNow.AddSeconds(30),
            Status = status,
        };

        // Act
        var bytes = _serializer.Serialize(bcRequest);
        var result = _serializer.Deserialize<BackChannelAuthenticationRequest>(bytes);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(bcRequest.Status, result.Status);
        Assert.NotNull(result.NextPollAt);
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

    [Fact]
    public void Serialize_CompareWithJsonSerializer_ProducesSmaller()
    {
        // Arrange
        var session = new AuthSession("user-123", "session-456", DateTimeOffset.UtcNow, "local")
        {
            AffectedClientIds = ["client-1", "client-2", "client-3"],
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
