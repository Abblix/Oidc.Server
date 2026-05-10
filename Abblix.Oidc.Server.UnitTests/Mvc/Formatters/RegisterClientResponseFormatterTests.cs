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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Utils;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Mvc.Formatters;

/// <summary>
/// Unit tests for <see cref="RegisterClientResponseFormatter"/>. Locks the bridge from the
/// internal <see cref="ClientRegistrationSuccessResponse"/> business-shape into the
/// public-API <see cref="ClientRegistrationResponse"/> wire-shape, with emphasis on the
/// RFC 7591 §3.2.1 «echo registered metadata» surface and the RFC 9449 §5.2
/// <c>dpop_bound_access_tokens</c> field. Without these tests, fields added on
/// <see cref="ClientRegistrationSuccessResponse"/> stay unsurfaced on the JSON payload —
/// the failure mode that prompted writing this suite (slice #108).
/// </summary>
public class RegisterClientResponseFormatterTests
{
    private static readonly Uri ConfigurationEndpoint = new("https://auth.example.com/register/abc");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private static readonly Uri JwksUri = new("https://client.example.com/jwks");
    private static readonly Uri SectorIdentifierUri = new("https://client.example.com/sectors");

    private static readonly DateTimeOffset IssuedAt = new(2026, 5, 10, 12, 0, 0, TimeSpan.Zero);

    private readonly Mock<IUriResolver> _uriResolver = new(MockBehavior.Strict);
    private readonly RegisterClientResponseFormatter _formatter;

    public RegisterClientResponseFormatterTests()
    {
        _uriResolver
            .Setup(r => r.Action(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<object?>()))
            .Returns(ConfigurationEndpoint);

        _formatter = new RegisterClientResponseFormatter(_uriResolver.Object);
    }

    [Fact]
    public async Task FormatResponseAsync_DpopBoundAccessTokensTrue_EchoedOnWireShape()
    {
        var result = await FormatAsync(BuildSuccess(dpopBoundAccessTokens: true));

        var wire = AssertCreated(result);
        Assert.True(wire.DpopBoundAccessTokens);
    }

    [Fact]
    public async Task FormatResponseAsync_DpopBoundAccessTokensFalse_EchoedOnWireShape()
    {
        var result = await FormatAsync(BuildSuccess(dpopBoundAccessTokens: false));

        var wire = AssertCreated(result);
        Assert.False(wire.DpopBoundAccessTokens);
    }

    [Fact]
    public async Task FormatResponseAsync_RfcMetadata_EchoedOnWireShape()
    {
        // RFC 7591 §3.2.1 echo: registered metadata MUST appear on the wire response.
        var success = BuildSuccess(dpopBoundAccessTokens: null) with
        {
            RedirectUris = [RedirectUri],
            ApplicationType = "web",
            ClientName = "Test Client",
            JwksUri = JwksUri,
            SectorIdentifierUri = SectorIdentifierUri,
            SubjectType = "public",
            Contacts = ["security@client.example.com"],
        };

        var result = await FormatAsync(success);

        var wire = AssertCreated(result);
        Assert.NotNull(wire.RedirectUris);
        Assert.Single(wire.RedirectUris);
        Assert.Equal(RedirectUri, wire.RedirectUris[0]);
        Assert.Equal("web", wire.ApplicationType);
        Assert.Equal("Test Client", wire.ClientName);
        Assert.Equal(JwksUri, wire.JwksUri);
        Assert.Equal(SectorIdentifierUri, wire.SectorIdentifierUri);
        Assert.Equal("public", wire.SubjectType);
        Assert.NotNull(wire.Contacts);
        Assert.Single(wire.Contacts);
    }

    [Fact]
    public async Task FormatResponseAsync_TlsClientAuthMetadata_EchoedOnWireShape()
    {
        // RFC 8705 mTLS metadata also flows through the bridge unchanged.
        var success = BuildSuccess(dpopBoundAccessTokens: null) with
        {
            TlsClientAuthSubjectDn = "CN=client,O=test",
            TlsClientAuthSanDns = ["client.example.com"],
        };

        var result = await FormatAsync(success);

        var wire = AssertCreated(result);
        Assert.Equal("CN=client,O=test", wire.TlsClientAuthSubjectDn);
        Assert.NotNull(wire.TlsClientAuthSanDns);
        Assert.Single(wire.TlsClientAuthSanDns);
    }

    [Fact]
    public async Task FormatResponseAsync_FailureResult_Returns400()
    {
        var error = new OidcError(ErrorCodes.InvalidClientMetadata, "bad metadata");

        var result = await _formatter.FormatResponseAsync(
            new ClientRegistrationRequest(),
            error);

        var objectResult = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, objectResult.StatusCode);
    }

    private Task<ActionResult> FormatAsync(ClientRegistrationSuccessResponse success)
        => _formatter.FormatResponseAsync(new ClientRegistrationRequest(), success);

    private static ClientRegistrationResponse AssertCreated(ActionResult result)
    {
        var objectResult = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status201Created, objectResult.StatusCode);
        return Assert.IsType<ClientRegistrationResponse>(objectResult.Value);
    }

    private static ClientRegistrationSuccessResponse BuildSuccess(bool? dpopBoundAccessTokens)
        => new(
            ClientId: "client-id-1",
            ClientIdIssuedAt: IssuedAt,
            RegistrationAccessToken: "registration-access-token")
        {
            DpopBoundAccessTokens = dpopBoundAccessTokens,
        };
}
