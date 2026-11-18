// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// Unit tests for <see cref="ProofKeyThumbprintValidator"/>: the syntactic check on the
/// RFC 9449 section 10 <c>dpop_jkt</c> authorization-request parameter (exactly 43 base64url
/// characters, no padding - the encoded length of an RFC 7638 SHA-256 JWK thumbprint).
/// </summary>
public class ProofKeyThumbprintValidatorTests
{
    private const string ValidThumbprint = "Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nVbA9Y";

    private readonly ProofKeyThumbprintValidator _validator = new();

    private static AuthorizationValidationContext CreateContext(string? thumbprint)
    {
        var request = new AuthorizationRequest
        {
            ClientId = TestConstants.DefaultClientId,
            ResponseType = [ResponseTypes.Code],
            RedirectUri = new Uri("https://client.example.com/callback"),
            Scope = [Scopes.OpenId],
            ProofKeyThumbprint = thumbprint,
        };
        return new AuthorizationValidationContext(request)
        {
            ClientInfo = new ClientInfo(TestConstants.DefaultClientId),
            ResponseMode = ResponseModes.Query,
            ValidRedirectUri = request.RedirectUri,
        };
    }

    [Fact]
    public async Task ValidateAsync_NoThumbprint_PassesThrough()
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(thumbprint: null));
        Assert.Null(result);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.2: access tokens are sender-constrained via MTLS only, so a client held to FAPI 1.0
    /// Advanced committing to a DPoP key with dpop_jkt is refused here with invalid_request rather than at the token
    /// endpoint; a client held to no profile keeps the commitment.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, false)]
    [InlineData(null, true)]
    public async Task ValidateAsync_AThumbprintUnderACertificateBoundProfile_IsRefused(
        ClientSecurityProfile? profile, bool accepted)
    {
        var context = CreateContext(ValidThumbprint);
        context.ClientInfo.SecurityProfile = profile;

        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, context);

        Assert.Equal(accepted ? null : ErrorCodes.InvalidRequest, result?.Error);
    }

    [Fact]
    public async Task ValidateAsync_ValidSha256Thumbprint_PassesThrough()
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(ValidThumbprint));
        Assert.Null(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nVbA9")]      // 42 chars (one short)
    [InlineData("Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nVbA9YX")]    // 44 chars (one long)
    [InlineData("Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nVbA9Y=")]    // base64 padding
    [InlineData("Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nV/A9Y")]    // standard-base64 '/' (not base64url)
    [InlineData("Wv1eDD8H4U6oOyVD0Y8GbqYAh8mXJTfjOcfZ4nV+A9Y")]    // standard-base64 '+' (not base64url)
    public async Task ValidateAsync_MalformedThumbprint_ReturnsInvalidRequest(string thumbprint)
    {
        var result = await _validator.ValidateAsync(SingleIssuer.Tenant, CreateContext(thumbprint));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidRequest, result.Error);
        Assert.Contains("dpop_jkt", result.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }
}
