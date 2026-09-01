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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="JwksUriValidator"/>.
/// </summary>
/// <remarks>
/// These rows say what the verdict is; they cannot say the validator is REACHED, which is the half that
/// was missing while the gap was open. That half is
/// <c>ClientManagementTests.A_relative_jwks_uri_is_refused</c>, driven through the endpoint.
/// </remarks>
public class JwksUriValidatorTests
{
    private static ClientRegistrationValidationContext Context(Uri? jwksUri)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            JwksUri = jwksUri,
        });

    [Fact]
    public async Task ValidateAsync_WithNoJwksUri_ReturnsNull()
        => Assert.Null(await new JwksUriValidator().ValidateAsync(Context(null)));

    [Fact]
    public async Task ValidateAsync_WithAnAbsoluteUri_ReturnsNull()
        => Assert.Null(await new JwksUriValidator()
            .ValidateAsync(Context(new Uri("https://client.example.com/.well-known/jwks.json"))));

    /// <summary>
    /// A non-https absolute URI is NOT this validator's verdict to give: the SSRF policy is applied by
    /// the fetch, against a name re-resolved at request time, and a registration-time answer here would
    /// be about an address that may since have moved.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WithAnAbsoluteHttpUri_ReturnsNull()
        => Assert.Null(await new JwksUriValidator()
            .ValidateAsync(Context(new Uri("http://client.example.com/.well-known/jwks.json"))));

    [Fact]
    public async Task ValidateAsync_WithARelativeUri_ReturnsInvalidClientMetadata()
    {
        var result = await new JwksUriValidator()
            .ValidateAsync(Context(new Uri("/.well-known/jwks.json", UriKind.Relative)));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);

        // The member by name, because "invalid_client_metadata" alone leaves a registrant guessing which
        // of thirty members the server means.
        Assert.Contains(
            ClientRegistrationRequest.Parameters.JwksUri,
            result.ErrorDescription,
            StringComparison.Ordinal);
    }
}
