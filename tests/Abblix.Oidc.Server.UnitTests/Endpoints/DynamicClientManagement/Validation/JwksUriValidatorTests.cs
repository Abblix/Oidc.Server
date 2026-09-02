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
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
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
    private static JwksUriValidator CreateValidator(SecureHttpFetchOptions options)
        => new(new SecureUriValidator(Options.Create(options)));

    // Secure defaults: https-only, private networks blocked.
    private static SecureHttpFetchOptions SecureDefaults => new();

    private static ClientRegistrationValidationContext Context(Uri? jwksUri)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            JwksUri = jwksUri,
        });

    [Fact]
    public async Task ValidateAsync_WithNoJwksUri_ReturnsNull()
        => Assert.Null(await CreateValidator(SecureDefaults).ValidateAsync(Context(null)));

    [Fact]
    public async Task ValidateAsync_WithAnAbsoluteUri_ReturnsNull()
        => Assert.Null(await CreateValidator(SecureDefaults)
            .ValidateAsync(Context(new Uri("https://client.example.com/.well-known/jwks.json"))));

    /// <summary>
    /// Everything the fetch policy refuses is refused here, including the two shapes that read as
    /// absolute to a check that only asks <see cref="Uri.IsAbsoluteUri"/>.
    /// </summary>
    /// <remarks>
    /// The <c>host:port</c> rows are the ones that matter, and they are the reason absoluteness alone
    /// was not enough: a dot is legal in a URI scheme, so <c>client.example.com:8080/jwks</c> parses as
    /// an ABSOLUTE URI whose scheme is the host name and whose <see cref="Uri.Host"/> is the empty
    /// string. Nothing throws and nothing is malformed - it simply names no destination, and the client
    /// registers with keys that can never be loaded. It is also what a registrant types when they mean a
    /// host and a port, so it is the likely mistake rather than an exotic one.
    /// </remarks>
    [Theory]
    [InlineData("/.well-known/jwks.json", UriKind.Relative)]
    [InlineData("http://client.example.com/.well-known/jwks.json", UriKind.Absolute)]
    [InlineData("https://localhost/.well-known/jwks.json", UriKind.Absolute)]
    [InlineData("client.example.com:8080/.well-known/jwks.json", UriKind.Absolute)]
    [InlineData("www.example.com:443/jwks", UriKind.Absolute)]
    public async Task ValidateAsync_WithAValueThePolicyRefuses_ReturnsInvalidClientMetadata(
        string uri,
        UriKind kind)
    {
        var result = await CreateValidator(SecureDefaults).ValidateAsync(Context(new Uri(uri, kind)));

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);

        // The member by name, because "invalid_client_metadata" alone leaves a registrant guessing which
        // of thirty members the server means.
        Assert.Contains(
            ClientRegistrationRequest.Parameters.JwksUri,
            result.ErrorDescription,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A destination the deployment named is accepted over plain HTTP, because the policy says so.
    /// </summary>
    /// <remarks>
    /// The row that a hard-coded <c>https</c> would fail. <c>AllowedDestinations</c> exists to name a
    /// service inside the deployment's own network, which is reached over HTTP, and the policy checks it
    /// FIRST so that it lifts the scheme restriction. The same address registers as a
    /// <c>backchannel_logout_uri</c>, so refusing it here would make the two fetched endpoints disagree
    /// about one address - measured before this row existed: 201 for one member, 400 for the other.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_WithANamedDestinationOverHttp_ReturnsNull()
    {
        var options = new SecureHttpFetchOptions
        {
            AllowedDestinations = [new Uri("http://keys.internal:8080/jwks")],
        };

        var result = await CreateValidator(options)
            .ValidateAsync(Context(new Uri("http://keys.internal:8080/jwks")));

        Assert.Null(result);

        // The control: the same address is refused under the defaults, so what this row measures is the
        // named destination and not a policy that permits everything.
        Assert.NotNull(await CreateValidator(SecureDefaults)
            .ValidateAsync(Context(new Uri("http://keys.internal:8080/jwks"))));
    }

    /// <summary>
    /// The control on the rows above: the two <c>host:port</c> values really do reach the validator as
    /// ABSOLUTE URIs, so their refusal comes from the policy and not from relativeness.
    /// </summary>
    [Theory]
    [InlineData("client.example.com:8080/.well-known/jwks.json")]
    [InlineData("www.example.com:443/jwks")]
    public void AHostAndPortWithNoScheme_ParsesAsAbsoluteWithNoHost(string value)
    {
        var uri = new Uri(value, UriKind.Absolute);

        Assert.True(uri.IsAbsoluteUri);
        Assert.Equal(string.Empty, uri.Host);
    }
}
