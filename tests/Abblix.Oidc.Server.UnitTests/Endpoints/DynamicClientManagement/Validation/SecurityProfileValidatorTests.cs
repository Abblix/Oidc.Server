// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// Unit tests for <see cref="SecurityProfileValidator"/>. A dynamically registered client cannot
/// declare a profile (that is a server-side policy decision), so the validator rejects a registration
/// whose response types cannot satisfy the server-wide <c>DefaultSecurityProfile</c>, and is a no-op
/// when no server-wide profile applies.
/// </summary>
public class SecurityProfileValidatorTests
{
    private static TenantDefinition TenantHolding(ClientSecurityProfile defaultSecurityProfile)
        => new TestIssuer { DefaultSecurityProfile = defaultSecurityProfile }.ToTenant();

    private static ClientRegistrationValidationContext CreateContext(string[][] responseTypes)
    {
        var request = new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = responseTypes,

            // These cases are about response types, so the authentication method is one the
            // profile admits: leaving the default here would make every one of them fail for
            // the wrong reason.
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        };

        return new ClientRegistrationValidationContext(request);
    }

    /// <summary>
    /// With no server-wide profile the validator is a no-op: an implicit-only registration passes this
    /// step (the response-type/grant-type consistency is enforced by other validators).
    /// </summary>
    [Fact]
    public async Task ValidateAsync_NoServerProfileImplicitOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.IdToken]]);

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.None), context);

        Assert.Null(result);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration limited to the authorization-code response
    /// type is self-consistent.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2CodeOnly_ShouldReturnNull()
    {
        var context = CreateContext([[ResponseTypes.Code]]);

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Null(result);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration that requests an implicit response type and
    /// never permits code is rejected with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2ImplicitOnly_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.IdToken]]);

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// Under a server-wide FAPI 2.0 default, a registration that allows code but also a hybrid response
    /// type is rejected: the hybrid type can never be used under the profile.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2CodePlusHybrid_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.Code], [ResponseTypes.Code, ResponseTypes.IdToken]]);

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.NotNull(result);
        Assert.Equal(ErrorCodes.InvalidClientMetadata, result.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6: a registration under that profile naming RS256 for its ID tokens is refused with
    /// invalid_client_metadata, while one naming PS256 or naming none - which is given PS256 - passes.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    [InlineData(null, true)]
    public async Task ValidateAsync_Fapi1Advanced_IdTokenSigningAlgorithm(string? algorithm, bool accepted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenSignedResponseAlg = algorithm,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        if (accepted)
            Assert.Null(result);
        else
            Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// A registration pinning its request objects or its authentication assertions to RS256 under FAPI 1.0 Advanced
    /// is refused with invalid_client_metadata rather than registered as a client that can never sign acceptably.
    /// </summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task ValidateAsync_Fapi1Advanced_WhatTheClientSignsWith(bool requestObject, bool assertion)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            RequestObjectSigningAlg = requestObject ? SigningAlgorithms.RS256 : null,
            TokenEndpointAuthSigningAlg = assertion ? SigningAlgorithms.RS256 : null,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// The same clause at registration: an http redirect URI is refused with the invalid_redirect_uri RFC 7591 section
    /// 3.2.2 names for it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi1Advanced_AnHttpRedirectUri_IsRefused()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [new System.Uri("http://127.0.0.1:8080/cb")],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(ErrorCodes.InvalidRedirectUri, result?.Error);
    }

    /// <summary>
    /// The same clause at registration: id_token_encrypted_response_alg RSA1_5 is refused with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi1Advanced_Rsa1_5Encryption_IsRefused()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenEncryptedResponseAlg = EncryptionAlgorithms.KeyManagement.Rsa1_5,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }
}
