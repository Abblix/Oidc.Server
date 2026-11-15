// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using System;
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
    /// FAPI 2.0 Security Profile section 5.3.2.2: the server "shall require the value of response_type described in
    /// [RFC6749] to be code", so a registration for none beside code is refused with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ServerDefaultFapi2CodePlusNone_ShouldReturnError()
    {
        var context = CreateContext([[ResponseTypes.Code], [ResponseTypes.None]]);

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// FAPI 2.0 section 5.3.2.2 binds the response type "for flows that use the authorization endpoint", and RFC 7591
    /// section 2.1 correlates the client credentials grant with no response type: a registration under a FAPI profile
    /// for that grant alone, or for no grant at all as a resource server calling introspection, registers no response
    /// type and passes.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, GrantTypes.ClientCredentials)]
    [InlineData(ClientSecurityProfile.Fapi2, null)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, GrantTypes.ClientCredentials)]
    public async Task ValidateAsync_Fapi_NoResponseTypes_ShouldReturnNull(ClientSecurityProfile profile, string? grantType)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            ResponseTypes = [],
            GrantTypes = grantType is null ? [] : [grantType],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        });

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(profile), context);

        Assert.Null(result);
    }

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.2.1: authorization servers "shall reject requests using the resource owner
    /// password credentials grant", so a registration for that grant beside the authorization code grant is refused
    /// with invalid_client_metadata at a tenant held to FAPI 2.0 or Message Signing, and the same registration without
    /// it, or at a tenant held to FAPI 1.0 Advanced or no profile, passes.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, true, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientSecurityProfile.Fapi2, false, null)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, true, ErrorCodes.InvalidClientMetadata)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, true, null)]
    [InlineData(ClientSecurityProfile.None, true, null)]
    public async Task ValidateAsync_ThePasswordGrant_IsRefusedUnderFapi2(
        ClientSecurityProfile profile, bool password, string? expectedError)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            GrantTypes = password
                ? [GrantTypes.AuthorizationCode, GrantTypes.Password]
                : [GrantTypes.AuthorizationCode],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,

            // FAPI 1.0 Part 2 section 8.2 issues certificate-bound access tokens only, so the FAPI 1.0 Advanced row is
            // refused for nothing but what it is about
            TlsClientCertificateBoundAccessTokens = true,
        });

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(profile), context);

        Assert.Equal(expectedError, result?.Error);
    }

    /// <summary>
    /// The algorithms a registration names are judged only where the client can be issued the JWT they sign, the same
    /// answer startup gives: a client of the client credentials grant alone, registering no response type, is never
    /// issued an ID token or an authorization response, so RS256 named for both passes; a client of the CIBA grant is
    /// issued ID tokens at the token endpoint, so RS256 named for them is refused, and named for the authorization
    /// response alone it passes.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.ClientCredentials, SigningAlgorithms.RS256, SigningAlgorithms.RS256, null)]
    [InlineData(GrantTypes.Ciba, SigningAlgorithms.RS256, null, ErrorCodes.InvalidClientMetadata)]
    [InlineData(GrantTypes.Ciba, null, SigningAlgorithms.RS256, null)]
    public async Task ValidateAsync_Fapi2_NoResponseTypes_JudgesOnlyTheJwtsTheClientIsIssued(
        string grantType, string? idTokenAlgorithm, string? authorizationResponseAlgorithm, string? expectedError)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            ResponseTypes = [],
            GrantTypes = [grantType],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenSignedResponseAlg = idTokenAlgorithm,
            AuthorizationSignedResponseAlg = authorizationResponseAlgorithm,
        });

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(expectedError, result?.Error);
    }

    /// <summary>
    /// A registration naming no response type but a back-channel logout URI can still be sent a logout token for a
    /// session the client joined before its registration changed, signed with the ID token's algorithm, so RS256 named
    /// for the ID token is refused.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2_NoResponseTypesButBackChannelLogout_JudgesTheIdToken()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            BackChannelLogoutUri = new Uri("https://client.example.com/logout"),
            ResponseTypes = [],
            GrantTypes = [GrantTypes.ClientCredentials],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenSignedResponseAlg = SigningAlgorithms.RS256,
        });

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// A registration naming no response type but a redirect URI can still be sent an authorization error response,
    /// which a JWT response mode signs with the authorization response algorithm, so RS256 named for it is refused.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi2_NoResponseTypesButARedirectUri_JudgesTheAuthorizationResponse()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [],
            GrantTypes = [GrantTypes.ClientCredentials],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            AuthorizationSignedResponseAlg = SigningAlgorithms.RS256,
        });

        var result = await new SecurityProfileValidator().ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3.2: a userinfo response registered for encryption is a JWT, so naming none for
    /// its signature under FAPI 1.0 Part 2 section 8.6 is refused; none without encryption is plain JSON and passes, as
    /// does encryption with no signature named, which is given one later.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, SigningAlgorithms.None, false)]
    [InlineData(null, SigningAlgorithms.None, true)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, null, true)]
    public async Task ValidateAsync_Fapi1Advanced_AnEncryptedUserInfoSignedWithNone_IsRefused(
        string? encryption, string? signature, bool accepted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            TlsClientCertificateBoundAccessTokens = true,
            UserInfoEncryptedResponseAlg = encryption,
            UserInfoSignedResponseAlg = signature,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(accepted ? null : ErrorCodes.InvalidClientMetadata, result?.Error);
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
            TlsClientCertificateBoundAccessTokens = true,
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

    /// <summary>
    /// The same clause at registration: an http jwks_uri is refused with invalid_client_metadata.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_Fapi1Advanced_AnHttpJwksUri_IsRefused()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            JwksUri = new System.Uri("http://client.example.com/jwks"),
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.2 has access tokens sender-constrained via MTLS only. A registration asking for DPoP
    /// (RFC 9449 section 5.2) or one that could be bound to no certificate - neither authenticating with mutual TLS nor
    /// registering tls_client_certificate_bound_access_tokens (RFC 8705 section 3) - would be refused every token, so
    /// it is refused here with invalid_client_metadata.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, true, true, false)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, false, false, false)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, false, true, true)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, false, false, true)]
    public async Task ValidateAsync_Fapi1Advanced_TokensItCannotBeIssued_AreRefused(
        string method, bool dpop, bool certificateBound, bool accepted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = method,
            IdTokenSignedResponseAlg = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.PS256,
            DpopBoundAccessTokens = dpop,
            TlsClientCertificateBoundAccessTokens = certificateBound,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi1Advanced), context);

        Assert.Equal(accepted ? null : ErrorCodes.InvalidClientMetadata, result?.Error);
    }
    /// <summary>
    /// FAPI 2.0 section 5.4.2: "any server providing a jwks_uri endpoint shall only serve the jwks_uri endpoint over
    /// TLS". A registration under FAPI 2.0 naming an http jwks_uri is refused with invalid_client_metadata; https passes.
    /// </summary>
    [Theory]
    [InlineData("http://client.example.com/jwks", false)]
    [InlineData("https://client.example.com/jwks", true)]
    public async Task ValidateAsync_Fapi2_AJwksUriNotServedOverTls_IsRefused(string jwksUri, bool accepted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenSignedResponseAlg = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.PS256,
            JwksUri = new System.Uri(jwksUri),
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(accepted ? null : ErrorCodes.InvalidClientMetadata, result?.Error);
    }
    /// <summary>
    /// FAPI 2.0 section 5.4.1 has the server "adhere to [RFC8725]" when creating or processing JWTs, and RFC 8725
    /// section 3.2 says "Avoid all RSA-PKCS1 v1.5 encryption algorithms": a registration under FAPI 2.0 asking for its ID
    /// tokens encrypted with RSA1_5 is refused with invalid_client_metadata; RSA-OAEP-256 passes.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, false)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
    public async Task ValidateAsync_Fapi2_Rsa1_5Encryption_IsRefused(string keyManagement, bool accepted)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            ResponseTypes = [[ResponseTypes.Code]],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
            IdTokenSignedResponseAlg = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.PS256,
            IdTokenEncryptedResponseAlg = keyManagement,
        });

        var result = await new SecurityProfileValidator()
            .ValidateAsync(TenantHolding(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(accepted ? null : ErrorCodes.InvalidClientMetadata, result?.Error);
    }
}
