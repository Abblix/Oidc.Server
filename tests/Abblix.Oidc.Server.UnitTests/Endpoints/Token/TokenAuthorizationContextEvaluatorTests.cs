// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

/// <summary>
/// Verifies the RFC 8705 certificate-binding rules in
/// <see cref="TokenAuthorizationContextEvaluator"/>: a refreshed token stays bound to the
/// certificate the original token was bound to (RFC 8705 section 4 - the AS SHOULD bind the refresh
/// token to the certificate and check that binding), and an initial token binds to the
/// certificate presented at issuance only for a client registered for it or held to a profile
/// requiring it (sections 3 and 3.4). The invariant the refresh tests pin is that a
/// refresh neither drops the binding (when no certificate is re-presented) nor silently
/// rebinds to a different certificate.
/// </summary>
public class TokenAuthorizationContextEvaluatorTests
{
    private const string OriginalThumbprint = "original-cert-thumbprint";

    private static readonly TokenAuthorizationContextEvaluator Evaluator = new();

    [Fact]
    public void Refresh_WithoutClientCertificate_PreservesOriginalCertificateBinding()
    {
        // A DPoP/mTLS-style bound grant is refreshed on a connection that does not re-present
        // the client certificate. RFC 8705 section 4 says the refreshed token should remain bound
        // to the original certificate - the binding must not be wiped to null.
        var request = CreateRefreshRequest(
            boundThumbprint: OriginalThumbprint,
            clientCertificate: null);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Equal(OriginalThumbprint, result.CertificateSha256Thumbprint);
    }

    [Fact]
    public void Refresh_WithDifferentClientCertificate_DoesNotRebindToNewCertificate()
    {
        // A rotated certificate is presented on refresh. The token must stay bound to the
        // ORIGINAL certificate (RFC 8705 section 4) rather than silently rebinding to the new one.
        using var rotatedCertificate = CreateCertificate();
        var request = CreateRefreshRequest(
            boundThumbprint: OriginalThumbprint,
            clientCertificate: rotatedCertificate);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Equal(OriginalThumbprint, result.CertificateSha256Thumbprint);
    }

    /// <summary>
    /// RFC 8705 section 3.4: tls_client_certificate_bound_access_tokens conveys "the client's intention to use
    /// mutual-TLS client certificate-bound access tokens. If omitted, the default value is false." So at initial
    /// issuance the token is bound to the presented certificate for a client that registered it, whatever it
    /// authenticates with, and for a client held to a profile issuing certificate-bound tokens only (FAPI 1.0 Part 2
    /// section 5.2.2: "shall only issue sender-constrained access tokens" with MTLS the mechanism), and for no other:
    /// authenticating with mutual TLS binds nothing by itself, and FAPI 2.0 leaves the sender constraint to the client.
    /// </summary>
    [Theory]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, false, null, false)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth, false, null, false)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, false, ClientSecurityProfile.Fapi2, false)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, true, null, true)]
    [InlineData(ClientAuthenticationMethods.SelfSignedTlsClientAuth, true, null, true)]
    [InlineData(ClientAuthenticationMethods.TlsClientAuth, false, ClientSecurityProfile.Fapi1Advanced, true)]
    [InlineData(ClientAuthenticationMethods.PrivateKeyJwt, false, ClientSecurityProfile.Fapi1Advanced, true)]
    public void InitialIssuance_WithClientCertificate_BindsOnlyWhenRegisteredOrRequiredByTheProfile(
        string authMethod, bool certificateBoundAccessTokens, ClientSecurityProfile? securityProfile, bool bound)
    {
        using var certificate = CreateCertificate();
        var request = CreateRefreshRequest(
            boundThumbprint: null,
            clientCertificate: certificate,
            authMethod: authMethod,
            certificateBoundAccessTokens: certificateBoundAccessTokens,
            securityProfile: securityProfile);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Equal(
            bound ? Base64Url.EncodeToString(SHA256.HashData(certificate.RawData)) : null,
            result.CertificateSha256Thumbprint);
    }

    /// <summary>
    /// RFC 8705 section 3.4 leaves a token request of a client registered for certificate-bound tokens that arrives
    /// without mutual TLS "at the authorization server's discretion as to whether to return an error or issue an
    /// unbound token": nothing is bound here, and a profile requiring a sender-constrained token refuses the request
    /// before it reaches this step.
    /// </summary>
    [Fact]
    public void InitialIssuance_RegisteredForBindingWithoutCertificate_DoesNotBind()
    {
        var request = CreateRefreshRequest(
            boundThumbprint: null,
            clientCertificate: null,
            certificateBoundAccessTokens: true);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Null(result.CertificateSha256Thumbprint);
    }

    [Fact]
    public void GrantWithoutResources_RequestedResourceIsNotAddedToAudience()
    {
        // RFC 8707 section 2.2 anti-escalation: a grant that authorized no resource must NOT gain one at
        // the token endpoint just because the request asks for a (globally registered) resource.
        // The requested resource is dropped, not folded into the issued token's aud.
        var request = CreateResourceRequest(
            grantResources: null,
            requestedResources: [new Uri("https://api.example/c")]);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.True(result.Resources is null or { Length: 0 });
    }

    [Fact]
    public void RequestedResourceNotInGrant_IsDroppedByIntersection()
    {
        // Grant authorized A and B; the request asks for C (registered but never granted). The
        // intersection is empty - C cannot be escalated into the token's audience.
        var request = CreateResourceRequest(
            grantResources: [new Uri("https://api.example/a"), new Uri("https://api.example/b")],
            requestedResources: [new Uri("https://api.example/c")]);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Empty(result.Resources!);
    }

    [Fact]
    public void RequestedResourceSubsetOfGrant_IsNarrowedToIntersection()
    {
        // A request for a subset of the granted resources narrows the audience to that subset.
        var a = new Uri("https://api.example/a");
        var request = CreateResourceRequest(
            grantResources: [a, new Uri("https://api.example/b")],
            requestedResources: [a]);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Equal([a], result.Resources!);
    }

    private static ValidTokenRequest CreateResourceRequest(Uri[]? grantResources, Uri[] requestedResources)
    {
        var fixedTime = DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var session = new AuthSession("user-123", "session-456", fixedTime, "local");
        var context = new AuthorizationContext("test-client", [TestConstants.DefaultScope], null)
        {
            Resources = grantResources,
        };
        var grant = new AuthorizedGrant(session, context);
        var clientInfo = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        };

        return new ValidTokenRequest(
            new TokenRequest(),
            grant,
            clientInfo,
            [],
            Array.ConvertAll(requestedResources, resource => new ResourceDefinition(resource)));
    }

    /// <summary>
    /// RFC 8705 section 3.4: tls_client_certificate_bound_access_tokens binds the issued token to the
    /// presented certificate even when the client authenticates with a non-mTLS method - the
    /// metadata decouples binding from authentication.
    /// </summary>
    [Fact]
    public void InitialIssuance_NonMtlsAuthWithBindingFlag_BindsToPresentedCertificate()
    {
        using var certificate = CreateCertificate();
        var expectedThumbprint = Base64Url.EncodeToString(SHA256.HashData(certificate.RawData));
        var request = CreateRefreshRequest(
            boundThumbprint: null,
            clientCertificate: certificate,
            authMethod: ClientAuthenticationMethods.PrivateKeyJwt,
            certificateBoundAccessTokens: true);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Equal(expectedThumbprint, result.CertificateSha256Thumbprint);
    }

    /// <summary>
    /// Without the RFC 8705 section 3.4 flag a non-mTLS-authenticated client gets no certificate binding
    /// even when a certificate happens to be present on the connection - pins the pre-existing
    /// behavior the new flag deliberately does not change.
    /// </summary>
    [Fact]
    public void InitialIssuance_NonMtlsAuthWithoutBindingFlag_DoesNotBind()
    {
        using var certificate = CreateCertificate();
        var request = CreateRefreshRequest(
            boundThumbprint: null,
            clientCertificate: certificate,
            authMethod: ClientAuthenticationMethods.PrivateKeyJwt,
            certificateBoundAccessTokens: false);

        var result = Evaluator.EvaluateAuthorizationContext(SingleIssuer.Tenant, request);

        Assert.Null(result.CertificateSha256Thumbprint);
    }

    private static ValidTokenRequest CreateRefreshRequest(
        string? boundThumbprint,
        X509Certificate2? clientCertificate,
        string authMethod = ClientAuthenticationMethods.TlsClientAuth,
        bool certificateBoundAccessTokens = false,
        ClientSecurityProfile? securityProfile = null)
    {
        var fixedTime = DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var session = new AuthSession("user-123", "session-456", fixedTime, "local");
        var context = new AuthorizationContext("test-client", [TestConstants.DefaultScope], null)
        {
            CertificateSha256Thumbprint = boundThumbprint,
        };
        var grant = new AuthorizedGrant(session, context);
        var clientInfo = new ClientInfo("test-client")
        {
            TokenEndpointAuthMethod = authMethod,
            TlsClientCertificateBoundAccessTokens = certificateBoundAccessTokens,
            SecurityProfile = securityProfile,
        };

        return new ValidTokenRequest(
            new TokenRequest(),
            grant,
            clientInfo,
            [],
            [],
            clientCertificate);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Client",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var notBefore = DateTimeOffset.Parse("2025-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var notAfter = DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
