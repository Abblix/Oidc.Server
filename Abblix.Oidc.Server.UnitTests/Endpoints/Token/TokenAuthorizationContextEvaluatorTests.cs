// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

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
/// certificate the original token was bound to (RFC 8705 §4 — the AS SHOULD bind the refresh
/// token to the certificate and check that binding), and an initial token binds to the
/// certificate presented at issuance (§3). The invariant the refresh tests pin is that a
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
        // the client certificate. RFC 8705 §4 says the refreshed token should remain bound
        // to the original certificate — the binding must not be wiped to null.
        var request = CreateRefreshRequest(
            boundThumbprint: OriginalThumbprint,
            clientCertificate: null);

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Equal(OriginalThumbprint, result.CertificateSha256Thumbprint);
    }

    [Fact]
    public void Refresh_WithDifferentClientCertificate_DoesNotRebindToNewCertificate()
    {
        // A rotated certificate is presented on refresh. The token must stay bound to the
        // ORIGINAL certificate (RFC 8705 §4) rather than silently rebinding to the new one.
        using var rotatedCertificate = CreateCertificate();
        var request = CreateRefreshRequest(
            boundThumbprint: OriginalThumbprint,
            clientCertificate: rotatedCertificate);

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Equal(OriginalThumbprint, result.CertificateSha256Thumbprint);
    }

    [Fact]
    public void InitialIssuance_WithClientCertificate_BindsToPresentedCertificate()
    {
        // Initial issuance: the grant carries no prior binding, the client authenticated via
        // mTLS, so the issued token binds to the presented certificate's SHA-256 thumbprint.
        using var certificate = CreateCertificate();
        var expectedThumbprint = Base64Url.EncodeToString(SHA256.HashData(certificate.RawData));
        var request = CreateRefreshRequest(
            boundThumbprint: null,
            clientCertificate: certificate);

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Equal(expectedThumbprint, result.CertificateSha256Thumbprint);
    }

    [Fact]
    public void GrantWithoutResources_RequestedResourceIsNotAddedToAudience()
    {
        // RFC 8707 §2.2 anti-escalation: a grant that authorized no resource must NOT gain one at
        // the token endpoint just because the request asks for a (globally registered) resource.
        // The requested resource is dropped, not folded into the issued token's aud.
        var request = CreateResourceRequest(
            grantResources: null,
            requestedResources: [new Uri("https://api.example/c")]);

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.True(result.Resources is null or { Length: 0 });
    }

    [Fact]
    public void RequestedResourceNotInGrant_IsDroppedByIntersection()
    {
        // Grant authorized A and B; the request asks for C (registered but never granted). The
        // intersection is empty — C cannot be escalated into the token's audience.
        var request = CreateResourceRequest(
            grantResources: [new Uri("https://api.example/a"), new Uri("https://api.example/b")],
            requestedResources: [new Uri("https://api.example/c")]);

        var result = Evaluator.EvaluateAuthorizationContext(request);

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

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Equal([a], result.Resources);
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
    /// RFC 8705 §3.4: tls_client_certificate_bound_access_tokens binds the issued token to the
    /// presented certificate even when the client authenticates with a non-mTLS method — the
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

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Equal(expectedThumbprint, result.CertificateSha256Thumbprint);
    }

    /// <summary>
    /// Without the RFC 8705 §3.4 flag a non-mTLS-authenticated client gets no certificate binding
    /// even when a certificate happens to be present on the connection — pins the pre-existing
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

        var result = Evaluator.EvaluateAuthorizationContext(request);

        Assert.Null(result.CertificateSha256Thumbprint);
    }

    private static ValidTokenRequest CreateRefreshRequest(
        string? boundThumbprint,
        X509Certificate2? clientCertificate,
        string authMethod = ClientAuthenticationMethods.TlsClientAuth,
        bool certificateBoundAccessTokens = false)
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
