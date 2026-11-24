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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.TokenExchange;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token;

// A bound subject token exchanged by the client it was issued to requires a proof of its key or certificate, and one
// exchanged by another client through cross-client exchange requires neither. Each row runs the grant the handler
// builds through DPoPBindingValidator, the token endpoint's check of the binding.
public partial class TokenExchangeGrantHandlerTests
{
    private const string BoundKey = "the-bound-dpop-key";
    private const string OtherKey = "another-dpop-key";
    private const string OtherClientId = "the-token-owner";

    public enum Presented { Nothing, TheBoundOne, AnotherOne }

    /// <summary>
    /// DPoP binding: the client the token was issued to proves the bound key, and another client is not asked to.
    /// </summary>
    [Theory]
    [InlineData(true, Presented.Nothing, ErrorCodes.InvalidDPoPProof)]
    [InlineData(true, Presented.TheBoundOne, null)]
    [InlineData(true, Presented.AnotherOne, ErrorCodes.InvalidDPoPProof)]
    [InlineData(false, Presented.Nothing, null)]
    public async Task ADPoPBoundSubjectToken_RequiresItsKey_OfItsOwnClientOnly(
        bool requesterIsTheOwner,
        Presented presented,
        string? expectedError)
    {
        var (grant, requester) = await ExchangeAsync(requesterIsTheOwner, proofKey: BoundKey, certificate: null);
        var context = new TokenValidationContext(ExchangeRequest(TokenExchangeTokenTypes.AccessToken), new ClientRequest())
        {
            ClientInfo = requester,
            AuthorizedGrant = grant,
            ProofKeyThumbprint = presented switch
            {
                Presented.Nothing => null,
                Presented.TheBoundOne => BoundKey,
                Presented.AnotherOne => OtherKey,
                _ => throw new ArgumentOutOfRangeException(nameof(presented), presented, null),
            },
        };

        var error = await BindingValidator().ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(expectedError, error?.Error);
    }

    /// <summary>
    /// Certificate binding: the client the token was issued to presents the bound certificate, whether or not it
    /// authenticates by mutual TLS, and another client is not asked to.
    /// </summary>
    [Theory]
    [InlineData(true, false, Presented.Nothing, ErrorCodes.InvalidGrant)]
    [InlineData(true, false, Presented.TheBoundOne, null)]
    [InlineData(true, false, Presented.AnotherOne, ErrorCodes.InvalidGrant)]
    [InlineData(true, true, Presented.AnotherOne, ErrorCodes.InvalidGrant)]
    [InlineData(true, true, Presented.TheBoundOne, null)]
    [InlineData(false, false, Presented.Nothing, null)]
    public async Task ACertificateBoundSubjectToken_RequiresItsCertificate_OfItsOwnClientOnly(
        bool requesterIsTheOwner,
        bool requesterAuthenticatesByMutualTls,
        Presented presented,
        string? expectedError)
    {
        using var bound = CreateCertificate("CN=Bound");
        using var other = CreateCertificate("CN=Other");
        var (grant, requester) = await ExchangeAsync(
            requesterIsTheOwner,
            proofKey: null,
            certificate: Base64Url.EncodeToString(SHA256.HashData(bound.RawData)));
        if (requesterAuthenticatesByMutualTls)
            requester.TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth;

        var clientRequest = new ClientRequest
        {
            ClientCertificate = presented switch
            {
                Presented.Nothing => null,
                Presented.TheBoundOne => bound,
                Presented.AnotherOne => other,
                _ => throw new ArgumentOutOfRangeException(nameof(presented), presented, null),
            },
        };
        var context = new TokenValidationContext(ExchangeRequest(TokenExchangeTokenTypes.AccessToken), clientRequest)
        {
            ClientInfo = requester,
            AuthorizedGrant = grant,
        };

        var error = await BindingValidator().ValidateAsync(SingleIssuer.Tenant, context, TestContext.Current.CancellationToken);

        Assert.Equal(expectedError, error?.Error);
    }

    /// <summary>
    /// The grant the handler builds for a subject token bound as given, exchanged by its own client or by another one
    /// allowed to exchange tokens issued to others.
    /// </summary>
    private static async Task<(AuthorizedGrant Grant, ClientInfo Requester)>
        ExchangeAsync(bool requesterIsTheOwner, string? proofKey, string? certificate)
    {
        var subject = new SubjectTokenContext(TestSubject, Issuer: null, Scope: null, AuthorizationDetails: null)
        {
            SessionId = TestSessionId,
            AuthenticationTime = TestAuthenticationTime,
            OriginalClientId = requesterIsTheOwner ? ClientId : OtherClientId,
            ProofKeyThumbprint = proofKey,
            CertificateSha256Thumbprint = certificate,
        };
        var (handler, _) = CreateHandlerWith(TokenExchangeTokenTypes.AccessToken, subject);
        var requester = ClientWithAllowlist(TokenExchangeTokenTypes.AccessToken) with
        {
            AllowCrossClientSubjectTokenExchange = !requesterIsTheOwner,
        };

        var result = await handler.AuthorizeAsync(
            SingleIssuer.Tenant,
            ExchangeRequest(TokenExchangeTokenTypes.AccessToken),
            requester,
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant), result.TryGetFailure(out var failure) ? failure.ErrorDescription : null);
        return (grant, requester);
    }

    private static DPoPBindingValidator BindingValidator() => new(Mock.Of<ILogger<DPoPBindingValidator>>());

    private static X509Certificate2 CreateCertificate(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var notBefore = DateTimeOffset.Parse("2025-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var notAfter = DateTimeOffset.Parse("2027-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}
