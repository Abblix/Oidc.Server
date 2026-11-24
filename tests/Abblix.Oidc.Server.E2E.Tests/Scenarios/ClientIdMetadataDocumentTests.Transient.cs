// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// Section 6.1: "At the token endpoint or pushed authorization request endpoint, the authorization server MUST
    /// return an invalid_client error, or for a transient failure, an HTTP 503 status code". A document whose server
    /// answers 503 or cannot be reached is a transient failure, whatever credential the request presents for the
    /// client the document would describe.
    /// </summary>
    [Theory]
    [InlineData(Endpoint.Token, Credential.None, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.None, Outage.Unreachable)]
    [InlineData(Endpoint.Token, Credential.PrivateKeyAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.SecretAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Token, Credential.Certificate, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.None, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.None, Outage.Unreachable)]
    [InlineData(Endpoint.Pushed, Credential.PrivateKeyAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.SecretAssertion, Outage.ServiceUnavailable)]
    [InlineData(Endpoint.Pushed, Credential.Certificate, Outage.ServiceUnavailable)]
    public async Task ADocumentNotToBeHadForNow_IsAnswered503(Endpoint endpoint, Credential credential, Outage outage)
    {
        switch (outage)
        {
            case Outage.ServiceUnavailable:
                _origin.Answer(ClientId, () => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
                break;

            case Outage.Unreachable:
                _origin.Unreachable(ClientId);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(outage), outage, null);
        }

        var (status, body) = await SendAuthenticatedAsync(endpoint, credential);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, status);
        Assert.Empty(body);
    }

    /// <summary>
    /// The other half of section 6.1 at the same endpoints: a document that was had and refused is a terminal failure,
    /// answered invalid_client.
    /// </summary>
    [Theory]
    [InlineData(Endpoint.Token, Credential.None)]
    [InlineData(Endpoint.Token, Credential.PrivateKeyAssertion)]
    [InlineData(Endpoint.Pushed, Credential.None)]
    [InlineData(Endpoint.Pushed, Credential.PrivateKeyAssertion)]
    public async Task ARefusedDocument_IsAnInvalidClient_NotA503(Endpoint endpoint, Credential credential)
    {
        Arrange(Unavailable.AnotherClientId);

        var (status, body) = await SendAuthenticatedAsync(endpoint, credential);

        Assert.Equal(StatusCodes.Status401Unauthorized, status);
        Assert.Contains(ErrorCodes.InvalidClient, body);
    }

    /// <summary>
    /// Sends a request for <see cref="ClientId"/> to <paramref name="endpoint"/>, authenticated the way
    /// <paramref name="credential"/> names, and returns the status and the body it is answered with.
    /// </summary>
    private async Task<(int Status, string Body)> SendAuthenticatedAsync(Endpoint endpoint, Credential credential)
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var (uri, form) = endpoint switch
        {
            Endpoint.Token => (discovery.TokenEndpoint, CodeExchange("code", GeneratePkcePair().Verifier)),
            Endpoint.Pushed => (discovery.PushedAuthorizationRequestEndpoint!,
                CodeFlowParameters(ClientId, GeneratePkcePair().Challenge)),
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
        };

        switch (credential)
        {
            case Credential.None:
            case Credential.Certificate:
                break;

            case Credential.PrivateKeyAssertion:
                await AddAssertionAsync(
                    form, discovery, JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256));
                break;

            case Credential.SecretAssertion:
                await AddAssertionAsync(form, discovery, JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256));
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(credential), credential, null);
        }

        if (credential == Credential.Certificate)
            return (await PostWithCertificateAsync(host, uri, form), string.Empty);

        using var response = await FormPostHelpers.PostFormAsync(client, uri, form);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task AddAssertionAsync(Dictionary<string, string> form, DiscoveryDocument discovery, JsonWebKey key)
    {
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] =
            await ClientSecretJwtAssertion.IssueWithKeyAsync(ClientId, key, discovery.Issuer.OriginalString);
    }

    public enum Endpoint
    {
        Token,
        Pushed,
    }

    public enum Credential
    {
        None,
        PrivateKeyAssertion,
        SecretAssertion,
        Certificate,
    }

    public enum Outage
    {
        ServiceUnavailable,
        Unreachable,
    }
}
