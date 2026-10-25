// Abblix OIDC Client Library
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

using System.Text;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.UnitTests.Features.ClientAuthentication;

/// <summary>
/// How this client presents its credentials, at whichever endpoint asks for them.
/// </summary>
public class ClientCredentialsPresenterTests
{
    private const string ClientId = "test-client";

    private static (IDictionary<string, string> Parameters, HttpRequestMessage Request) Present(
        string method, string? clientSecret = null)
    {
        var presenter = new ClientCredentialsPresenter(
            Options.Create(new OidcClientOptions { ClientId = ClientId }),
            Options.Create(new ClientAuthenticationOptions { Method = method, ClientSecret = clientSecret }));

        var parameters = new Dictionary<string, string>();
        var request = new HttpRequestMessage(HttpMethod.Post, "https://provider.example.com/token");

        presenter.Present(request, parameters);

        return (parameters, request);
    }

    private static string DecodeBasic(HttpRequestMessage request)
    {
        // Both halves said out loud: a request that carries no header, and one whose scheme arrived without
        // its credentials, are two different failures, and neither is a null reference from inside Convert.
        var authorization = request.Headers.Authorization;
        Assert.NotNull(authorization);
        Assert.NotNull(authorization.Parameter);

        return Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Parameter));
    }

    /// <summary>
    /// A public client names itself and presents no secret, because it has none to keep. RFC 6749 section
    /// 3.2.1 still requires the client identifier from a client that does not authenticate.
    /// </summary>
    [Fact]
    public void APublicClientNamesItselfWithoutASecret()
    {
        var (parameters, request) = Present(ClientAuthenticationMethods.None);

        Assert.Equal(ClientId, parameters["client_id"]);
        Assert.False(parameters.ContainsKey("client_secret"));
        Assert.Null(request.Headers.Authorization);
    }

    /// <summary>
    /// The secret travels in the body when the host configured that method.
    /// </summary>
    [Fact]
    public void ClientSecretPostPutsTheSecretInTheParameters()
    {
        var (parameters, request) = Present(
            ClientAuthenticationMethods.ClientSecretPost, "the-secret");

        Assert.Equal(ClientId, parameters["client_id"]);
        Assert.Equal("the-secret", parameters["client_secret"]);
        Assert.Null(request.Headers.Authorization);
    }

    /// <summary>
    /// The secret travels in the Authorization header when the host configured that method, and nowhere else.
    /// </summary>
    [Fact]
    public void ClientSecretBasicPutsTheSecretInTheHeader()
    {
        var (parameters, request) = Present(
            ClientAuthenticationMethods.ClientSecretBasic, "the-secret");

        Assert.Equal("Basic", request.Headers.Authorization?.Scheme);
        Assert.Equal($"{ClientId}:the-secret", DecodeBasic(request));
        Assert.False(parameters.ContainsKey("client_secret"));
    }

    /// <summary>
    /// Both halves of the Basic credentials are form-encoded before being joined, as RFC 6749 section 2.3.1
    /// requires. Without it a secret containing a colon reads to the provider as a different secret entirely.
    /// </summary>
    [Fact]
    public void BasicCredentialsAreFormEncodedBeforeBeingJoined()
    {
        var (_, request) = Present(ClientAuthenticationMethods.ClientSecretBasic, "se:cr et");

        Assert.Equal($"{ClientId}:se%3Acr%20et", DecodeBasic(request));
    }

    /// <summary>
    /// A method needing a secret that was not configured fails with a message naming what is missing, rather
    /// than sending a request the provider will reject for a reason that reads like anything else.
    /// </summary>
    [Fact]
    public void AMissingSecretIsNamedPlainly()
    {
        var exception = Assert.Throws<ClientAuthenticationException>(
            () => Present(ClientAuthenticationMethods.ClientSecretPost));

        Assert.Contains(nameof(ClientAuthenticationOptions.ClientSecret), exception.Message);
    }

    /// <summary>
    /// A method this client cannot present is named rather than attempted. Falling back to an unauthenticated
    /// request would turn a confidential client into a public one on a configuration typo.
    /// </summary>
    [Fact]
    public void AnUnsupportedMethodIsNamed()
    {
        var exception = Assert.Throws<ClientAuthenticationException>(
            () => Present("private_key_jwt", "the-secret"));

        Assert.Contains("private_key_jwt", exception.Message);
    }
}
