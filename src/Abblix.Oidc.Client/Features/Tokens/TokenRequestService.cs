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

using System.Net.Http.Json;
using System.Text.Json;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Posts grants to the provider's token endpoint and reads back what it returns.
/// </summary>
public sealed class TokenRequestService : ITokenRequestService
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this service resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    /// <remarks>
    /// A named client rather than a bare one so that a paid layer can hang a handler chain on this exact
    /// traffic: certificate-bound mutual TLS, or the retry that RFC 9449 requires when a provider answers a
    /// DPoP-protected request by demanding a fresh nonce.
    /// </remarks>
    public const string HttpClientName = "Abblix.Oidc.Client.Tokens";

    private readonly TokenEndpointClient _endpoint;

    /// <summary>
    /// Creates the service.
    /// </summary>
    public TokenRequestService(
        IProviderMetadataProvider metadataProvider,
        IHttpClientFactory httpClientFactory,
        IClientCredentialsPresenter credentialsPresenter)
        => _endpoint = new TokenEndpointClient(metadataProvider, httpClientFactory, credentialsPresenter);

    /// <inheritdoc />
    public Task<TokenResponse> ExchangeCodeAsync(
        string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default)
        => _endpoint.PostAsync(
            new Dictionary<string, string>
            {
                [Parameters.GrantType] = GrantTypes.AuthorizationCode,
                [Parameters.Code] = code,
                [Parameters.CodeVerifier] = codeVerifier,

                // Repeated from the authorization request, and compared by the provider against what it
                // recorded there. A mismatch is what stops a code from being redeemed into someone else's
                // client.
                [Parameters.RedirectUri] = redirectUri,
            },
            [],
            cancellationToken);

    /// <inheritdoc />
    public Task<TokenResponse> RefreshAsync(
        string refreshToken, CancellationToken cancellationToken = default)
        => _endpoint.PostAsync(
            new Dictionary<string, string>
            {
                [Parameters.GrantType] = GrantTypes.RefreshToken,
                [Parameters.RefreshToken] = refreshToken,
            },
            [],
            cancellationToken);

    /// <inheritdoc />
    public Task<TokenResponse> RequestClientCredentialsAsync(
        IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        var parameters = new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.ClientCredentials,
        };

        // Omitted rather than sent empty when nothing was asked for: RFC 6749 section 4.4.2 marks scope
        // OPTIONAL, and an empty value is a request for no scope at all, which is not the same thing.
        if (scopes is { Count: > 0 })
            parameters[Parameters.Scope] = string.Join(' ', scopes);

        return _endpoint.PostAsync(parameters, [], cancellationToken);
    }

    /// <inheritdoc />
    public Task<TokenResponse> ExchangeTokenAsync(
        TokenExchangeParameters exchange, CancellationToken cancellationToken = default)
    {
        // RFC 8693 section 2.1 requires actor_token_type when actor_token is present and forbids it when it
        // is absent. Both halves are checked, because sending a type for a token that is not there is the
        // same mistake read from the other end: the caller believes it is delegating and is not.
        if ((exchange.ActorToken is null) != (exchange.ActorTokenType is null))
            throw new ArgumentException(
                "An actor token and its type go together: RFC 8693 section 2.1 requires actor_token_type "
                + "when actor_token is present, and forbids it otherwise.",
                nameof(exchange));

        var parameters = new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.TokenExchange,
            [Parameters.SubjectToken] = exchange.SubjectToken,
            [Parameters.SubjectTokenType] = exchange.SubjectTokenType,
        };

        if (exchange.ActorToken is { } actorToken)
        {
            parameters[Parameters.ActorToken] = actorToken;
            parameters[Parameters.ActorTokenType] = exchange.ActorTokenType!;
        }

        if (exchange.RequestedTokenType is { } requestedTokenType)
            parameters[Parameters.RequestedTokenType] = requestedTokenType;

        if (exchange.Scopes is { Count: > 0 })
            parameters[Parameters.Scope] = string.Join(' ', exchange.Scopes);

        // resource and audience may each be given more than once, and the specification says so in as many
        // words. Joining them into one value would name a service nobody has.
        var repeated = exchange.Resources
            .Select(resource => new KeyValuePair<string, string>(Parameters.Resource, resource.AbsoluteUri))
            .Concat(exchange.Audiences.Select(audience => new KeyValuePair<string, string>(Parameters.Audience, audience)))
            .ToArray();

        return _endpoint.PostAsync(parameters, repeated, cancellationToken);
    }

    /// <inheritdoc />
    public Task<TokenResponse> RedeemDeviceCodeAsync(
        string deviceCode, CancellationToken cancellationToken = default)
        => _endpoint.PostAsync(
            new Dictionary<string, string>
            {
                [Parameters.GrantType] = GrantTypes.DeviceCode,
                [Parameters.DeviceCode] = deviceCode,
            },
            [],
            cancellationToken);

    /// <inheritdoc />
    public Task<TokenResponse> RedeemAuthenticationRequestAsync(
        string authenticationRequestId, CancellationToken cancellationToken = default)
        => _endpoint.PostAsync(
            new Dictionary<string, string>
            {
                [Parameters.GrantType] = GrantTypes.Ciba,
                [Parameters.AuthenticationRequestId] = authenticationRequestId,
            },
            [],
            cancellationToken);

}
