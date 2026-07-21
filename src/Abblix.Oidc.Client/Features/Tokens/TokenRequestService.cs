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

    private readonly IProviderMetadataProvider _metadataProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IClientCredentialsPresenter _credentialsPresenter;

    /// <summary>
    /// Creates the service.
    /// </summary>
    public TokenRequestService(
        IProviderMetadataProvider metadataProvider,
        IHttpClientFactory httpClientFactory,
        IClientCredentialsPresenter credentialsPresenter)
    {
        _metadataProvider = metadataProvider;
        _httpClientFactory = httpClientFactory;
        _credentialsPresenter = credentialsPresenter;
    }

    /// <inheritdoc />
    public Task<TokenResponse> ExchangeCodeAsync(
        string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default)
        => PostAsync(
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.AuthorizationCode,
                ["code"] = code,
                ["code_verifier"] = codeVerifier,

                // Repeated from the authorization request, and compared by the provider against what it
                // recorded there. A mismatch is what stops a code from being redeemed into someone else's
                // client.
                ["redirect_uri"] = redirectUri,
            },
            cancellationToken);

    /// <inheritdoc />
    public Task<TokenResponse> RefreshAsync(
        string refreshToken, CancellationToken cancellationToken = default)
        => PostAsync(
            new Dictionary<string, string>
            {
                ["grant_type"] = GrantTypes.RefreshToken,
                ["refresh_token"] = refreshToken,
            },
            cancellationToken);

    private async Task<TokenResponse> PostAsync(
        Dictionary<string, string> parameters, CancellationToken cancellationToken)
    {
        var metadata = await _metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.TokenEndpoint is not { } tokenEndpoint)
            throw new TokenRequestException(
                $"The OpenID Provider '{metadata.Issuer}' names no token endpoint, so no grant can be "
                + "redeemed.");

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        _credentialsPresenter.Present(request, parameters);
        request.Content = new FormUrlEncodedContent(parameters);

        HttpResponseMessage response;
        try
        {
            var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            response = await httpClient.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw new TokenRequestException(
                $"Failed to reach the token endpoint of OpenID Provider '{metadata.Issuer}' at "
                + $"'{tokenEndpoint}'.",
                exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                await ThrowRefusalAsync(response, metadata, cancellationToken);

            return await ReadSuccessAsync(response, metadata, tokenEndpoint, cancellationToken);
        }
    }

    private static async Task ThrowRefusalAsync(
        HttpResponseMessage response, ProviderMetadata metadata, CancellationToken cancellationToken)
    {
        TokenErrorResponse? error = null;
        try
        {
            error = await response.Content.ReadFromJsonAsync<TokenErrorResponse>(cancellationToken);
        }
        catch (JsonException)
        {
            // A provider that answers a refusal with something other than the documented shape still refused.
            // The status code is the part that matters, so the unreadable body is not allowed to mask it.
        }

        throw new TokenRequestException(
            $"The token endpoint of OpenID Provider '{metadata.Issuer}' refused the request with status "
            + $"{(int)response.StatusCode}"
            + (error?.Error is { } code ? $" and error '{code}'." : "."),
            error?.Error,
            error?.ErrorDescription);
    }

    private static async Task<TokenResponse> ReadSuccessAsync(
        HttpResponseMessage response,
        ProviderMetadata metadata,
        string tokenEndpoint,
        CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken)
                   ?? throw new TokenRequestException(
                       $"The token endpoint of OpenID Provider '{metadata.Issuer}' returned an empty "
                       + "response.");
        }
        catch (JsonException exception)
        {
            throw new TokenRequestException(
                $"Failed to read the response of the token endpoint at '{tokenEndpoint}'.", exception);
        }
    }
}
