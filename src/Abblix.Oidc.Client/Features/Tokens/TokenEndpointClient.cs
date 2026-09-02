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
/// Posts a form to the provider's token endpoint and reads back what it returns.
/// </summary>
/// <remarks>
/// Every grant differs only in the parameters it carries; finding the endpoint, presenting this client's
/// credentials, and telling a refusal from an unreadable answer are the same each time. Kept here so a grant
/// that lives outside <see cref="TokenRequestService"/> - one a host has to opt into by name - can be written
/// without a second copy of any of it.
/// </remarks>
/// <param name="metadataProvider">Supplies the token endpoint the provider published.</param>
/// <param name="httpClientFactory">Supplies the transport.</param>
/// <param name="credentialsPresenter">Presents this client's own credentials.</param>
internal sealed class TokenEndpointClient(
    IProviderMetadataProvider metadataProvider,
    IHttpClientFactory httpClientFactory,
    IClientCredentialsPresenter credentialsPresenter)
{
    /// <param name="parameters">
    /// The single-valued form parameters. Passed as a dictionary because the credentials presenter adds this
    /// client's own to it, and adding a credential twice is not something to leave possible.
    /// </param>
    /// <param name="repeated">
    /// Parameters a specification allows more than once, which no dictionary can hold. Appended after the
    /// credentials so that what is presented cannot be displaced by a caller's value.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    public async Task<TokenResponse> PostAsync(
        Dictionary<string, string> parameters,
        IReadOnlyCollection<KeyValuePair<string, string>> repeated,
        CancellationToken cancellationToken)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.TokenEndpoint is not { } tokenEndpoint)
            throw new TokenRequestException(
                $"The OpenID Provider '{metadata.Issuer}' names no token endpoint, so no grant can be "
                + "redeemed.");

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        credentialsPresenter.Present(request, parameters);
        request.Content = new FormUrlEncodedContent(parameters.Concat(repeated));

        HttpResponseMessage response;
        try
        {
            var httpClient = httpClientFactory.CreateClient(TokenRequestService.HttpClientName);
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
