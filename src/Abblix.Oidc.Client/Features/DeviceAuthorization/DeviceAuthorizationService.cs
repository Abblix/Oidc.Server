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
using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.DeviceAuthorization;

/// <summary>
/// Runs RFC 8628 from this side: asks for the code pair, then waits for the user by polling on the
/// provider's terms.
/// </summary>
/// <param name="metadataProvider">Supplies the device authorization endpoint the provider published.</param>
/// <param name="httpClientFactory">Supplies the transport.</param>
/// <param name="credentialsPresenter">Presents this client's credentials, as section 3.1 allows.</param>
/// <param name="tokenRequestService">Redeems the device code, one attempt per call.</param>
/// <param name="timeProvider">Measures the waiting, so a test does not have to sit through it.</param>
public sealed class DeviceAuthorizationService(
    IProviderMetadataProvider metadataProvider,
    IHttpClientFactory httpClientFactory,
    IClientCredentialsPresenter credentialsPresenter,
    ITokenRequestService tokenRequestService,
    TimeProvider timeProvider) : IDeviceAuthorizationService
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this service resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    public const string HttpClientName = "Abblix.Oidc.Client.DeviceAuthorization";

    /// <summary>
    /// What RFC 8628 section 3.5 adds to the interval each time the provider answers <c>slow_down</c>.
    /// </summary>
    private static readonly TimeSpan SlowDownIncrement = TimeSpan.FromSeconds(5);

    /// <inheritdoc />
    public async Task<DeviceAuthorizationResponse> RequestAsync(
        IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default)
    {
        var metadata = await metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.DeviceAuthorizationEndpoint is not { } endpoint)
            throw new DeviceAuthorizationException(
                $"The OpenID Provider '{metadata.Issuer}' names no device authorization endpoint, so a "
                + "device cannot be signed in this way.");

        var parameters = new Dictionary<string, string>();
        if (scopes is { Count: > 0 })
            parameters["scope"] = string.Join(' ', scopes);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        credentialsPresenter.Present(request, parameters);
        request.Content = new FormUrlEncodedContent(parameters);

        HttpResponseMessage response;
        try
        {
            var httpClient = httpClientFactory.CreateClient(HttpClientName);
            response = await httpClient.SendAsync(request, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw new DeviceAuthorizationException(
                $"Failed to reach the device authorization endpoint of OpenID Provider '{metadata.Issuer}' "
                + $"at '{endpoint}'.",
                exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
                throw new DeviceAuthorizationException(
                    $"The device authorization endpoint of OpenID Provider '{metadata.Issuer}' refused the "
                    + $"request with status {(int)response.StatusCode}.");

            try
            {
                return await response.Content.ReadFromJsonAsync<DeviceAuthorizationResponse>(cancellationToken)
                       ?? throw new DeviceAuthorizationException(
                           $"The device authorization endpoint of OpenID Provider '{metadata.Issuer}' "
                           + "returned an empty response.");
            }
            catch (JsonException exception)
            {
                throw new DeviceAuthorizationException(
                    $"Failed to read the response of the device authorization endpoint at '{endpoint}'.",
                    exception);
            }
        }
    }

    /// <inheritdoc />
    public async Task<TokenResponse> WaitForTokensAsync(
        DeviceAuthorizationResponse authorization, CancellationToken cancellationToken = default)
    {
        var interval = authorization.PollingInterval;

        // The deadline is read once, from the lifetime the provider stated, so a device whose user never
        // answers stops on its own rather than polling until something else stops it.
        var deadline = timeProvider.GetUtcNow() + authorization.Lifetime;

        while (true)
        {
            // Waiting first, not last: RFC 8628 section 3.5 says to wait "before each new request", and the
            // user has had no time at all at the moment the code was handed over.
            await Task.Delay(interval, timeProvider, cancellationToken);

            if (deadline <= timeProvider.GetUtcNow())
                throw new TokenRequestException(
                    "The device authorization expired before its user authorized it.",
                    TokenErrorCodes.ExpiredToken,
                    null);

            try
            {
                return await tokenRequestService.RedeemDeviceCodeAsync(
                    authorization.DeviceCode, cancellationToken);
            }
            catch (TokenRequestException refusal) when (refusal.Error == TokenErrorCodes.SlowDown)
            {
                // "the interval MUST be increased by 5 seconds for this and all subsequent requests" - so the
                // increase is kept rather than applied to the next wait alone.
                interval += SlowDownIncrement;
            }
            catch (TokenRequestException refusal) when (refusal.Error == TokenErrorCodes.AuthorizationPending)
            {
                // The user is still deciding. Every other refusal, expiry and denial included, is final and
                // travels out of here untouched: section 3.5 says a client receiving any other error "MUST
                // stop polling".
            }
        }
    }
}
