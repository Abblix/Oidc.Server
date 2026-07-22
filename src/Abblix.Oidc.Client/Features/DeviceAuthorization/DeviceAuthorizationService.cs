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
    /// The waiting itself, which RFC 8628 section 3.5 describes in the same words CIBA does.
    /// </summary>
    private readonly GrantPoller _poller = new(timeProvider);

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
    public Task<TokenResponse> WaitForTokensAsync(
        DeviceAuthorizationResponse authorization, CancellationToken cancellationToken = default)
        => _poller.PollAsync(
            authorization.PollingInterval,
            authorization.Lifetime,
            token => tokenRequestService.RedeemDeviceCodeAsync(authorization.DeviceCode, token),
            "The device authorization expired before its user authorized it.",
            cancellationToken);
}
