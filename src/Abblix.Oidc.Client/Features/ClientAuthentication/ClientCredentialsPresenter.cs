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


using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.ClientAuthentication;

/// <summary>
/// Presents the client's credentials the way the host configured, on any request that needs them.
/// </summary>
/// <param name="clientOptions">Supplies the client identifier every method has to state.</param>
/// <param name="options">Supplies the configured method and secret.</param>
public sealed class ClientCredentialsPresenter(
    IOptions<OidcClientOptions> clientOptions,
    IOptions<ClientAuthenticationOptions> options) : IClientCredentialsPresenter
{
    private readonly OidcClientOptions _clientOptions = clientOptions.Value;
    private readonly ClientAuthenticationOptions _options = options.Value;

    /// <inheritdoc />
    /// <remarks>
    /// The method is configured rather than picked from what the provider advertises. Choosing the strongest
    /// method a provider claims to support sounds helpful, but it lets the provider's own document decide how
    /// this client authenticates, and a downgrade there is silent.
    /// </remarks>
    public void Present(HttpRequestMessage request, IDictionary<string, string> parameters)
    {
        switch (_options.Method)
        {
            case ClientAuthenticationMethods.ClientSecretBasic:
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicCredentials());
                break;

            case ClientAuthenticationMethods.ClientSecretPost:
                parameters["client_id"] = _clientOptions.ClientId;
                parameters["client_secret"] = RequireSecret();
                break;

            case ClientAuthenticationMethods.None:
                // A public client has no secret to present, but still has to say who it is. RFC 6749
                // section 3.2.1 requires client_id from a client that does not authenticate.
                parameters["client_id"] = _clientOptions.ClientId;
                break;

            default:
                throw new ClientAuthenticationException(
                    $"Client authentication method '{_options.Method}' is not one this client can present.");
        }
    }

    /// <summary>
    /// Builds the HTTP Basic credentials of RFC 6749 section 2.3.1.
    /// </summary>
    /// <remarks>
    /// Both halves are form-encoded before being joined, which the specification requires and which matters
    /// for a secret containing a colon or a non-ASCII character. Skipping it produces credentials the
    /// provider reads as a different secret entirely.
    /// </remarks>
    private string BasicCredentials()
    {
        var userName = Uri.EscapeDataString(_clientOptions.ClientId);
        var password = Uri.EscapeDataString(RequireSecret());

        return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{userName}:{password}"));
    }

    private string RequireSecret()
        => _options.ClientSecret
           ?? throw new ClientAuthenticationException(
               $"Client authentication method '{_options.Method}' needs a client secret, but "
               + $"{nameof(ClientAuthenticationOptions)}.{nameof(ClientAuthenticationOptions.ClientSecret)} "
               + "is not set.");
}
