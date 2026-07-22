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

using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.PasswordGrant;

/// <summary>
/// Presents an end-user's username and password at the token endpoint.
/// </summary>
/// <remarks>
/// Separate from <see cref="TokenRequestService"/> on purpose: see <see cref="IPasswordGrantService"/> for
/// why a grant the security best current practice forbids is reached only through its own registration.
/// </remarks>
public sealed class PasswordGrantService : IPasswordGrantService
{
    private readonly TokenEndpointClient _endpoint;

    /// <summary>
    /// Creates the service.
    /// </summary>
    public PasswordGrantService(
        IProviderMetadataProvider metadataProvider,
        IHttpClientFactory httpClientFactory,
        IClientCredentialsPresenter credentialsPresenter)
        => _endpoint = new TokenEndpointClient(metadataProvider, httpClientFactory, credentialsPresenter);

    /// <inheritdoc />
    public Task<TokenResponse> RequestTokensAsync(
        string username,
        string password,
        IReadOnlyCollection<string>? scopes = null,
        CancellationToken cancellationToken = default)
    {
        var parameters = new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.Password,
            [Parameters.Username] = username,
            [Parameters.Password] = password,
        };

        // Omitted rather than sent empty when nothing was asked for: RFC 6749 section 4.3.2 marks scope
        // OPTIONAL, and an empty value is a request for no scope at all, which is not the same thing.
        if (scopes is { Count: > 0 })
            parameters[Parameters.Scope] = string.Join(' ', scopes);

        return _endpoint.PostAsync(parameters, [], cancellationToken);
    }
}
