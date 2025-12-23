// Abblix OIDC Server Library
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

using System;
using System.Linq;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure.Builders;

/// <summary>
/// Fluent builder for creating ClientInfo test objects.
/// Provides sensible defaults and eliminates duplicated factory code across tests.
/// </summary>
/// <example>
/// <code>
/// var client = new ClientInfoBuilder()
///     .WithClientId("my_client")
///     .WithSecret("my_secret")
///     .WithGrantTypes(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken)
///     .WithRedirectUri("https://example.com/callback")
///     .Build();
/// </code>
/// </example>
public class ClientInfoBuilder
{
    private string _clientId = TestConstants.DefaultClientId;
    private string[] _clientSecrets = [TestConstants.DefaultClientSecret];
    private string _authMethod = ClientAuthenticationMethods.ClientSecretPost;
    private string[] _grantTypes = [GrantTypes.AuthorizationCode];
    private Uri[] _redirectUris = [new(TestConstants.DefaultRedirectUri)];
    private TimeSpan _accessTokenExpiresIn = TestConstants.DefaultAccessTokenLifetime;
    private TimeSpan _authorizationCodeExpiresIn = TestConstants.DefaultAuthorizationCodeLifetime;
    private bool? _pkceRequired;
    private string? _clientName;
    private Uri? _clientUri;
    private Uri? _logoUri;
    private string[]? _contacts;
    private Uri[]? _postLogoutRedirectUris;
    private Uri? _jwksUri;
    private string? _backchannelTokenDeliveryMode;
    private Uri? _backchannelClientNotificationEndpoint;
    private string? _backchannelAuthenticationRequestSigningAlg;
    private bool? _backchannelUserCodeParameter;

    /// <summary>
    /// Sets the client ID.
    /// </summary>
    public ClientInfoBuilder WithClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    /// <summary>
    /// Sets a single client secret.
    /// The secret will be hashed using TestSecretHasher (SHA-512 with UTF-8).
    /// </summary>
    public ClientInfoBuilder WithSecret(string secret)
    {
        _clientSecrets = [secret];
        return this;
    }

    /// <summary>
    /// Sets multiple client secrets.
    /// All secrets will be hashed using TestSecretHasher (SHA-512 with UTF-8).
    /// </summary>
    public ClientInfoBuilder WithSecrets(params string[] secrets)
    {
        _clientSecrets = secrets;
        return this;
    }

    /// <summary>
    /// Sets the token endpoint authentication method.
    /// </summary>
    public ClientInfoBuilder WithAuthMethod(string method)
    {
        _authMethod = method;
        return this;
    }

    /// <summary>
    /// Sets the allowed grant types.
    /// </summary>
    public ClientInfoBuilder WithGrantTypes(params string[] grantTypes)
    {
        _grantTypes = grantTypes;
        return this;
    }

    /// <summary>
    /// Sets a single redirect URI.
    /// </summary>
    public ClientInfoBuilder WithRedirectUri(string uri)
    {
        _redirectUris = [new Uri(uri)];
        return this;
    }

    /// <summary>
    /// Sets a single redirect URI.
    /// </summary>
    public ClientInfoBuilder WithRedirectUri(Uri uri)
    {
        _redirectUris = [uri];
        return this;
    }

    /// <summary>
    /// Sets multiple redirect URIs.
    /// </summary>
    public ClientInfoBuilder WithRedirectUris(params string[] uris)
    {
        _redirectUris = uris.Select(u => new Uri(u)).ToArray();
        return this;
    }

    /// <summary>
    /// Sets multiple redirect URIs.
    /// </summary>
    public ClientInfoBuilder WithRedirectUris(params Uri[] uris)
    {
        _redirectUris = uris;
        return this;
    }

    /// <summary>
    /// Sets the access token expiration time.
    /// </summary>
    public ClientInfoBuilder WithAccessTokenExpiration(TimeSpan expiresIn)
    {
        _accessTokenExpiresIn = expiresIn;
        return this;
    }

    /// <summary>
    /// Sets the authorization code expiration time.
    /// </summary>
    public ClientInfoBuilder WithAuthorizationCodeExpiration(TimeSpan expiresIn)
    {
        _authorizationCodeExpiresIn = expiresIn;
        return this;
    }

    /// <summary>
    /// Configures whether PKCE (Proof Key for Code Exchange) is required.
    /// </summary>
    public ClientInfoBuilder WithPkce(bool required = true)
    {
        _pkceRequired = required;
        return this;
    }

    /// <summary>
    /// Sets the human-readable client name.
    /// </summary>
    public ClientInfoBuilder WithClientName(string name)
    {
        _clientName = name;
        return this;
    }

    /// <summary>
    /// Sets the client URI (homepage).
    /// </summary>
    public ClientInfoBuilder WithClientUri(string uri)
    {
        _clientUri = new Uri(uri);
        return this;
    }

    /// <summary>
    /// Sets the logo URI.
    /// </summary>
    public ClientInfoBuilder WithLogoUri(string uri)
    {
        _logoUri = new Uri(uri);
        return this;
    }

    /// <summary>
    /// Sets contact email addresses.
    /// </summary>
    public ClientInfoBuilder WithContacts(params string[] contacts)
    {
        _contacts = contacts;
        return this;
    }

    /// <summary>
    /// Sets post-logout redirect URIs.
    /// </summary>
    public ClientInfoBuilder WithPostLogoutRedirectUris(params string[] uris)
    {
        _postLogoutRedirectUris = uris.Select(u => new Uri(u)).ToArray();
        return this;
    }

    /// <summary>
    /// Sets the JWKS URI for public key retrieval.
    /// </summary>
    public ClientInfoBuilder WithJwksUri(string uri)
    {
        _jwksUri = new Uri(uri);
        return this;
    }

    /// <summary>
    /// Configures CIBA (Client Initiated Backchannel Authentication) settings.
    /// </summary>
    public ClientInfoBuilder WithCiba(
        string deliveryMode,
        Uri? notificationEndpoint = null,
        string? signingAlg = null,
        bool? userCodeParameter = null)
    {
        _backchannelTokenDeliveryMode = deliveryMode;
        _backchannelClientNotificationEndpoint = notificationEndpoint;
        _backchannelAuthenticationRequestSigningAlg = signingAlg;
        _backchannelUserCodeParameter = userCodeParameter;
        return this;
    }

    /// <summary>
    /// Builds the ClientInfo instance with all configured values.
    /// </summary>
    /// <returns>A fully configured ClientInfo object for testing.</returns>
    public ClientInfo Build()
    {
        var clientInfo = new ClientInfo(_clientId)
        {
            ClientSecrets = _clientSecrets
                .Select(secret => new ClientSecret
                {
                    Sha512Hash = TestSecretHasher.HashSecret(secret)
                })
                .ToArray(),
            TokenEndpointAuthMethod = _authMethod,
            AllowedGrantTypes = _grantTypes,
            RedirectUris = _redirectUris,
            AccessTokenExpiresIn = _accessTokenExpiresIn,
            AuthorizationCodeExpiresIn = _authorizationCodeExpiresIn,
            ClientName = _clientName,
            ClientUri = _clientUri,
            LogoUri = _logoUri,
            Contacts = _contacts,
            PostLogoutRedirectUris = _postLogoutRedirectUris ?? [],
            JwksUri = _jwksUri,
            BackChannelTokenDeliveryMode = _backchannelTokenDeliveryMode,
            BackChannelClientNotificationEndpoint = _backchannelClientNotificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = _backchannelAuthenticationRequestSigningAlg,
        };

        if (_pkceRequired.HasValue)
        {
            clientInfo.PkceRequired = _pkceRequired.Value;
        }

        if (_backchannelUserCodeParameter.HasValue)
        {
            clientInfo.BackChannelUserCodeParameter = _backchannelUserCodeParameter.Value;
        }

        return clientInfo;
    }

    /// <summary>
    /// Creates a default ClientInfo for basic testing scenarios.
    /// </summary>
    public static ClientInfo Default() => new ClientInfoBuilder().Build();

    /// <summary>
    /// Creates a ClientInfo configured for authorization code flow with PKCE.
    /// </summary>
    public static ClientInfo ForAuthorizationCodeFlow() => new ClientInfoBuilder()
        .WithGrantTypes(GrantTypes.AuthorizationCode, GrantTypes.RefreshToken)
        .WithPkce()
        .Build();

    /// <summary>
    /// Creates a ClientInfo configured for client credentials flow.
    /// </summary>
    public static ClientInfo ForClientCredentials() => new ClientInfoBuilder()
        .WithGrantTypes(GrantTypes.ClientCredentials)
        .WithAuthMethod(ClientAuthenticationMethods.ClientSecretPost)
        .Build();

    /// <summary>
    /// Creates a ClientInfo configured for CIBA with push mode.
    /// </summary>
    public static ClientInfo ForCibaPushMode(Uri notificationEndpoint) => new ClientInfoBuilder()
        .WithGrantTypes(GrantTypes.Ciba)
        .WithCiba(BackchannelTokenDeliveryModes.Push, notificationEndpoint)
        .Build();

    /// <summary>
    /// Creates a ClientInfo configured for CIBA with poll mode.
    /// </summary>
    public static ClientInfo ForCibaPollMode() => new ClientInfoBuilder()
        .WithGrantTypes(GrantTypes.Ciba)
        .WithCiba(BackchannelTokenDeliveryModes.Poll)
        .Build();

    /// <summary>
    /// Creates a ClientInfo configured for CIBA with ping mode.
    /// </summary>
    public static ClientInfo ForCibaPingMode(Uri notificationEndpoint) => new ClientInfoBuilder()
        .WithGrantTypes(GrantTypes.Ciba)
        .WithCiba(BackchannelTokenDeliveryModes.Ping, notificationEndpoint)
        .Build();
}
