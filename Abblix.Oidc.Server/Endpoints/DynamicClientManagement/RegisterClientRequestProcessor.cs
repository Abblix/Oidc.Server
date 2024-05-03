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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using ClientRegistrationResponse = Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces.ClientRegistrationResponse;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the registration of new clients by generating necessary credentials and adding client information to
/// the system. Ensures the secure and compliant registration of clients as per OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class RegisterClientRequestProcessor : IRegisterClientRequestProcessor
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterClientRequestProcessor"/> with dependencies
    /// required for client registration.
    /// </summary>
    /// <param name="clientIdGenerator">Responsible for generating unique client IDs.</param>
    /// <param name="clientSecretGenerator">Responsible for generating secure client secrets.</param>
    /// <param name="hashService">Provides hashing services for client secrets.</param>
    /// <param name="clientInfoManager">Manages storage and retrieval of client information.</param>
    /// <param name="clock">Provides time-related functionality, crucial for token issuance and expiration.</param>
    /// <param name="options">Configuration options for client registration, including secret length and expiration.</param>
    /// <param name="serviceJwtFormatter">Formats JWTs for service use, including registration access tokens.</param>
    /// <param name="issuerProvider">Provides issuer information, necessary for token issuance.</param>
    public RegisterClientRequestProcessor(
        IClientIdGenerator clientIdGenerator,
        IClientSecretGenerator clientSecretGenerator,
        IHashService hashService,
        IClientInfoManager clientInfoManager,
        TimeProvider clock,
        NewClientOptions options,
        IAuthServiceJwtFormatter serviceJwtFormatter,
        IIssuerProvider issuerProvider)
    {
        _clientIdGenerator = clientIdGenerator;
        _clientSecretGenerator = clientSecretGenerator;
        _hashService = hashService;
        _clientInfoManager = clientInfoManager;
        _clock = clock;
        _options = options;
        _serviceJwtFormatter = serviceJwtFormatter;
        _issuerProvider = issuerProvider;
    }

    private readonly IClientIdGenerator _clientIdGenerator;
    private readonly IClientInfoManager _clientInfoManager;
    private readonly IClientSecretGenerator _clientSecretGenerator;
    private readonly IHashService _hashService;
    private readonly TimeProvider _clock;
    private readonly IIssuerProvider _issuerProvider;
    private readonly NewClientOptions _options;
    private readonly IAuthServiceJwtFormatter _serviceJwtFormatter;

    /// <summary>
    /// Processes a valid client registration request, generating and storing the client's credentials and configuration.
    /// </summary>
    /// <param name="request">The client registration request containing the necessary details for registering
    /// a new client.</param>
    /// <returns>A task that results in a <see cref="ClientRegistrationResponse"/>, which includes the client ID,
    /// client secret and registration access token, along with other registration details.</returns>
    /// <remarks>
    /// This method orchestrates the client registration process, starting from generating a unique client ID
    /// and secret (if required) to issuing a registration access token. It ensures that all registered clients
    /// are compliant with the system's security standards and the OAuth 2.0 and OpenID Connect protocols.
    /// The method also handles the storage of client information, facilitating future authentication and
    /// authorization processes.
    /// </remarks>
    public async Task<ClientRegistrationResponse> ProcessAsync(ValidClientRegistrationRequest request)
    {
        var model = request.Model;

        var issuedAt = _clock.GetUtcNow();
        var clientId = model.ClientId.HasValue() ? model.ClientId : _clientIdGenerator.GenerateClientId();
        var (clientSecret, expiresAt) = GenerateClientSecret(model.TokenEndpointAuthMethod, issuedAt);

        var clientInfo = ToClientInfo(model, clientId, clientSecret, expiresAt, request.SectorIdentifier);
        await _clientInfoManager.AddClientAsync(clientInfo);

        var response = new ClientRegistrationSuccessResponse(clientId, issuedAt)
        {
            ClientSecret = clientSecret,
            ClientSecretExpiresAt = expiresAt,
            RegistrationAccessToken = await IssueRegistrationAccessTokenAsync(clientId, issuedAt),
        };
        return response;
    }

    private (string? clientSecret, DateTimeOffset? expiresAt) GenerateClientSecret(
        string tokenEndpointAuthMethod,
        DateTimeOffset issuedAt)
    {
        switch (tokenEndpointAuthMethod)
        {
            case ClientAuthenticationMethods.ClientSecretBasic:
            case ClientAuthenticationMethods.ClientSecretPost:
                var clientSecret = _clientSecretGenerator.GenerateClientSecret(_options.ClientSecret.Length);
                var expiresAt = issuedAt + _options.ClientSecret.ExpiresAfter;
                return (clientSecret, expiresAt);

            default:
                // It is not needed for Clients selecting a token_endpoint_auth_method of private_key_jwt unless symmetric encryption will be used.
                return (clientSecret: null, expiresAt: null);
        }
    }

    private ClientInfo ToClientInfo(
        ClientRegistrationRequest model,
        string clientId,
        string? clientSecret,
        DateTimeOffset? expiresAt,
        string? sectorIdentifier)
    {
        var clientInfo = new ClientInfo(clientId)
        {
            ClientSecrets = clientSecret.HasValue()
                ? new[]
                {
                    new ClientSecret
                    {
                        Sha512Hash = _hashService.Sha(HashAlgorithm.Sha512, clientSecret),
                        ExpiresAt = expiresAt,
                    }
                }
                : null,

            TokenEndpointAuthMethod = model.TokenEndpointAuthMethod,
            AllowedResponseTypes = model.ResponseTypes,
            AllowedGrantTypes = model.GrantTypes,
            RedirectUris = model.RedirectUris,
            Jwks = model.Jwks,
            JwksUri = model.JwksUri,
            PkceRequired = model.PkceRequired,
            OfflineAccessAllowed = model.OfflineAccessAllowed,
            LogoUri = model.LogoUri,
            PolicyUri = model.PolicyUri,
            TermsOfServiceUri = model.TermsOfServiceUri,
            InitiateLoginUri = model.InitiateLoginUri,
            SubjectType = model.SubjectType,
            SectorIdentifier = sectorIdentifier,
            PostLogoutRedirectUris = model.PostLogoutRedirectUris,
        };

        if (model.UserInfoSignedResponseAlg.HasValue())
        {
            clientInfo.UserInfoSignedResponseAlgorithm = model.UserInfoSignedResponseAlg;
        }

        if (model.IdTokenSignedResponseAlg.HasValue())
        {
            clientInfo.IdentityTokenSignedResponseAlgorithm = model.IdTokenSignedResponseAlg;
        }

        if (model.BackChannelLogoutUri != null)
        {
            clientInfo.BackChannelLogout = new BackChannelLogoutOptions(
                model.BackChannelLogoutUri,
                model.BackChannelLogoutSessionRequired);
        }

        if (model.FrontChannelLogoutUri != null)
        {
            clientInfo.FrontChannelLogout = new FrontChannelLogoutOptions(
                model.FrontChannelLogoutUri,
                model.FrontChannelLogoutSessionRequired);
        }

        return clientInfo;
    }

    private Task<string> IssueRegistrationAccessTokenAsync(string clientId, DateTimeOffset issuedAt)
    {
        var token = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.RegistrationAccessToken,
                Algorithm = SigningAlgorithms.RS256,
            },
            Payload =
            {
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                //ExpiresAt = issuedAt + ..., //TODO think about the expiration of this token

                Issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer()),
                Audiences = new[] { clientId },
                Subject = clientId,
            },
        };

        return _serviceJwtFormatter.FormatAsync(token);
    }
}
