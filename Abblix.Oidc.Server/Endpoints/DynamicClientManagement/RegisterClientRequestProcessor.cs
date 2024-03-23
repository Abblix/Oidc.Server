// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Clock;
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
        IClock clock,
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
    private readonly IClock _clock;
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

        var issuedAt = _clock.UtcNow;
        var clientId = model.ClientId.HasValue() ? model.ClientId : _clientIdGenerator.GenerateClientId();
        var (clientSecret, expiresAt) = GenerateClientSecret(model.TokenEndpointAuthMethod, issuedAt);

        await _clientInfoManager.AddClientAsync(ToClientInfo(model, clientId, clientSecret, expiresAt, request.SectorIdentifier));

        var response = new ClientRegistrationSuccessResponse(clientId, issuedAt)
        {
            ClientSecret = clientSecret,
            ClientSecretExpiresAt = expiresAt,
            RegistrationAccessToken = await IssueRegistrationAccessToken(clientId, issuedAt),
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

    private Task<string> IssueRegistrationAccessToken(string clientId, DateTimeOffset issuedAt)
    {
        var token = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.RegistrationAccessToken,
                Algorithm = SigningAlgorithms.RS256,
            },
            Payload = {
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                //ExpiresAt = issuedAt + ..., //TODO think about the expiration of this token

                Issuer = LicenseChecker.CheckLicense(_issuerProvider.GetIssuer()),
                Audiences = new[] { clientId },
                Subject = clientId,
            },
        };

        return _serviceJwtFormatter.FormatAsync(token);
    }
}
