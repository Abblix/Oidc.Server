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
using Abblix.Oidc.Server.Common;
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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the registration of new clients by generating the necessary credentials and adding client information to
/// the system. Ensures the secure and compliant registration of clients as per OAuth 2.0 and OpenID Connect standards.
/// </summary>
/// <param name="clientIdGenerator">Responsible for generating unique client IDs.</param>
/// <param name="clientSecretGenerator">Responsible for generating secure client secrets.</param>
/// <param name="hashService">Provides hashing services for client secrets.</param>
/// <param name="clientInfoManager">Manages storage and retrieval of client information.</param>
/// <param name="clock">Provides time-related functionality, crucial for token issuance and expiration.</param>
/// <param name="options">Configuration options for client registration, including secret length and expiration.</param>
/// <param name="serviceJwtFormatter">Formats JWTs for service use, including registration access tokens.</param>
/// <param name="issuerProvider">Provides issuer information, necessary for token issuance.</param>
public class RegisterClientRequestProcessor(
    IClientIdGenerator clientIdGenerator,
    IClientSecretGenerator clientSecretGenerator,
    IHashService hashService,
    IClientInfoManager clientInfoManager,
    TimeProvider clock,
    NewClientOptions options,
    IAuthServiceJwtFormatter serviceJwtFormatter,
    IIssuerProvider issuerProvider) : IRegisterClientRequestProcessor
{
    /// <summary>
    /// Processes a valid client registration request, generating and storing the client's credentials and configuration.
    /// </summary>
    /// <param name="request">The client registration request containing the necessary details for registering
    /// a new client.</param>
    /// <returns>A task that results in a Result containing the client ID,
    /// client secret and registration access token, along with other registration details.</returns>
    /// <remarks>
    /// This method orchestrates the client registration process, starting from generating a unique client ID
    /// and secret (if required) to issuing a registration access token. It ensures that all registered clients
    /// are compliant with the system's security standards and the OAuth 2.0 and OpenID Connect protocols.
    /// The method also handles the storage of client information, facilitating future authentication and
    /// authorization processes.
    /// </remarks>
    public async Task<Result<ClientRegistrationSuccessResponse, OidcError>> ProcessAsync(ValidClientRegistrationRequest request)
    {
        var model = request.Model;

        var issuedAt = clock.GetUtcNow();
        var clientId = model.ClientId.HasValue() ? model.ClientId : clientIdGenerator.GenerateClientId();
        var (clientSecret, expiresAt) = GenerateClientSecret(model.TokenEndpointAuthMethod, issuedAt);

        var clientInfo = ToClientInfo(model, clientId, clientSecret, expiresAt, request.SectorIdentifier);
        await clientInfoManager.AddClientAsync(clientInfo);

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
                var clientSecret = clientSecretGenerator.GenerateClientSecret(options.ClientSecret.Length);
                var expiresAt = issuedAt + options.ClientSecret.ExpiresAfter;
                return (clientSecret, expiresAt);

            default:
                // It is unnecessary for Clients selecting a token_endpoint_auth_method of private_key_jwt
                // unless symmetric encryption will be used
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
            BackChannelTokenDeliveryMode = model.BackChannelTokenDeliveryMode,
            BackChannelClientNotificationEndpoint = model.BackChannelClientNotificationEndpoint,
            BackChannelAuthenticationRequestSigningAlg = model.BackChannelAuthenticationRequestSigningAlg,
            BackChannelUserCodeParameter = model.BackChannelUserCodeParameter,
            ApplicationType = model.ApplicationType,
            Contacts = model.Contacts,
            ClientName = model.ClientName,
            ClientUri = model.ClientUri,
            DefaultMaxAge = model.DefaultMaxAge,
            RequireAuthTime = model.RequireAuthTime,
            DefaultAcrValues = model.DefaultAcrValues,
            IdentityTokenEncryptedResponseAlgorithm = model.IdTokenEncryptedResponseAlg,
            IdentityTokenEncryptedResponseEncryption = model.IdTokenEncryptedResponseEnc,
            UserInfoEncryptedResponseAlgorithm = model.UserInfoEncryptedResponseAlg,
            UserInfoEncryptedResponseEncryption = model.UserInfoEncryptedResponseEnc,
            RequestObjectSigningAlgorithm = model.RequestObjectSigningAlg,
            RequestObjectEncryptionAlgorithm = model.RequestObjectEncryptionAlg,
            RequestObjectEncryptionMethod = model.RequestObjectEncryptionEnc,
            TokenEndpointAuthSigningAlgorithm = model.TokenEndpointAuthSigningAlg,
        };

        if (clientSecret.HasValue())
        {
            clientInfo.ClientSecrets =
            [
                new ClientSecret
                {
                    Value = clientInfo.TokenEndpointAuthMethod == ClientAuthenticationMethods.ClientSecretJwt
                        ? clientSecret
                        : null,
                    Sha512Hash = hashService.Sha(HashAlgorithm.Sha512, clientSecret),
                    ExpiresAt = expiresAt,
                }
            ];
        }

        if (model.RequestUris != null)
        {
            clientInfo.RequestUris = model.RequestUris;
        }

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
                model.BackChannelLogoutSessionRequired ?? false);
        }

        if (model.FrontChannelLogoutUri != null)
        {
            clientInfo.FrontChannelLogout = new FrontChannelLogoutOptions(
                model.FrontChannelLogoutUri,
                model.FrontChannelLogoutSessionRequired ?? false);
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

                Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),
                Audiences = [clientId],
                Subject = clientId,
            },
        };

        return serviceJwtFormatter.FormatAsync(token);
    }
}
