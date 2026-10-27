// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Handles the registration of new clients by generating the necessary credentials and adding client information to
/// the system. Ensures the secure and compliant registration of clients as per OAuth 2.0 and OpenID Connect standards.
/// </summary>
/// <param name="logger">Records a registration the client store did not keep.</param>
/// <param name="credentialFactory">Generates the client id and secret.</param>
/// <param name="clientInfoManager">Stores the registration with its registration access token id.</param>
/// <param name="clock">Provides the issue time.</param>
/// <param name="tokenIdGenerator">Generates the registration access token id.</param>
/// <param name="registrationAccessTokenService">Issues the registration access token.</param>
/// <param name="newClientOptions">The defaults a newly registered client takes, its scope among them.</param>
public partial class RegisterClientRequestProcessor(
    ILogger<RegisterClientRequestProcessor> logger,
    IClientCredentialFactory credentialFactory,
    IClientInfoManager clientInfoManager,
    TimeProvider clock,
    ITokenIdGenerator tokenIdGenerator,
    IRegistrationAccessTokenService registrationAccessTokenService,
    NewClientOptions newClientOptions) : IRegisterClientRequestProcessor
{
    /// <summary>
    /// Processes a valid client registration request, generating and storing the client's credentials and configuration.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
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
    public async Task<Result<ClientRegistrationSuccessResponse, OidcError>> ProcessAsync(TenantDefinition tenant, ValidClientRegistrationRequest request)
    {
        var model = request.Model;

        var issuedAt = clock.GetUtcNow();
        var credentials = credentialFactory.Create(model.TokenEndpointAuthMethod, model.ClientId);
        var clientInfo = ToClientInfo(model, credentials, request.SectorIdentifier);

        // The registration holds the jti of its registration access token, so the management endpoint
        // accepts that token for this registration alone (RFC 7592 section 5).
        var registrationAccessTokenId = tokenIdGenerator.GenerateTokenId();

        // Issued before the client is stored: issuing stores nothing, though it signs the token, so a
        // failure to issue leaves no stored client that no token could manage, and a token for a
        // registration the store then refuses matches nothing and is never answered.
        var registrationAccessToken = await registrationAccessTokenService.IssueTokenAsync(
            tenant,
            credentials.ClientId,
            issuedAt,
            clientInfo.ExpiresAfter,
            registrationAccessTokenId);

        // The response echoes the registered metadata, so what the store now holds is the answer -
        // RFC 7591 section 3.2.1 asks for the server-assigned defaults to be visible to the client. A
        // registration the store did not keep - one racing another under the same id, or, in a store
        // following reloads, one under an id the settings came to configure meanwhile - is refused as
        // a taken id is.
        if (!await clientInfoManager.TryAddClientAsync(tenant, new RegisteredClient(clientInfo, registrationAccessTokenId)))
        {
            LogRegistrationNotKept(credentials.ClientId);
            return Validation.ErrorFactory.InvalidClientMetadata(
                $"The client with id={credentials.ClientId} is already registered");
        }

        var response = new ClientRegistrationSuccessResponse(
            credentials.ClientId,
            issuedAt,
            registrationAccessToken)
        {
            ClientSecret = credentials.ClientSecret,
            ClientSecretExpiresAt = credentials.ExpiresAt,
            Metadata = RegisteredClientMetadata.Of(clientInfo),
        };

        return response;
    }

    /// <summary>
    /// Converts the registration request and credentials into a ClientInfo entity for storage.
    /// </summary>
    private ClientInfo ToClientInfo(
        ClientRegistrationRequest model,
        ClientCredentials credentials,
        string? sectorIdentifier)
        => new ClientInfoBuilder(credentials.ClientId, model)
            .WithSectorIdentifier(sectorIdentifier)
            .WithDefaultScope(newClientOptions.Scope)
            .WithClientSecrets(ToClientSecrets(model.TokenEndpointAuthMethod, credentials))
            .Build();

    /// <summary>
    /// The secrets a newly registered client authenticates with, or null when its method uses none.
    /// </summary>
    /// <remarks>
    /// Only client_secret_jwt keeps the secret itself, since verifying the client's HMAC-signed assertion
    /// needs it; every other method is verified against the hash.
    /// </remarks>
    private static ClientSecret[]? ToClientSecrets(string tokenEndpointAuthMethod, ClientCredentials credentials)
    {
        if (!credentials.ClientSecret.HasValue())
            return null;

        return
        [
            new ClientSecret
            {
                Value = tokenEndpointAuthMethod switch
                {
                    ClientAuthenticationMethods.ClientSecretJwt => credentials.ClientSecret,
                    _ => null,
                },
                Sha512Hash = credentials.Sha512Hash,
                ExpiresAt = credentials.ExpiresAt,
            }
        ];
    }
}
