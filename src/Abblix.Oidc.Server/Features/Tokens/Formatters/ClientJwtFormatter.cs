// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Provides functionality to format JSON Web Tokens (JWTs) issued to clients by the authentication service.
/// This class handles the signing of JWTs and, if configured, their encryption, based on the needs of each client.
/// </summary>
/// <param name="logger">Logs each JWT refused, at the level of its cause.</param>
/// <param name="issuer">Issues the JWT once the client's profile admits its algorithms.</param>
/// <param name="encryptionKeyResolver">Chooses the key the JWT is encrypted to under the algorithm the client
/// registered.</param>
/// <param name="serviceKeysProvider">Provider for service signing keys.</param>
/// <param name="signingAlgorithms">Tells which algorithms a key signs with.</param>
public partial class ClientJwtFormatter(
    ILogger<ClientJwtFormatter> logger,
    ProfiledJwtIssuer issuer,
    ClientEncryptionKeyResolver encryptionKeyResolver,
    IAuthServiceKeysProvider serviceKeysProvider,
    SigningAlgorithmsProvider signingAlgorithms) : IClientJwtFormatter
{
    /// <summary>
    /// Asynchronously formats a JWT for a specific client, signing it with the authentication service's key chosen by
    /// the token's header algorithm and - per the supplied <paramref name="encryption"/> policy - optionally
    /// encrypting it to the client's registered public key.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="token">The JSON Web Token (JWT) to be formatted for the client.</param>
    /// <param name="clientInfo">Information about the client to which the JWT is issued.</param>
    /// <param name="encryption">The encryption policy: the key management and content encryption algorithms the
    /// client registered for this JWT, and the content-encryption default.</param>
    /// <returns>A task that returns a JWT string formatted and ready for use by the client, or the refusal of a JWT
    /// that cannot be issued to it, which the caller answers in its own protocol.</returns>
    /// <remarks>
    /// Every JWT the server signs for a client passes here - ID tokens, logout tokens, and JWT authorization, userinfo
    /// and introspection responses - so this is where the client's algorithm is held to its security profile and to
    /// the tenant's signing keys whatever changed since the client was checked at startup or registration: the
    /// client's registration, the tenant's keys, or a code or session from before either.
    /// </remarks>
    public async Task<Result<string, OidcError>> FormatAsync(
        TenantDefinition tenant, JsonWebToken token, ClientInfo clientInfo, ClientJwtEncryption encryption)
    {
        var profile = SecurityProfileRequirements.For(tenant, clientInfo);
        var algorithm = token.Header.Algorithm;
        var signingCredentials = await SigningKeyAsync(tenant, algorithm);
        if (WhyItCannotBeSigned(clientInfo, profile, algorithm, signingCredentials) is { } refusal)
            return Refused(clientInfo, refusal);

        // OpenID Connect Dynamic Client Registration 1.0 section 2, id_token_encrypted_response_alg: "JWE alg algorithm
        // [JWA] REQUIRED for encrypting the ID Token issued to this Client" and "The default, if omitted, is that no encryption
        // is performed"; JARM section 3 and the userinfo and introspection members say the same. Only a registered
        // algorithm asks for encryption, and the token is encrypted under exactly that algorithm
        if (encryption.KeyManagementAlgorithm is not { } keyEncryptionAlgorithm)
            return await issuer.IssueAsync(profile, token, signingCredentials);

        // The key is chosen here, where the token is issued, because the keys sit at a jwks_uri the client can change
        // after registration and a client secret can expire in between
        var contentEncryptionAlgorithm = encryption.ContentEncryptionAlgorithmInUse;
        var encryptingCredentials = await encryptionKeyResolver.ResolveAsync(
            profile, clientInfo, keyEncryptionAlgorithm, contentEncryptionAlgorithm);

        // A client that registered an algorithm expects what is issued to it encrypted, so a token is not sent in the
        // clear because the client has no key (or none could be read) that algorithm can encrypt to
        if (encryptingCredentials == null)
        {
            // unauthorized_client rather than invalid_client: the client is who it says, and it is the JWT it asked
            // for that cannot be issued (RFC 6749 section 5.2)
            return Refused(clientInfo, new ClientJwtRefusal(
                ClientJwtRefusalCause.NoClientEncryptionKey,
                $"The client {clientInfo.ClientId} has no key its registered {keyEncryptionAlgorithm} can encrypt to " +
                "under its security profile"));
        }

        if (signingCredentials is null && encryption.UnsignedIsClaimsSet)
        {
            return await issuer.EncryptClaimsAsync(
                profile, token, encryptingCredentials, keyEncryptionAlgorithm, contentEncryptionAlgorithm);
        }

        return await issuer.IssueAsync(
            profile,
            token,
            signingCredentials,
            encryptingCredentials,
            keyEncryptionAlgorithm,
            contentEncryptionAlgorithm);
    }

    /// <summary>
    /// Logs <paramref name="refusal"/> at the level of its cause and returns it. Every JWT issued to a client is refused
    /// here, so a tenant without the signing key a client needs is an error whichever endpoint met it, and the callers
    /// that record the refusal with their own context do not log its cause again.
    /// </summary>
    private ClientJwtRefusal Refused(ClientInfo clientInfo, ClientJwtRefusal refusal)
    {
        LogJwtNotIssued(refusal.LogLevel, clientInfo.ClientId, refusal.Cause, refusal.ErrorDescription);
        return refusal;
    }

    /// <summary>
    /// The first signing key of the tenant that performs <paramref name="algorithm"/>, or null for an unsigned token
    /// and where no key performs it.
    /// </summary>
    private async Task<JsonWebKey?> SigningKeyAsync(TenantDefinition tenant, string? algorithm)
    {
        if (IsUnsigned(algorithm))
            return null;

        var keys = await serviceKeysProvider.GetSigningKeys(tenant, true).ToArrayAsync();
        var signingKey = Array.Find(keys, key => signingAlgorithms.CanSign(key, algorithm));
        if (signingKey is null)
        {
            // The client is told only that no key produces the algorithm; the host is told which key it passed over
            // for its size, which a key held by a custodian or supplied by its own provider is checked for nowhere else
            foreach (var (key, bits, floor) in SigningKeyFloor.UndersizedKeys(keys, algorithm))
                LogSigningKeyBelowTheFloor(key.KeyId, algorithm, bits, floor);
        }

        return signingKey;
    }

    /// <summary>
    /// Why a JWT signed with <paramref name="algorithm"/> cannot be issued to the client, or null where it can: its
    /// security profile does not admit the algorithm, or no signing key of the tenant performs it, and a JWT is neither
    /// signed with another algorithm than the one the client registered nor sent unsigned in its place.
    /// </summary>
    /// <remarks>
    /// unauthorized_client rather than invalid_client, as for the encryption key: the client is who it says, and it is
    /// the JWT its registration asks for that cannot be issued (RFC 6749 section 5.2). Each caller answers the refusal
    /// in its own protocol.
    /// </remarks>
    private static ClientJwtRefusal? WhyItCannotBeSigned(
        ClientInfo clientInfo,
        SecurityProfileRequirements profile,
        string? algorithm,
        JsonWebKey? signingKey)
    {
        if (!profile.PermitsSigningAlgorithm(algorithm))
        {
            return new ClientJwtRefusal(
                ClientJwtRefusalCause.AlgorithmOutsideProfile,
                $"The client {clientInfo.ClientId} is registered for {algorithm ?? SigningAlgorithms.None} signatures, " +
                "which its security profile does not admit");
        }

        if (signingKey is null && !IsUnsigned(algorithm))
        {
            return new ClientJwtRefusal(
                ClientJwtRefusalCause.NoTenantSigningKey,
                $"The client {clientInfo.ClientId} is registered for {algorithm} signatures, which no signing key of " +
                "the tenant produces");
        }

        return null;
    }

    private static bool IsUnsigned([NotNullWhen(false)] string? algorithm)
        => algorithm is null or SigningAlgorithms.None;
}
