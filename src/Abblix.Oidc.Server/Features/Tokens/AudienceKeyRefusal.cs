// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Tells a refusal the issuing guard made of the key an access token's audience publishes from one of the server's own.
/// </summary>
/// <remarks>
/// The decision stays with <see cref="ProfiledJwtIssuer"/>; this only names whose it is. A key management algorithm
/// the profile forbids, taken from the key the audience publishes, is that resource's to answer for, so it becomes
/// <see cref="AudienceKeyRefusedException"/> and is recorded as a warning; any other refusal is the server's and goes on
/// as it was raised.
/// </remarks>
internal static partial class AudienceKeyRefusal
{
    /// <summary>
    /// Formats <paramref name="token"/> as <see cref="IAuthServiceJwtFormatter.FormatAsync"/> does, a refusal of the
    /// audience's key raised as <see cref="AudienceKeyRefusedException"/>.
    /// </summary>
    /// <param name="formatter">Formats the token through the issuing guard.</param>
    /// <param name="tenant">The tenant the token is issued at.</param>
    /// <param name="token">The access token.</param>
    /// <param name="client">The client the token is issued to.</param>
    /// <param name="encryption">The policy, which names the audience's key where it publishes one.</param>
    /// <param name="resources">The resources the token is for.</param>
    /// <param name="logger">Records the refusal.</param>
    /// <exception cref="AudienceKeyRefusedException">The profile forbids the key management algorithm the audience's
    /// key yields.</exception>
    public static async Task<string> FormatAsync(
        IAuthServiceJwtFormatter formatter,
        TenantDefinition tenant,
        JsonWebToken token,
        ClientInfo client,
        ServiceJwtEncryption encryption,
        IReadOnlyCollection<Uri> resources,
        ILogger logger)
    {
        try
        {
            return await formatter.FormatAsync(tenant, token, client, encryption);
        }
        catch (AlgorithmRefusedByProfileException refused)
            when (encryption.Key is { } audienceKey && ReferenceEquals(refused.EncryptionKey, audienceKey))
        {
            LogAudienceKeyRefused(
                logger, Sanitized.Value(string.Join(" ", resources)), Sanitized.Value(refused.Algorithm));
            throw new AudienceKeyRefusedException(resources, refused);
        }
    }

    [LoggerMessage(
        EventId = LogEvents.TokenIssuance.AccessTokenService.AudienceKeyRefused,
        Level = LogLevel.Warning,
        Message = "No access token issued for {Resources}: its encryption key would have it encrypted with {Algorithm}, which the security profile in force forbids")]
    private static partial void LogAudienceKeyRefused(ILogger logger, Sanitized resources, Sanitized algorithm);
}
