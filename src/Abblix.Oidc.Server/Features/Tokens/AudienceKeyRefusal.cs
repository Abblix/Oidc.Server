// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Records the refusal of an audience a token cannot be encrypted to.
/// </summary>
/// <remarks>
/// The refusal is the resource's to answer for rather than the server's, so it is recorded as a warning and goes on as
/// <see cref="AudienceKeyRefusedException"/>, which the endpoint answers as an unusable resource.
/// </remarks>
internal static partial class AudienceKeyRefusal
{
    /// <summary>
    /// Points <paramref name="encryption"/> at the audience's key as
    /// <see cref="ServiceJwtEncryptionExtensions.WithAudienceKeyAsync"/> does, recording a refusal of the audience's
    /// keys.
    /// </summary>
    /// <param name="encryption">The policy projected from the server's own settings.</param>
    /// <param name="tenant">The tenant the token is issued at.</param>
    /// <param name="client">The client the token is issued to.</param>
    /// <param name="context">The authorization context naming the token's audience.</param>
    /// <param name="audienceKeys">Answers which key, if any, the named audience published.</param>
    /// <param name="logger">Records the refusal.</param>
    /// <exception cref="AudienceKeyRefusedException">The token cannot be encrypted to its audience.</exception>
    public static async Task<ServiceJwtEncryption> WithAudienceKeyAsync(
        ServiceJwtEncryption encryption,
        TenantDefinition tenant,
        ClientInfo client,
        AuthorizationContext context,
        IAudienceKeyResolver audienceKeys,
        ILogger logger)
    {
        try
        {
            return await encryption.WithAudienceKeyAsync(tenant, client, context, audienceKeys);
        }
        catch (AudienceKeyRefusedException refused)
        {
            LogAudienceKeyRefused(
                logger, Sanitized.Value(string.Join(" ", refused.Resources)), Sanitized.Value(refused.Message));
            throw;
        }
    }

    [LoggerMessage(
        EventId = LogEvents.TokenIssuance.AccessTokenService.AudienceKeyRefused,
        Level = LogLevel.Warning,
        Message = "No access token issued for {Resources}, which it cannot be encrypted to: {Reason}")]
    private static partial void LogAudienceKeyRefused(ILogger logger, Sanitized resources, Sanitized reason);
}
