// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class ClientSecretJwtAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.ClientSecretJwtAuthenticator.AudienceValidationFailed,
        Level = LogLevel.Warning,
        Message = "Audience validation failed, token audiences: {@Audiences}, actual requestUri: {RequestUri}")]
    private partial void LogAudienceValidationFailed(IReadOnlyCollection<string> Audiences, string RequestUri);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.ClientSecretJwtAuthenticator.WrongAuthMethod,
        Level = LogLevel.Debug,
        Message = "Client authentication failed: client {ClientId} uses another authentication method")]
    private partial void LogWrongAuthMethod(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.ClientSecretJwtAuthenticator.NoSecretsConfigured,
        Level = LogLevel.Warning,
        Message = "No client secrets configured for client {ClientId}")]
    private partial void LogNoSecretsConfigured(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.ClientSecretJwtAuthenticator.SecretWithoutRawValue,
        Level = LogLevel.Warning,
        Message = "Client secret for {ClientId} does not have a raw value, which is required for client_secret_jwt")]
    private partial void LogSecretWithoutRawValue(string ClientId);
}
