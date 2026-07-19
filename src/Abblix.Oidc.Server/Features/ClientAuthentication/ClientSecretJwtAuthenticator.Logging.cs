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
