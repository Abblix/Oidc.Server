// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

partial class ClientJwtValidator
{
    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidator.ValidationFailed,
        Level = LogLevel.Warning,
        Message = "Client JWT validation failed. Error: {ErrorType}, Description: {Description}")]
    private partial void LogValidationFailed(string ErrorType, string Description);

    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidator.ClientIdMismatch,
        Level = LogLevel.Warning,
        Message = "Client ID mismatch: issuer resolves to {IssuerClientId}, but client_id claim is {ClaimClientId}")]
    private partial void LogClientIdMismatch(string IssuerClientId, string ClaimClientId);

    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidator.ClientNotDetermined,
        Level = LogLevel.Warning,
        Message = "Unable to determine client from JWT. No matching client found by issuer or client_id claim.")]
    private partial void LogClientNotDetermined();

    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidator.ValidationSucceeded,
        Level = LogLevel.Information,
        Message = "Client JWT validation succeeded for client: {ClientId}")]
    private partial void LogValidationSucceeded(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtValidator.AudienceValidationFailed,
        Level = LogLevel.Warning,
        Message = "Audience validation failed, token audiences: {@Audiences}, expected requestUri: {RequestUri} or issuer: {Issuer}")]
    private partial void LogAudienceValidationFailed(IReadOnlyCollection<string> Audiences, string RequestUri, string Issuer);
}
