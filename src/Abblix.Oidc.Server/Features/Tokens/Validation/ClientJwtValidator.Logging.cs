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
