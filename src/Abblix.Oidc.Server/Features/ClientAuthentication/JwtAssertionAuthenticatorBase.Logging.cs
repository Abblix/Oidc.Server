// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class JwtAssertionAuthenticatorBase
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.WrongAssertionType,
        Level = LogLevel.Warning,
        Message = "client_assertion_type is not 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'")]
    private partial void LogWrongAssertionType();

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.MissingAssertion,
        Level = LogLevel.Warning,
        Message = "client_assertion_type is 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', but client_assertion is empty")]
    private partial void LogMissingAssertion();

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.JwtValidationError,
        Level = LogLevel.Warning,
        Message = "JWT validation error: {@Error}")]
    private partial void LogJwtValidationError(JwtValidationError Error);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.AuthMethodNotAllowed,
        Level = LogLevel.Warning,
        Message = "The authentication method is not allowed for the client {@ClientId}")]
    private partial void LogAuthMethodNotAllowed(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.SubjectExtractionFailed,
        Level = LogLevel.Warning,
        Message = "The error while getting subject: {Message}")]
    private partial void LogSubjectExtractionFailed(Exception ex, string Message);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.IssuerSubjectMismatch,
        Level = LogLevel.Warning,
        Message = "The error during authentication: iss is '{Issuer}', but sub is {Subject}")]
    private partial void LogIssuerSubjectMismatch(string? Issuer, string? Subject);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.MissingJti,
        Level = LogLevel.Warning,
        Message = "The client assertion for {@ClientId} has no jti claim, which OIDC Core §9 requires for single-use replay protection")]
    private partial void LogMissingJti(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.OtherKindPresentedAsAssertion,
        Level = LogLevel.Warning,
        Message = "The client assertion for {ClientId} declares typ {TokenType}, which names another kind of JWT rather than an authentication assertion")]
    private partial void LogOtherKindPresentedAsAssertion(string ClientId, string? TokenType);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.SigningAlgorithmNotAllowed,
        Level = LogLevel.Warning,
        Message = "The client assertion for {ClientId} uses algorithm {Algorithm}, but the client registered token_endpoint_auth_signing_alg {RequiredAlgorithm}")]
    private partial void LogSigningAlgorithmNotAllowed(string ClientId, string? Algorithm, string RequiredAlgorithm);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.MissingExpiration,
        Level = LogLevel.Warning,
        Message = "The client assertion for {ClientId} has no exp claim, which RFC 7523 §3 requires to bound the assertion's usage window")]
    private partial void LogMissingExpiration(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.ReplayDetected,
        Level = LogLevel.Warning,
        Message = "The client assertion jti {Jti} for {ClientId} has already been used; possible replay attack")]
    private partial void LogReplayDetected(string Jti, string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.TimestampsOutsideTheClientsProfile,
        Level = LogLevel.Warning,
        Message = "The assertion from {ClientId} passed the deployment's clock tolerance but not the "
                  + "one the client's own security profile allows: {Refusal}")]
    private partial void LogTimestampsOutsideTheClientsProfile(string ClientId, string Refusal);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.JwtAssertionAuthenticatorBase.AudienceIsNotTheIssuerAlone,
        Level = LogLevel.Warning,
        Message = "The client assertion for {ClientId} carries {@Audiences} where the profile "
                  + "governing it accepts the issuer identifier {IssuerIdentifier} alone")]
    private partial void LogAudienceIsNotTheIssuerAlone(
        string ClientId,
        string[] Audiences,
        string IssuerIdentifier);
}
