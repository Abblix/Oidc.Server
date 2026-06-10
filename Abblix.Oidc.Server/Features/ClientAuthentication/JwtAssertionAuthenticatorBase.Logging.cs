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
}
