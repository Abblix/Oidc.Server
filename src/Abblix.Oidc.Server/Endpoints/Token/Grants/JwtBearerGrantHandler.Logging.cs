// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class JwtBearerGrantHandler
{
	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingAssertion,
		Level = LogLevel.Warning,
		Message = "JWT Bearer grant request missing required 'assertion' parameter from client {ClientId}")]
	private partial void LogMissingAssertion(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AssertionTooLarge,
		Level = LogLevel.Warning,
		Message = "JWT assertion too large ({Length} chars, max {MaxSize}) from client {ClientId}")]
	private partial void LogAssertionTooLarge(int Length, int MaxSize, string ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.ValidationFailed,
		Level = LogLevel.Warning,
		Message = "JWT assertion validation failed for client {ClientId}: {ErrorCode} - {ErrorDescription}")]
	private partial void LogValidationFailed(string ClientId, JwtError ErrorCode, string ErrorDescription);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingSubject,
		Level = LogLevel.Warning,
		Message = "JWT assertion missing required 'sub' claim for client {ClientId}")]
	private partial void LogMissingSubject(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingExpiration,
		Level = LogLevel.Warning,
		Message = "JWT assertion missing required 'exp' claim for issuer {Issuer}, client {ClientId}")]
	private partial void LogMissingExpiration(string ClientId, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AlgorithmNotAllowed,
		Level = LogLevel.Warning,
		Message = "JWT assertion rejected: algorithm {Algorithm} not allowed for issuer {Issuer}, client {ClientId}")]
	private partial void LogAlgorithmNotAllowed(string? Algorithm, string Issuer, string ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.TokenTypeNotAllowed,
		Level = LogLevel.Warning,
		Message = "JWT assertion rejected: token type '{TokenType}' not in allowed types [{AllowedTypes}], client {ClientId}, issuer {Issuer}")]
	private partial void LogTokenTypeNotAllowed(string TokenType, string AllowedTypes, string ClientId, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingIssuedAt,
		Level = LogLevel.Warning,
		Message = "JWT assertion rejected: missing 'iat' claim but MaxJwtAge is configured, client {ClientId}, issuer {Issuer}")]
	private partial void LogMissingIssuedAt(string ClientId, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.TooOld,
		Level = LogLevel.Warning,
		Message = "JWT assertion rejected: JWT too old. Issued at {IssuedAt}, age {JwtAge}, max allowed {MaxAge}, client {ClientId}, issuer {Issuer}")]
	private partial void LogTooOld(DateTimeOffset IssuedAt, TimeSpan JwtAge, TimeSpan MaxAge, string ClientId, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingJti,
		Level = LogLevel.Warning,
		Message = "JWT assertion missing required 'jti' claim for client {ClientId}, issuer {Issuer}")]
	private partial void LogMissingJti(string ClientId, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.ReplayDetected,
		Level = LogLevel.Warning,
		Message = "SECURITY: JWT replay attack detected - JTI: {JwtId}, Client: {ClientId}, Issuer: {Issuer}, KeyId: {KeyId}, IP: {ClientIp}")]
	private partial void LogReplayDetected(string JwtId, string ClientId, string Issuer, string KeyId, IPAddress? ClientIp);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.ScopesNotAllowed,
		Level = LogLevel.Warning,
		Message = "JWT Bearer grant rejected: scopes {InvalidScopes} not allowed for issuer {Issuer}")]
	private partial void LogScopesNotAllowed(string InvalidScopes, string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.GrantSucceeded,
		Level = LogLevel.Information,
		Message = "AUDIT: JWT Bearer grant SUCCESS - Client: {ClientId}, Subject: {Subject}, Issuer: {Issuer}, JTI: {JwtId}, KeyId: {KeyId}, IP: {ClientIp}")]
	private partial void LogGrantSucceeded(string ClientId, string Subject, string Issuer, string JwtId, string KeyId, IPAddress? ClientIp);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.IssuerNotTrusted,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: issuer {Issuer} is not trusted")]
	private partial void LogIssuerNotTrusted(string Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedStrict,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint}, got {Audiences}")]
	private partial void LogAudienceFailedStrict(Uri TokenEndpoint, string Audiences);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.AudienceFailedPermissive,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: audience validation failed. Expected {TokenEndpoint} or {ApplicationUri}, got {Audiences}")]
	private partial void LogAudienceFailedPermissive(Uri TokenEndpoint, string ApplicationUri, string Audiences);
}
