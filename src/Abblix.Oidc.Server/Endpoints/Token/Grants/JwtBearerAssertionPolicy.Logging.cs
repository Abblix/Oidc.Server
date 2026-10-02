// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

partial class JwtBearerAssertionPolicy
{
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
}
