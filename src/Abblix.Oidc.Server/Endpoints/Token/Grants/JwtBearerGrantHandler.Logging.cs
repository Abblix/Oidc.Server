// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Utils;
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
	private partial void LogValidationFailed(string ClientId, JwtError ErrorCode, Sanitized ErrorDescription);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingSubject,
		Level = LogLevel.Warning,
		Message = "JWT assertion missing required 'sub' claim for client {ClientId}")]
	private partial void LogMissingSubject(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.MissingJti,
		Level = LogLevel.Warning,
		Message = "JWT assertion missing required 'jti' claim for client {ClientId}, issuer {Issuer}")]
	private partial void LogMissingJti(string ClientId, Sanitized Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.ReplayDetected,
		Level = LogLevel.Warning,
		Message = "SECURITY: JWT replay attack detected - JTI: {JwtId}, Client: {ClientId}, Issuer: {Issuer}, KeyId: {KeyId}, IP: {ClientIp}")]
	private partial void LogReplayDetected(Sanitized JwtId, string ClientId, Sanitized Issuer, Sanitized KeyId, IPAddress? ClientIp);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.ScopesNotAllowed,
		Level = LogLevel.Warning,
		Message = "JWT Bearer grant rejected: scopes {InvalidScopes} not allowed for issuer {Issuer}")]
	private partial void LogScopesNotAllowed(Sanitized InvalidScopes, Sanitized Issuer);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.GrantSucceeded,
		Level = LogLevel.Information,
		Message = "AUDIT: JWT Bearer grant SUCCESS - Client: {ClientId}, Subject: {Subject}, Issuer: {Issuer}, JTI: {JwtId}, KeyId: {KeyId}, IP: {ClientIp}")]
	private partial void LogGrantSucceeded(string ClientId, Sanitized Subject, Sanitized Issuer, Sanitized JwtId, Sanitized KeyId, IPAddress? ClientIp);

	[LoggerMessage(
		EventId = LogEvents.Endpoints.JwtBearer.IssuerNotTrusted,
		Level = LogLevel.Warning,
		Message = "JWT Bearer assertion rejected: issuer {Issuer} is not trusted")]
	private partial void LogIssuerNotTrusted(Sanitized Issuer);
}
