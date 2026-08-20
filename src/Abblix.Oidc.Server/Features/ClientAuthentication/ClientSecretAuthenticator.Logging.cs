// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class ClientSecretAuthenticator
{
	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.ClientNotFound,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: client information for id {ClientId} is missing")]
	private partial void LogClientNotFound(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.WrongAuthMethod,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: client {ClientId} uses another authentication method")]
	private partial void LogWrongAuthMethod(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.NoSecretsConfigured,
		Level = LogLevel.Debug,
		Message = "Client authentication failed: no secrets are configured for client {ClientId}")]
	private partial void LogNoSecretsConfigured(Sanitized ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.NoMatchingSecret,
		Level = LogLevel.Warning,
		Message = "Client authentication failed: No matching secret found for client {ClientId}")]
	private partial void LogNoMatchingSecret(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.SecretExpired,
		Level = LogLevel.Warning,
		Message = "Client authentication failed: Secret has expired for client {ClientId}")]
	private partial void LogSecretExpired(string ClientId);

	[LoggerMessage(
		EventId = LogEvents.ClientAuth.ClientSecretAuthenticator.Authenticated,
		Level = LogLevel.Information,
		Message = "Client authenticated successfully with client ID {ClientId}")]
	private partial void LogAuthenticated(string ClientId);
}
