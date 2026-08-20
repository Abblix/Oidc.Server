// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SecureHttpFetcherExtensions
{
	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.FetchingJwks,
		Level = LogLevel.Debug,
		Message = "Fetching JWKS for {EntityType} {EntityId} from {JwksUri}")]
	private static partial void LogFetchingJwks(ILogger logger, string EntityType, string EntityId, Uri JwksUri);

	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.JwksEmpty,
		Level = LogLevel.Warning,
		Message = "JWKS for {EntityType} {EntityId} from {JwksUri} is empty or invalid")]
	private static partial void LogJwksEmpty(ILogger logger, string EntityType, string EntityId, Uri JwksUri);

	[LoggerMessage(
		EventId = LogEvents.HttpFetch.SecureHttpFetcherExtensions.JwksFetchFailed,
		Level = LogLevel.Error,
		Message = "Failed to fetch JWKS for {EntityType} {EntityId} from {JwksUri}: {Error}")]
	private static partial void LogJwksFetchFailed(ILogger logger, string EntityType, string EntityId, Uri JwksUri, string? Error);
}
