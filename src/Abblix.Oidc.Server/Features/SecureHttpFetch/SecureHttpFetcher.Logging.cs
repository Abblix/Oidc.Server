// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SecureHttpFetcher
{
    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.ResponseTooLarge,
        Level = LogLevel.Warning,
        Message = "Response from {Uri} exceeds maximum allowed size. Content-Length: {ContentLength} bytes, Max: {MaxSize} bytes")]
    private partial void LogResponseTooLarge(Sanitized Uri, long ContentLength, long MaxSize);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.UnexpectedContentType,
        Level = LogLevel.Warning,
        Message = "Response from {Uri} has unexpected Content-Type: {ContentType}, expected application/json")]
    private partial void LogUnexpectedContentType(Sanitized Uri, string ContentType);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.Timeout,
        Level = LogLevel.Warning,
        Message = "Timeout while fetching content from {Uri}")]
    private partial void LogTimeout(Exception ex, Sanitized Uri);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.SsrfProtectionBlocked,
        Level = LogLevel.Warning,
        Message = "SSRF protection blocked request to {Uri}")]
    private partial void LogSsrfProtectionBlocked(Exception ex, Sanitized Uri);

    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureHttpFetcher.FetchFailed,
        Level = LogLevel.Warning,
        Message = "Unable to fetch content from {Uri}")]
    private partial void LogFetchFailed(Exception ex, Sanitized Uri);
}
