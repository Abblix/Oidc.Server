// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class TlsClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.ClientNotFound,
        Level = LogLevel.Debug,
        Message = "mTLS auth failed: unknown client_id {ClientId}")]
    private partial void LogClientNotFound(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.NoMatchingPublicKey,
        Level = LogLevel.Warning,
        Message = "mTLS auth failed: no matching JWKS public key found for client_id {ClientId}")]
    private partial void LogNoMatchingPublicKey(string ClientId);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.Authenticated,
        Level = LogLevel.Information,
        Message = "mTLS client authenticated via self-signed certificate for client_id {ClientId}")]
    private partial void LogAuthenticated(string ClientId);
}
