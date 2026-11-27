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

partial class TlsClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.ClientNotFound,
        Level = LogLevel.Debug,
        Message = "mTLS auth failed: unknown client_id {ClientId}")]
    private partial void LogClientNotFound(Sanitized ClientId);

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

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.OutsideValidityPeriod,
        Level = LogLevel.Warning,
        Message = "mTLS auth failed: the certificate presented for client_id {ClientId} is outside its validity period, {NotBefore} to {NotAfter}")]
    private partial void LogOutsideValidityPeriod(string ClientId, DateTimeOffset NotBefore, DateTimeOffset NotAfter);

    [LoggerMessage(
        EventId = LogEvents.ClientAuth.TlsClientAuthenticator.UnsupportedKeyType,
        Level = LogLevel.Warning,
        Message = "mTLS auth failed: the certificate presented for client_id {ClientId} carries a key of a type no JWK of a client is compared with")]
    private partial void LogUnsupportedKeyType(string ClientId);
}
