// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Nonces;

partial class RollingHmacNonceService
{
    [LoggerMessage(
        EventId = LogEvents.Tokens.RollingHmacNonceService.SecretGenerated,
        Level = LogLevel.Debug,
        Message = "Nonce-service secret generated for bucket {Bucket}")]
    private partial void LogSecretGenerated(long Bucket);

    [LoggerMessage(
        EventId = LogEvents.Tokens.RollingHmacNonceService.ValidationFailed,
        Level = LogLevel.Debug,
        Message = "Nonce-service validation failed: {Failure}")]
    private partial void LogValidationFailed(NonceValidationFailure Failure);
}
