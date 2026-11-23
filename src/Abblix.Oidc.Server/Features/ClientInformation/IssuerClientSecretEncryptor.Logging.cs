// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

internal sealed partial class IssuerClientSecretEncryptor
{
    [LoggerMessage(
        EventId = LogEvents.ClientInformation.ClientSecretEncryption.SecretNotDecrypted,
        Level = LogLevel.Warning,
        Message = "The client secret of the client {ClientId} at the tenant '{TenantId}' does not decrypt: the tenant " +
                  "has no client secret encryption key, or not the one it was encrypted with, so the client's " +
                  "registration is read without it")]
    private partial void LogSecretNotDecrypted(Sanitized ClientId, string TenantId);
}
