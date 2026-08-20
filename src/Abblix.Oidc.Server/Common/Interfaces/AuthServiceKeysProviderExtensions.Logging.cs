// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Common.Interfaces;

partial class AuthServiceKeysProviderExtensions
{
    [LoggerMessage(
        EventId = LogEvents.Misc.AuthServiceKeysProvider.PrivateKeyStrippedFromPublishedSet,
        Level = LogLevel.Warning,
        Message = "A key handed to the JWKS publication set carried private key material and was stripped to " +
                  "its public half before publication (kid: {KeyId}). A key provider must publish only public " +
                  "halves; investigate the provider that produced this key.")]
    private static partial void LogPrivateKeyStrippedFromPublishedSet(ILogger logger, string? KeyId);
}
