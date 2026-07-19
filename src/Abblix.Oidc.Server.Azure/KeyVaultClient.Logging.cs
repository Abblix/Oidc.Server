// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Azure;

partial class KeyVaultClient
{
    // Static with an explicit logger parameter, unlike the instance log methods elsewhere: this type has two
    // constructors and so holds the logger in a field rather than a primary-constructor parameter, and passing
    // that field here is the one place the field is read in source, which an instance method would leave only to
    // generated code.
    [LoggerMessage(
        EventId = LogEvents.KeyVaultClient.UnwrapRejected,
        Level = LogLevel.Warning,
        Message = "Key Vault rejected an unwrap for key '{KeyId}': the ciphertext is a wrong or tampered key, or " +
                  "the version that wrapped it is disabled. No key material is logged.")]
    private static partial void LogUnwrapRejected(ILogger logger, string keyId);
}
