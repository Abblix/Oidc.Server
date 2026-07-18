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
    [LoggerMessage(
        EventId = LogEvents.KeyVaultClient.UnwrapRejected,
        Level = LogLevel.Warning,
        Message = "Key Vault rejected an unwrap for key '{KeyId}': the ciphertext is a wrong or tampered key, or " +
                  "the version that wrapped it is disabled. No key material is logged.")]
    private partial void LogUnwrapRejected(string keyId);
}
