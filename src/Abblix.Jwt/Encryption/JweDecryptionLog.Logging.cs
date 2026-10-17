// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

partial class JweDecryptionLog
{
    [LoggerMessage(
        EventId = LogEvents.Jwt.NoDecryptionKey,
        Level = LogLevel.Warning,
        Message = "JWE decryption failed: no decryption key is available for the token (alg='{Algorithm}', "
                  + "enc='{EncryptionAlgorithm}', kid='{KeyId}'). A kid naming no key of this server usually means "
                  + "the sender encrypted to a key that was never published here or was retired.")]
    private partial void LogNoDecryptionKey(string Algorithm, string EncryptionAlgorithm, Sanitized KeyId);

    [LoggerMessage(
        EventId = LogEvents.Jwt.NoDecryptionKeyOpened,
        Level = LogLevel.Warning,
        Message = "JWE decryption failed: none of {KeyCount} candidate key(s) opened the token (alg='{Algorithm}', "
                  + "enc='{EncryptionAlgorithm}', kid='{KeyId}'). A token encrypted to another key and a token "
                  + "altered on the way look the same here.")]
    private partial void LogNoKeyOpened(string Algorithm, string EncryptionAlgorithm, Sanitized KeyId, int KeyCount);
}
