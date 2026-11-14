// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt;

partial class KeyedSignatureCheck
{
    [LoggerMessage(
        EventId = LogEvents.Jwt.UnimportableKey,
        Level = LogLevel.Warning,
        Message = "A candidate key for alg='{Algorithm}' (kid='{KeyId}') could not be imported, so no signature "
                  + "verifies under it: {Reason}.")]
    private partial void LogUnimportableKey(Sanitized KeyId, Sanitized Algorithm, Sanitized Reason);
}
