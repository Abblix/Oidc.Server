// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Wraps a custodian failure that waiting will not resolve: the identity lacks the permission, the key is gone
/// or disabled, the request was malformed. The library answers 500, which is what a condition that will not
/// clear on its own deserves, and never puts this exception's text in the response.
/// </summary>
/// <remarks>
/// This is the seam's default reading of a failure it cannot place. A custodian says "not now" by throwing
/// <see cref="KeyCustodianUnavailableException"/>; everything else arrives here, because a retry promised on a
/// guess is worse than one not offered. The type exists so the endpoints can recognise a custodian failure at
/// all: an exception that never passed through the seam is none of the library's business and keeps travelling
/// to whatever the host has around it.
/// </remarks>
public sealed class KeyCustodianFailedException : Exception
{
    /// <summary>
    /// Reports that the custodian refused <paramref name="operation"/> for a reason a later attempt will meet
    /// again.
    /// </summary>
    /// <param name="operation">What was being asked of the custodian, named for the log line.</param>
    /// <param name="innerException">The failure as the custodian's own client reported it.</param>
    public KeyCustodianFailedException(string operation, Exception innerException)
        : base($"The key custodian failed to {operation}.", innerException)
        => Operation = operation;

    /// <summary>What was being asked of the custodian when it failed.</summary>
    public string Operation { get; }
}
