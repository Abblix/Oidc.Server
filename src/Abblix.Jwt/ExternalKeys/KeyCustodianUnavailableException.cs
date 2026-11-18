// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Thrown by an <see cref="IKeyCustodian"/> when the custodian could not answer for a reason that a later attempt
/// may resolve on its own: it is sealed, unreachable, throttling, or failing internally. The library turns this
/// into a 503 carrying <c>Retry-After</c>, because that is a statement the caller can act on.
/// </summary>
/// <remarks>
/// The distinction this type carries is the one the library cannot make for itself. An endpoint sees an exception
/// and nothing more; only the custodian knows whether its backend said "not now" or "not you". So a custodian
/// throws this for the first case and anything else for the second, and the second answers 500 - the honest
/// status for a condition that will not clear on its own, such as a missing permission or a key that is gone.
/// Defaulting the other way would promise a retry that cannot help, so an unclassified failure is treated as
/// permanent.
/// <para>
/// This is not the way a DECRYPTION failure is reported. <see cref="IKeyCustodian.UnwrapKeyAsync"/> returns null
/// for a CEK it could not recover, which keeps a wrong key indistinguishable from bad padding; that mitigation
/// is about what an attacker can learn from a well-formed answer, and is unrelated to the custodian being
/// unable to answer at all.
/// </para>
/// </remarks>
public sealed class KeyCustodianUnavailableException : Exception
{
    /// <summary>
    /// Reports that the custodian is temporarily unable to perform <paramref name="operation"/>.
    /// </summary>
    /// <param name="operation">What was being asked of the custodian, named for a log line and nothing else:
    /// it never reaches a response body.</param>
    /// <param name="message">What the custodian said, for the log.</param>
    /// <param name="retryAfter">How long the custodian suggests waiting, when it says so. Null when it does
    /// not: the library then answers 503 without <c>Retry-After</c> rather than inventing an interval.</param>
    /// <param name="innerException">The failure as the custodian's own client reported it.</param>
    public KeyCustodianUnavailableException(
        string operation,
        string message,
        TimeSpan? retryAfter = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Operation = operation;
        RetryAfter = retryAfter;
    }

    /// <summary>What was being asked of the custodian when it declined.</summary>
    public string Operation { get; }

    /// <summary>
    /// How long to wait before trying again, when the custodian named an interval. Null means it did not, and
    /// the library says so by omitting the header rather than by guessing.
    /// </summary>
    public TimeSpan? RetryAfter { get; }
}
