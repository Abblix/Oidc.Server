// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text;

namespace Abblix.Utils;

/// <summary>
/// Stands in a log record for a value that is itself a credential - a device code, a user code - so records about
/// the same value can be told to belong together while the value cannot be read back out of them.
/// </summary>
/// <remarks>
/// A keyed hash rather than a plain one: a user code has few enough combinations that a plain hash would give it
/// back to anybody who tries them all. The key comes from whoever creates the fingerprint, so every process of one
/// deployment that holds the same key writes the same fingerprint for the same value.
/// <para>
/// A plain struct rather than a positional record, whose parameters would become public properties: a sink that
/// writes an object's properties would then write the credential itself.
/// </para>
/// </remarks>
/// <param name="key">The secret the fingerprint is computed under.</param>
/// <param name="value">The credential the record is about, never written itself.</param>
public readonly struct Fingerprint(byte[] key, string? value)
{
    // Hexadecimal characters of the hash kept: enough that two codes alive at once do not share one.
    private const int Length = 16;

    /// <summary>
    /// The fingerprint, or "(null)" for an absent value, as the logging library writes a null argument.
    /// </summary>
    public override string ToString()
    {
        if (value is null)
            return Sanitized.NullText;

        var hash = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash)[..Length];
    }
}
