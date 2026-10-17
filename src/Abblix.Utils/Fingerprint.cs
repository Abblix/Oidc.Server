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
/// back to anybody who tries them all. The key is drawn once per process, so a fingerprint matches only the records
/// one process wrote; the price is that two nodes write different fingerprints for the same code.
/// </remarks>
public readonly record struct Fingerprint
{
    // Hexadecimal characters of the hash kept: enough that two codes alive at once do not share one.
    private const int Length = 16;

    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(SHA256.HashSizeInBytes);

    private readonly string? _value;

    private Fingerprint(string? value)
    {
        _value = value;
    }

    /// <summary>
    /// Wraps <paramref name="value"/>, which is never written: only its fingerprint is.
    /// </summary>
    public static Fingerprint Of(string? value) => new(value);

    /// <summary>
    /// The fingerprint, or "(null)" for an absent value, as the logging library writes a null argument.
    /// </summary>
    public override string ToString()
    {
        if (_value is null)
            return Sanitized.NullText;

        var hash = HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes(_value));
        return Convert.ToHexStringLower(hash)[..Length];
    }
}
