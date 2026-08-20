// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// The one email transformation RFC 9493 settles, offered for comparing addresses rather than for
/// storing them.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9493 Section 3.2.2.1 records the situation plainly: providers differ over whether the local
/// part is case-sensitive and whether dots in it are significant, email canonicalisation is not
/// standardised, and a receiver has no way to learn the sending provider's algorithm. It therefore
/// puts the choice on the receiver, which is why nothing here runs automatically.
/// </para>
/// <para>
/// What the specification does settle is the domain: it is case-insensitive per RFC 1034, always,
/// for every provider. <see cref="ToComparableForm"/> folds that and nothing else, so applying it
/// can never merge two addresses that are genuinely distinct. Anything beyond it - folding the
/// local part, dropping dots, stripping a "+" qualifier - is a guess about one provider's rules
/// and belongs in the application that knows which provider it is talking to.
/// </para>
/// </remarks>
public static class EmailCanonicalization
{
    /// <summary>
    /// Returns the address with its domain lowercased, leaving the local part untouched.
    /// </summary>
    /// <param name="email">The address to fold. May be any string; nothing is validated here.</param>
    /// <returns>
    /// The address with the part after the last "@" lowercased using the invariant culture. When
    /// the value holds no "@", it is returned unchanged - deciding what a domain-less string means
    /// is the caller's business, not this method's.</returns>
    /// <remarks>
    /// The split is on the LAST "@" because RFC 5322 permits a quoted local part to contain one,
    /// as in <c>"odd@name"@example.com</c>; splitting on the first would lowercase part of the
    /// local part and change the address.
    /// </remarks>
    public static string ToComparableForm(string email)
    {
        ArgumentNullException.ThrowIfNull(email);

        var at = email.LastIndexOf('@');
        if (at < 0)
            return email;

        var domain = email[(at + 1)..];
        return email[..(at + 1)] + domain.ToLowerInvariant();
    }
}
