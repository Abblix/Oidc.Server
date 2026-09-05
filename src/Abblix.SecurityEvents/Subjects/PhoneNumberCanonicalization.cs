// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Subjects;

/// <summary>
/// Removes presentation characters from a telephone number so that two senders' spellings of one
/// number can be compared.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9493 Section 3.2.5 requires the wire value to be in E.164 form already, and E.164 defines a
/// number as a country code followed by a national number - digits only, with no separators. The
/// separators seen in practice (spaces, hyphens, parentheses, dots) are presentation, so removing
/// them recovers the number E.164 describes and cannot merge two different numbers.
/// </para>
/// <para>
/// Only those four named separators are removed. Every other character - a letter, an unexpected
/// symbol, a non-ASCII digit - survives, precisely because this method validates nothing: deleting
/// what it does not understand would fold two genuinely distinct values into one, and a comparison
/// utility that can say "equal" about different identifiers is worse than one that says "not
/// equal" about equal spellings.
/// </para>
/// <para>
/// What this deliberately does NOT do is repair a number that is not in E.164 form. Reading a
/// leading "00" as the "+" prefix, or supplying a country code from context, are national dialling
/// conventions rather than anything E.164 or RFC 9493 states; a library that guessed at them would
/// occasionally guess wrong and produce a valid-looking number belonging to somebody else. An
/// application that knows the dialling plan its senders use is the right place for that.
/// </para>
/// </remarks>
public static class PhoneNumberCanonicalization
{
    /// <summary>
    /// Returns the number with the presentation separators - spaces, hyphens, parentheses and
    /// dots - removed, and every other character kept.
    /// </summary>
    /// <param name="phoneNumber">
    /// The number to fold. May be any string; nothing is validated, and a value that was not in
    /// E.164 form going in is not in E.164 form coming out.</param>
    /// <returns>The number without its presentation separators.</returns>
    public static string ToComparableForm(string phoneNumber)
    {
        ArgumentNullException.ThrowIfNull(phoneNumber);

        return string.Concat(phoneNumber.Where(character => character is not (' ' or '-' or '(' or ')' or '.')));
    }
}
