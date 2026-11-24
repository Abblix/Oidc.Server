// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Compares a certificate's subject with the distinguished name a client registered by the distinguishedNameMatch
/// rule of RFC 4517 section 4.2.15, which RFC 8705 section 2.1 names as "a predictable treatment of DN values".
/// </summary>
/// <remarks>
/// The rule is TRUE "if and only if the attribute value and the assertion value have the same number of relative
/// distinguished names and corresponding relative distinguished names (by position) are the same", an RDN being the
/// same when it holds the same attribute types with equal values, "The order of the AVAs is not significant". Both
/// names are compared in their encoded form, so the registered string's RFC 4514 order (most specific first) is
/// already the encoding's reverse once parsed. A string value is compared as RFC 5280 section 7.1 has it, after the
/// LDAP StringPrep of RFC 4518 under caseIgnoreMatch: whatever string type encodes it (a certificate writes UTF8String
/// where a parsed name writes PrintableString), compatibility-normalized, case-folded and with insignificant spaces
/// collapsed. A value of any other type is compared by its encoding.
/// </remarks>
internal static class DistinguishedNameMatch
{
    /// <summary>
    /// Whether <paramref name="presented"/> and <paramref name="required"/> name the same subject.
    /// </summary>
    /// <param name="presented">The subject of the certificate presented.</param>
    /// <param name="required">The distinguished name the client registered.</param>
    public static bool Matches(X500DistinguishedName presented, X500DistinguishedName required)
    {
        if (!TryRead(presented, out var presentedNames) || !TryRead(required, out var requiredNames))
            return false;

        return presentedNames.Count == requiredNames.Count &&
               presentedNames.Zip(requiredNames).All(pair => pair.First.SetEquals(pair.Second));
    }

    /// <summary>
    /// The relative distinguished names of <paramref name="name"/> in encoded order, each the set of its attribute
    /// type and prepared value pairs; false when the name does not decode, which matches nothing.
    /// </summary>
    private static bool TryRead(X500DistinguishedName name, out List<HashSet<string>> names)
    {
        names = [];
        try
        {
            var sequence = new AsnReader(name.RawData, AsnEncodingRules.DER).ReadSequence();
            while (sequence.HasData)
            {
                var set = sequence.ReadSetOf();
                var attributes = new HashSet<string>(StringComparer.Ordinal);
                while (set.HasData)
                {
                    var attribute = set.ReadSequence();
                    attributes.Add($"{attribute.ReadObjectIdentifier()}={ReadValue(attribute)}");
                }

                names.Add(attributes);
            }

            return true;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    /// <summary>
    /// The attribute value as compared: a string prepared by RFC 4518, any other value by its encoding, each marked
    /// so that one never equals the other.
    /// </summary>
    private static string ReadValue(AsnReader attribute)
    {
        var tag = attribute.PeekTag();
        if (tag.TagClass == TagClass.Universal && IsReadableString((UniversalTagNumber)tag.TagValue))
            return "s:" + Prepare(attribute.ReadCharacterString((UniversalTagNumber)tag.TagValue));

        return "x:" + Convert.ToHexString(attribute.ReadEncodedValue().Span);
    }

    /// <summary>
    /// The string types of a DirectoryString and the other naming attributes that .NET decodes; TeletexString is
    /// left to its encoding, since its character set is not one decoder can read.
    /// </summary>
    private static bool IsReadableString(UniversalTagNumber tag) => tag switch
    {
        UniversalTagNumber.UTF8String or
        UniversalTagNumber.PrintableString or
        UniversalTagNumber.IA5String or
        UniversalTagNumber.VisibleString or
        UniversalTagNumber.NumericString or
        UniversalTagNumber.BMPString => true,
        _ => false,
    };

    /// <summary>
    /// RFC 4518 string preparation as RFC 5280 section 7.1 clarifies it for caseIgnoreMatch: normalized (step 3, NFKC),
    /// case-folded (step 2, applied here after normalization, which a case fold to lower case commutes with), and with
    /// insignificant space handling (section 2.6.1): no leading or trailing space, and each inner run of spaces taken
    /// as one.
    /// </summary>
    private static string Prepare(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormKC).ToLowerInvariant();
        var builder = new StringBuilder(normalized.Length);
        foreach (var part in normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (builder.Length > 0)
                builder.Append(' ');
            builder.Append(part);
        }

        return builder.ToString();
    }
}
