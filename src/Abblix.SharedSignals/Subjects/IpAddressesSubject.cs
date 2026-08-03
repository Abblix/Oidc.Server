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

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Subjects;

/// <summary>
/// Identifies a subject by the IP addresses the transmitter observed for it
/// (SSF 1.0 Section 3.5.3), each in the RFC 4001 textual representation.
/// </summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class IpAddressesSubject : SubjectIdentifier
{
    /// <summary>
    /// Creates an IP Addresses Subject Identifier.
    /// </summary>
    /// <param name="ipAddresses">
    /// The observed IP addresses. REQUIRED; every entry must be a non-empty string. The
    /// specification bounds neither the count nor the syntax of an entry, so neither is
    /// enforced here.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="ipAddresses"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="ipAddresses"/> holds a null or empty entry.</exception>
    [JsonConstructor]
    public IpAddressesSubject(IReadOnlyList<string> ipAddresses)
        : base(SsfSubjectFormats.IpAddresses)
    {
        ArgumentNullException.ThrowIfNull(ipAddresses);

        for (var i = 0; i < ipAddresses.Count; i++)
        {
            if (string.IsNullOrEmpty(ipAddresses[i]))
            {
                throw new ArgumentException(
                    $"The '{SsfSubjectMemberNames.IpAddresses}' member holds a null or empty entry at "
                    + $"index {i}; every entry must be the string representation of an IP address "
                    + "(SSF 1.0 Section 3.5.3).",
                    nameof(ipAddresses));
            }
        }

        // A copy, not the caller's list, so what was validated is what will be serialized.
        IpAddresses = Array.AsReadOnly(ipAddresses.ToArray());
    }

    /// <summary>
    /// Creates an IP Addresses Subject Identifier from the addresses given.
    /// </summary>
    /// <param name="ipAddresses">
    /// The observed IP addresses, under the same conditions as the primary constructor.</param>
    public IpAddressesSubject(params string[] ipAddresses)
        : this((IReadOnlyList<string>)ipAddresses)
    {
    }

    /// <summary>
    /// The IP addresses of the subject as observed by the transmitter
    /// (SSF 1.0 Section 3.5.3).
    /// </summary>
    [JsonPropertyName(SsfSubjectMemberNames.IpAddresses)]
    public IReadOnlyList<string> IpAddresses { get; }
}
