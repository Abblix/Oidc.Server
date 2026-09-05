// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.Subjects;

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
        : base(SubjectFormats.IpAddresses)
    {
        ArgumentNullException.ThrowIfNull(ipAddresses);

        for (var i = 0; i < ipAddresses.Count; i++)
        {
            if (string.IsNullOrEmpty(ipAddresses[i]))
            {
                throw new ArgumentException(
                    $"The '{SubjectMemberNames.IpAddresses}' member holds a null or empty entry at "
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
    [JsonPropertyName(SubjectMemberNames.IpAddresses)]
    public IReadOnlyList<string> IpAddresses { get; }
}
