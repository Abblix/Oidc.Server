// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a physical address, providing various components typically used in postal addresses.
/// </summary>
public record Address
{
    /// <summary>
    /// Wire-level member names of the <c>address</c> claim (OIDC Core section 5.1.1).
    /// </summary>
    private static class Parameters
    {
        /// <summary>The <c>formatted</c> member carrying the full mailing address.</summary>
        public const string Formatted = "formatted";

        /// <summary>The <c>street_address</c> member carrying the full street address component.</summary>
        public const string StreetAddress = "street_address";

        /// <summary>The <c>locality</c> member carrying the city or locality component.</summary>
        public const string Locality = "locality";

        /// <summary>The <c>region</c> member carrying the state, province, prefecture, or region component.
        /// </summary>
        public const string Region = "region";

        /// <summary>The <c>postal_code</c> member carrying the zip or postal code component.</summary>
        public const string PostalCode = "postal_code";

        /// <summary>The <c>country</c> member carrying the country name component.</summary>
        public const string Country = "country";
    }

    /// <summary>
    /// Full mailing address, formatted for display or use on a mailing label.
    /// This field MAY contain multiple lines, separated by newlines.
    /// Newlines can be represented either as a carriage return/line feed pair ("\r\n")
    /// or as a single line feed character ("\n").
    /// </summary>
    [JsonPropertyName(Parameters.Formatted)]
    [JsonPropertyOrder(1)]
    public string? Formatted { get; set; }

    /// <summary>
    /// Full street address component, which MAY include house number, street name, Post Office Box,
    /// and multi-line extended street address information.
    /// This field MAY contain multiple lines, separated by newlines.
    /// Newlines can be represented either as a carriage return/line feed pair ("\r\n")
    /// or as a single line feed character ("\n").
    /// </summary>
    [JsonPropertyName(Parameters.StreetAddress)]
    [JsonPropertyOrder(2)]
    public string? StreetAddress { get; set; }

    /// <summary>
    /// City or locality component.
    /// </summary>
    [JsonPropertyName(Parameters.Locality)]
    [JsonPropertyOrder(3)]
    public string? Locality { get; set; }

    /// <summary>
    /// State, province, prefecture, or region component.
    /// </summary>
    [JsonPropertyName(Parameters.Region)]
    [JsonPropertyOrder(4)]
    public string? Region { get; set; }

    /// <summary>
    /// Zip code or postal code component.
    /// </summary>
    [JsonPropertyName(Parameters.PostalCode)]
    [JsonPropertyOrder(5)]
    public string? PostalCode { get; set; }

    /// <summary>
    /// Country name component.
    /// </summary>
    [JsonPropertyName(Parameters.Country)]
    [JsonPropertyOrder(6)]
    public string? Country { get; set; }
}
