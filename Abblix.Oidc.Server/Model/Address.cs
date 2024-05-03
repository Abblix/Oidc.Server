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

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a physical address, providing various components typically used in postal addresses.
/// </summary>
public record Address
{
    private static class Parameters
    {
        public const string Formatted = "formatted";
        public const string StreetAddress = "street_address";
        public const string Locality = "locality";
        public const string Region = "region";
        public const string PostalCode = "postal_code";
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
