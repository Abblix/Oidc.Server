// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
