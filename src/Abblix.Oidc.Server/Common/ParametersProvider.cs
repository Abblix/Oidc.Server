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

using System.Text.Json;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Extracts parameters from an object by serializing it to a JSON element and enumerating its properties. Pure
/// System.Text.Json, framework-neutral — the single implementation both the MVC and Minimal API transports use.
/// </summary>
public class ParametersProvider : IParametersProvider
{
    /// <inheritdoc />
    public IEnumerable<(string name, string? value)> GetParameters(object obj)
        => JsonSerializer.SerializeToElement(obj).EnumerateObject()
            .Select(property => (property.Name, ToParameterValue(property.Value)))
            .ToArray();

    // A parameter value is a string on the wire, but a property may serialize to any JSON kind — for example
    // expires_in serializes as a number. JsonElement.GetString() only accepts String and Null and throws on every
    // other kind, so non-string values render through their raw JSON text instead (a number as its digits, a boolean
    // as true/false). JSON null maps to a null value that downstream query/fragment/form encoders drop.
    private static string? ToParameterValue(JsonElement value)
        => value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Null => null,
            _ => value.GetRawText(),
        };
}
