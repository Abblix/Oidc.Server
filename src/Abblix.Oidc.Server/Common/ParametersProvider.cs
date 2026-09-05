// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Extracts parameters from an object by serializing it to a JSON element and enumerating its properties. Pure
/// System.Text.Json, framework-neutral - the single implementation both the MVC and Minimal API transports use.
/// </summary>
public class ParametersProvider : IParametersProvider
{
    /// <inheritdoc />
    public IEnumerable<(string name, string? value)> GetParameters(object obj)
        => JsonSerializer.SerializeToElement(obj).EnumerateObject()
            .Select(property => (property.Name, ToParameterValue(property.Value)))
            .ToArray();

    // A parameter value is a string on the wire, but a property may serialize to any JSON kind - for example
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
