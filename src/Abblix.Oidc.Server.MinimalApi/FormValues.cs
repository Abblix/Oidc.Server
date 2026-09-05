// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Helpers that turn raw request values into the shapes the OIDC request models expect. They reproduce, in plain code,
/// what the MVC custom model binders do (space-separated lists, seconds to <see cref="TimeSpan"/>, JSON in a single
/// field, culture lists), so each model's <c>BindAsync</c> can call them. The core overloads take
/// <see cref="StringValues"/> so they work equally for form fields and query parameters; the <see cref="IFormCollection"/>
/// overloads are conveniences for the form-only models.
/// </summary>
internal static class FormValues
{
    /// <summary>A single value, or null when absent or empty.</summary>
    /// <remarks>
    /// RFC 6749 section 3.1 puts this in the request direction as a requirement rather than a preference:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request." A query
    /// string carries no way to say "present and empty" that differs from saying nothing, so binding
    /// "state=" as an empty string invented a value the client never sent - and state is returned only if
    /// it was present in the request, so the client got back one it never issued.
    /// </remarks>
    public static string? Value(StringValues values)
        => values is { Count: > 0 } && values.ToString() is { Length: > 0 } value ? value : null;

    /// <summary>A single value read from the form by name.</summary>
    public static string? Value(IFormCollection form, string name) => Value(Get(form, name));

    /// <summary>A repeated field as an array (RFC 8707 <c>resource</c>/<c>audience</c>), or null.</summary>
    /// <remarks>
    /// Valueless entries are dropped for the reason given on <see cref="Value(StringValues)"/>, and a field
    /// whose every entry was valueless is the field not being there. Repeating the reading here rather than
    /// leaving it to the callers keeps one answer to "what does present-but-empty mean" for the whole
    /// binding surface.
    /// </remarks>
    public static string[]? Strings(StringValues values)
        => values is { Count: > 0 }
           && values.OfType<string>().Where(value => value.Length > 0).ToArray() is { Length: > 0 } strings
            ? strings
            : null;

    /// <summary>A repeated form field read by name as an array, or null.</summary>
    public static string[]? Strings(IFormCollection form, string name) => Strings(Get(form, name));

    /// <summary>A single space-separated value (e.g. <c>scope</c>) as an array; empty when absent.</summary>
    public static string[] SpaceSeparated(StringValues values)
    {
        var value = Value(values);
        return string.IsNullOrEmpty(value)
            ? []
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>A single space-separated form value read by name as an array; empty when absent.</summary>
    public static string[] SpaceSeparated(IFormCollection form, string name) => SpaceSeparated(Get(form, name));

    /// <summary>A single space-separated value as an array, or null when absent (for optional list fields).</summary>
    public static string[]? SpaceSeparatedOrNull(StringValues values)
    {
        var value = Value(values);
        return string.IsNullOrEmpty(value)
            ? null
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>A single value parsed as a URI, or null when absent or unparseable.</summary>
    public static Uri? ParseUri(StringValues values)
    {
        var value = Value(values);
        return value is not null && Uri.TryCreate(value, UriKind.RelativeOrAbsolute, out var uri) ? uri : null;
    }

    /// <summary>A single form value read by name as a URI, or null.</summary>
    public static Uri? ParseUri(IFormCollection form, string name) => ParseUri(Get(form, name));

    /// <summary>A repeated field as an array of URIs (RFC 8707 <c>resource</c>), or null.</summary>
    public static Uri[]? ParseUris(StringValues values)
    {
        if (values.Count == 0)
            return null;

        var uris = new List<Uri>(values.Count);
        foreach (var value in values)
        {
            if (value is not null && Uri.TryCreate(value, UriKind.RelativeOrAbsolute, out var uri))
                uris.Add(uri);
        }

        return uris.ToArray();
    }

    /// <summary>A repeated form field read by name as an array of URIs, or null.</summary>
    public static Uri[]? ParseUris(IFormCollection form, string name) => ParseUris(Get(form, name));

    /// <summary>A single integer-seconds value as a <see cref="TimeSpan"/> (e.g. <c>max_age</c>), or null.</summary>
    public static TimeSpan? Seconds(StringValues values)
    {
        var value = Value(values);
        if (value is null || !long.TryParse(value, out var seconds))
            return null;

        // A syntactically valid but out-of-range seconds value overflows TimeSpan. Shape it as a 400 rather than
        // letting the throw escape BindAsync as a 500 (mirrors the MVC model binder's catch-into-ModelState).
        try
        {
            return TimeSpan.FromSeconds(seconds);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>A single space-separated locale list (e.g. <c>ui_locales</c>) as cultures, or null.</summary>
    public static CultureInfo[]? Cultures(StringValues values)
    {
        var value = Value(values);
        if (string.IsNullOrEmpty(value))
            return null;

        // An invalid BCP-47 tag throws; shape it as a 400 instead of a 500 escaping BindAsync.
        try
        {
            return value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(culture => new CultureInfo(culture))
                .ToArray();
        }
        catch (CultureNotFoundException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>Deserializes a single field's JSON value (e.g. <c>claims</c>, <c>authorization_details</c>), or null.</summary>
    public static T? Json<T>(StringValues values)
    {
        var value = Value(values);
        if (string.IsNullOrEmpty(value))
            return default;

        // Malformed JSON in a single field must be a 400, not a 500 from an uncaught JsonException in BindAsync.
        try
        {
            return JsonSerializer.Deserialize<T>(value);
        }
        catch (JsonException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>A single boolean value (e.g. <c>confirmed</c>), or null when absent or unparseable.</summary>
    public static bool? Bool(StringValues values)
    {
        var value = Value(values);
        return value is not null && bool.TryParse(value, out var result) ? result : null;
    }

    /// <summary>A single request header value, or null when absent.</summary>
    public static string? Header(HttpRequest request, string name)
        => request.Headers.TryGetValue(name, out var values) && values.Count > 0 ? values.ToString() : null;

    private static StringValues Get(IFormCollection form, string name)
        => form.TryGetValue(name, out var values) ? values : StringValues.Empty;

    // A binding-time BadHttpRequestException with a 400 status is rendered by ASP.NET Core as a 400 response, the
    // Minimal API counterpart of the MVC binder shaping a malformed value into invalid_request.
    private static BadHttpRequestException MalformedValue()
        => new("The request contains a malformed parameter value.", StatusCodes.Status400BadRequest);
}
