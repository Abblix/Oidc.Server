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
    public static string? Value(StringValues values) => values is { Count: > 0 } ? values.ToString() : null;

    /// <summary>A single value read from the form by name.</summary>
    public static string? Value(IFormCollection form, string name) => Value(Get(form, name));

    /// <summary>A repeated field as an array (RFC 8707 <c>resource</c>/<c>audience</c>), or null.</summary>
    public static string[]? Strings(StringValues values) => values is { Count: > 0 } ? (string[]?)values : null;

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
