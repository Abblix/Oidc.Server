// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Fails at startup on <see cref="OidcOptions.ClientIdMetadataDocuments"/> settings under which a client's metadata
/// document could never be accepted, or would be accepted from more URLs than the setting appears to name.
/// </summary>
/// <remarks>
/// Each of these is otherwise found on the first authorization request of a client nobody configured, as a refusal
/// that names the client rather than the setting.
/// </remarks>
public sealed class ClientIdMetadataDocumentOptionsValidator : IValidateOptions<OidcOptions>
{
    private const string Section = nameof(OidcOptions.ClientIdMetadataDocuments);

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var settings = options.ClientIdMetadataDocuments;
        if (!settings.Enabled)
            return ValidateOptionsResult.Success;

        if (settings.MaxDocumentSize <= 0)
        {
            return ValidateOptionsResult.Fail(
                $"{Section}.{nameof(settings.MaxDocumentSize)} is {settings.MaxDocumentSize}, so no client's " +
                "metadata document could be read. Set it to the number of bytes a document may take, 5 KB by default.");
        }

        if (settings.MinimumCacheDuration < TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{Section}.{nameof(settings.MinimumCacheDuration)} is {settings.MinimumCacheDuration}, which is no " +
                "span of time to hold a document for. Set it to zero or more.");
        }

        if (settings.MaximumCacheDuration < settings.MinimumCacheDuration)
        {
            return ValidateOptionsResult.Fail(
                $"{Section}.{nameof(settings.MaximumCacheDuration)} ({settings.MaximumCacheDuration}) is shorter than " +
                $"{nameof(settings.MinimumCacheDuration)} ({settings.MinimumCacheDuration}), so the longest a document " +
                "is held would be shorter than the shortest.");
        }

        return settings.AllowedClientIdPrefixes is { } prefixes
            ? WhyPrefixesRefused(prefixes)
            : ValidateOptionsResult.Success;
    }

    private static ValidateOptionsResult WhyPrefixesRefused(string[] prefixes)
    {
        const string member = $"{Section}.{nameof(ClientIdMetadataDocumentOptions.AllowedClientIdPrefixes)}";

        if (prefixes.Length == 0)
        {
            return ValidateOptionsResult.Fail(
                $"{member} is empty, so no client's metadata document would ever be fetched. Name the prefixes to " +
                "accept, or leave it unset to accept any client identifier URL.");
        }

        foreach (var prefix in prefixes)
        {
            if (WhyRefused(prefix) is { } reason)
                return ValidateOptionsResult.Fail($"{member} holds '{prefix}', which {reason}.");
        }

        return ValidateOptionsResult.Success;
    }

    private static string? WhyRefused(string? prefix)
    {
        if (!Uri.TryCreate(prefix, UriKind.Absolute, out var uri))
            return "is not an absolute URL";

        if (uri.Scheme != Uri.UriSchemeHttps)
            return "does not use the https scheme every client identifier URL uses";

        // Each would compare against client identifiers that never carry it, or admit more than the entry reads as
        if (uri.UserInfo.Length > 0 || prefix.Contains('?') || prefix.Contains('#'))
            return "carries user information, a query or a fragment";

        // Without the slash, https://example.com would admit https://example.com.attacker.test/client
        if (!prefix.EndsWith('/'))
            return "does not end with a slash, so it would admit hosts and paths it only begins";

        // A client identifier is accepted only in the form it is requested in, so a prefix in another spelling - an
        // uppercase host, a default port - would match none
        if (!string.Equals(uri.AbsoluteUri, prefix, StringComparison.Ordinal))
            return $"is not written in the form a client identifier is requested in ({uri.AbsoluteUri})";

        return null;
    }
}
