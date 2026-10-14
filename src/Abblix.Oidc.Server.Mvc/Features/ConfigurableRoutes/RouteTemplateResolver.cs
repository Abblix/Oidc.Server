// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Resolves a route template the way version 2.4 did: a token such as <c>[route:token?[route:base?~/connect]/token]</c>
/// is replaced by the value the configuration section holds under its name, or by its fallback where the section is
/// silent, until no token is left.
/// </summary>
/// <param name="prefix">The word that opens a token, <c>route</c> unless the host chose another.</param>
/// <param name="section">The configuration section whose keys name the tokens.</param>
internal sealed class RouteTemplateResolver(string prefix, IConfigurationSection section)
{
    private const string TokenGroup = "token";
    private const string FallbackGroup = "fallback";
    private const string DepthGroup = "depth";

    // Templates and their values are written by the host's developer and read once at startup, so the timeout is a
    // backstop against a hang, generous enough that a loaded machine compiling the pattern does not trip it.
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(10);

    // The fallback ends at the bracket closing its own token: brackets inside it pair up, so a nested token stays
    // part of it while "[route:ApiPrefix?v1]/[controller]" keeps "/[controller]" as the rest of the template
    private readonly Regex _token = new(
        $@"\[{Regex.Escape(prefix)}:(?<{TokenGroup}>\w+)(\?(?<{FallbackGroup}>(?>[^\[\]]+|\[(?<{DepthGroup}>)|\](?<-{DepthGroup}>))*(?({DepthGroup})(?!))))?\]",
        RegexOptions.None,
        MatchTimeout);

    /// <summary>The template written as a token, with the default the token falls back to.</summary>
    public string Token(string name, string fallback) => $"[{prefix}:{name}?{fallback}]";

    /// <summary>
    /// The template with every token replaced, and whether the section gave any token on the way.
    /// </summary>
    /// <exception cref="InvalidOperationException">A token refers back to itself, or has neither a value nor a
    /// fallback.</exception>
    public (string Template, bool Configured) Resolve(string template)
    {
        var configured = false;
        var resolvedTokens = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            var original = template;
            template = _token.Replace(original, match =>
            {
                var token = match.Groups[TokenGroup].Value;
                if (!resolvedTokens.Add(token))
                {
                    throw new InvalidOperationException(
                        $"The route token '{token}' refers back to itself in '{original}'.");
                }

                if (section[token] is { } value)
                {
                    configured = true;
                    return value;
                }

                var fallback = match.Groups[FallbackGroup];
                if (fallback.Success)
                    return fallback.Value;

                throw new InvalidOperationException(
                    $"The route token '{token}' has no value in {section.Path} and no fallback.");
            });

            if (string.Equals(original, template, StringComparison.Ordinal))
                return (template, configured);
        }
    }
}
