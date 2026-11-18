// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json.Nodes;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The startup warnings about this deployment and the CAEP Interoperability Profile 1.0, one method
/// for each half of the surface - the configuration document and the Stream Management API.
/// </summary>
internal static partial class CaepProfileWarnings
{
    /// <summary>
    /// Says once, at startup, where this deployment falls outside the CAEP Interoperability Profile 1.0
    /// and the host looks unaware of it. Nothing here refuses the host: each of these is a working
    /// deployment, and each is a choice the host is entitled to make knowingly.
    /// <para>
    /// No count is given, because a count over a list that grows is the one thing in a comment guaranteed
    /// to rot. What each warning says, and how optional the member it names really is elsewhere, lives on
    /// that warning's own message.
    /// </para>
    /// </summary>
    /// <remarks>
    /// It does NOT announce every profile-rejected document, and one configuration is deliberately left
    /// silent: an EMPTY <see cref="SharedSignalsTransmitterOptions.AuthorizationSchemes"/> omits the
    /// member, which Section 2.3.7 rejects, and says nothing - because the host wrote that empty list on
    /// purpose and a warning it cannot act on is one it learns to ignore. A conformance run failing 2.3.7
    /// against a clean startup log is therefore possible, and this is the configuration that does it.
    /// </remarks>
    internal static void WarnIfTheDocumentIsOutsideTheCaepProfile(
        IServiceProvider services, SharedSignalsTransmitterOptions options)
    {
        var logger = LoggerOf(services);
        if (logger is null)
            return;

        if (options.JwksUri is null)
            LogNoJwksUriAdvertised(logger);

        // Only a host-supplied list can be short: the default IS the required entry. Asked positively -
        // does some scheme name OAuth 2.0 - so a list can carry anything else it likes without the check
        // needing to know what.
        if (options.AuthorizationSchemes is { Count: > 0 } schemes && !schemes.Any(IsOAuth))
            LogOAuthSchemeNotAdvertised(logger, schemes.Count);
    }

    /// <summary>
    /// The half of the profile check that is about the Stream Management API, run where that API is
    /// mapped.
    /// </summary>
    /// <remarks>
    /// Both statements below are about the management routes - the scope filter guards every one of
    /// them, reads and poll included, and the subjects mode decides what a stream created there covers.
    /// A host may have that surface without the document or the document without that surface: streams declared in configuration need
    /// the document so a receiver can find them and never map the management routes, while a deployment
    /// whose canonical address is answered by a gateway maps the routes with
    /// <see cref="SharedSignalsEndpointOptions.MapWellKnownConfiguration"/> off. Attached to the document,
    /// these warnings were wrong in both directions at once - noise for the first host, silence for the
    /// second - and the second is the one exposing stream creation.
    /// </remarks>
    internal static void WarnIfTheManagementApiIsOutsideTheCaepProfile(
        IServiceProvider services,
        SharedSignalsTransmitterOptions options,
        SharedSignalsEndpointOptions endpointOptions)
    {
        var logger = LoggerOf(services);
        if (logger is null)
            return;

        if (endpointOptions.GrantedScopesSelector is null)
            LogScopeCheckingDisabled(logger);

        if (options.DefaultSubjectsMode is StreamSubjectsMode.None)
            LogNoSubjectsIncludedByDefault(logger);
    }

    private static ILogger? LoggerOf(IServiceProvider services)
        => services.GetService<ILoggerFactory>()
            ?.CreateLogger(typeof(SharedSignalsEndpointRouteBuilderExtensions));

    private static bool IsOAuth(JsonObject scheme)
        => scheme.TryGetPropertyValue(TransmitterConfiguration.ParameterNames.SpecUrn, out var urn)
           && urn is JsonValue value
           && value.TryGetValue<string>(out var specUrn)
           && specUrn == TransmitterConfiguration.AuthorizationSchemeUrns.OAuth2;
}
