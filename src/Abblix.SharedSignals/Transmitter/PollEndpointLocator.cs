// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where this transmitter serves a stream's poll queue - the "endpoint_url value is supplied by the
/// Transmitter" of SSF 1.0 Section 8.1.1.1, and therefore the one thing a stream cannot be created with
/// poll delivery without.
/// </summary>
/// <remarks>
/// The address has two possible sources and they answer different questions.
/// <list type="bullet">
///   <item><see cref="TransmitterRoutes.ServePollAt"/> is the address the endpoint was mapped on, declared by whatever mapped
///   it. That is the only code that knows: the route and its prefix belong to the web framework adapter,
///   and a host may move either. A proxy that rewrites paths is covered here too, because what the
///   mapping declares is the ADVERTISED prefix rather than the internal one.</item>
///   <item><see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/> is the address a host names
///   itself, for a deployment the mapped one cannot describe - a separate delivery host, or a host that
///   maps no routes through this framework at all. It wins.</item>
/// </list>
/// <para>
/// Neither could be a default computed here. A guess assembled from the issuer alone would be right only
/// while the prefix is the untouched default and silently wrong afterwards - a transmitter minting and
/// STORING an address that answers 404, which a receiver meets long after the create it belongs to
/// succeeded.
/// </para>
/// <para>
/// A transmitter with neither source offers no poll delivery: the configuration document omits the
/// method and a create asking for it is refused, which is the honest answer when there is no address to
/// hand out.
/// </para>
/// </remarks>
/// <param name="options">The deployment's one-time decisions, holding the host's own address if it named
/// one.</param>
/// <param name="routes">Where the routes were mapped, declared once by the code that mapped them.</param>
/// <param name="identity">The transmitter whose streams this locates, whose address the mapped route is
/// reached under.</param>
public sealed class PollEndpointLocator(
    SharedSignalsTransmitterOptions options,
    TransmitterRoutes routes,
    ITransmitterIdentity identity)
{

    /// <summary>
    /// Whether this transmitter offers poll delivery at all - what "delivery_methods_supported"
    /// advertises (SSF 1.0 Section 7.1) and what a create naming poll is judged against.
    /// </summary>
    public bool IsOffered => options.PollEndpointFactory is not null || routes.Poll is not null;

    /// <summary>
    /// The poll endpoint of a stream, or null when there is none for it.
    /// </summary>
    /// <remarks>
    /// Null has TWO causes and a caller that can act on them differently should ask
    /// <see cref="IsOffered"/> which it is: this transmitter serves no poll delivery at all, or it does
    /// and this stream still has no address - an identifier the route cannot carry, for one. Reading
    /// null as the first cause alone makes the branch written for the second look unreachable, which is
    /// why the summary above names neither.
    /// </remarks>
    /// <param name="streamId">The stream whose queue is served there.</param>
    public Uri? Of(string streamId)
        => options.PollEndpointFactory is { } hostsOwn ? hostsOwn(streamId) : routes.Poll?.Invoke(identity, streamId);
}
