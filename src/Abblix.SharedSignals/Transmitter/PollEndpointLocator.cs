// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where this transmitter serves a stream's poll queue - the "endpoint_url value is supplied by the
/// Transmitter" of SSF 1.0 Section 8.1.1.1, and therefore the one thing a stream cannot be created with
/// poll delivery without.
/// </summary>
/// <remarks>
/// The address has two possible sources and they answer different questions.
/// <list type="bullet">
///   <item><see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/> is where the outside world
///   reaches the endpoint. A deployment behind a gateway is the case it exists for, and it wins.</item>
///   <item><see cref="ServedAt"/> is where the endpoint is actually mapped, declared by whatever mapped
///   it. That is the only code that knows: the route and its prefix belong to the web framework adapter,
///   and a host may move the prefix.</item>
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
public sealed class PollEndpointLocator(SharedSignalsTransmitterOptions options)
{
    private Func<string, Uri>? _served;

    /// <summary>
    /// Whether this transmitter offers poll delivery at all - what "delivery_methods_supported"
    /// advertises (SSF 1.0 Section 7.1) and what a create naming poll is judged against.
    /// </summary>
    public bool IsOffered => options.PollEndpointFactory is not null || _served is not null;

    /// <summary>
    /// Declares where the poll endpoint is mapped, so a stream created without the host naming an address
    /// gets one that leads back to the route serving it.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the route, which happens once at startup and before any stream can be
    /// created. It is not the host's call to make: a host naming its own address uses
    /// <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>, which this never overrides.
    /// </remarks>
    /// <param name="pollEndpointOf">Derives the mapped address of a stream's poll endpoint.</param>
    /// <exception cref="InvalidOperationException">The endpoint was already mapped. A stream's poll
    /// address is stored in its configuration, so a second mapping would leave every stream created
    /// before it pointing at the first - and which streams those are depends on when each call ran.
    /// </exception>
    public void ServedAt(Func<string, Uri> pollEndpointOf)
    {
        ArgumentNullException.ThrowIfNull(pollEndpointOf);

        if (_served is not null)
        {
            throw new InvalidOperationException(
                "The poll endpoint is already mapped. A transmitter serves one, and the address goes "
                + "into every stream it creates.");
        }

        _served = pollEndpointOf;
    }

    /// <summary>
    /// The poll endpoint of a stream, or null when this transmitter offers no poll delivery.
    /// </summary>
    /// <param name="streamId">The stream whose queue is served there.</param>
    public Uri? Of(string streamId) => (options.PollEndpointFactory ?? _served)?.Invoke(streamId);
}
