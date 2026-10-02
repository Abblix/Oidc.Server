// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// Composes the addresses this deployment publishes for its poll endpoints.
/// </summary>
internal static class PollEndpointAddresses
{
    /// <summary>
    /// The prefix the outside world reaches this deployment on: the advertised one where a proxy rewrites
    /// paths, the mapped one otherwise.
    /// </summary>
    internal static PathString AdvertisedPrefixOf(SharedSignalsEndpointOptions endpointOptions)
        => endpointOptions.AdvertisedPrefix.HasValue
            ? endpointOptions.AdvertisedPrefix
            : endpointOptions.ManagementPrefix;

    /// <summary>
    /// The authority every endpoint this deployment publishes lives on - the issuer's, which is what a
    /// receiver holding nothing else already has.
    /// </summary>
    internal static Uri AuthorityOf(SharedSignalsTransmitterOptions options)
        => new(new Uri(options.Issuer, UriKind.Absolute).GetLeftPart(UriPartial.Authority));

    /// <summary>
    /// Where the poll endpoint of a stream is served, refused when that address would not lead back to
    /// the stream it names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The identifier is escaped so that one an operator spelled out survives into the URL whole, and the
    /// escaped text is handed over as a <see cref="PathString"/> rather than as a string. The distinction
    /// is load-bearing: PathString's implicit conversion FROM a string decodes - it runs the text back
    /// through UrlDecoder, keeping only %2F - so passing the interpolated string would undo the escaping
    /// one call later, and a '?' would reach <see cref="Uri"/> as a query delimiter. The address would
    /// then be that of a DIFFERENT stream, well-formed and served: "alerts?eu" minting the poll endpoint
    /// of "alerts". Composing by hand avoids the decode and loses the other thing
    /// <see cref="PathString.Add(PathString)"/> does, which is to trim a duplicated separator - a prefix
    /// ending in '/' would mint "/ssf//poll/{id}", which the route does not match.
    /// </para>
    /// <para>
    /// Escaping is not the same as being addressable, so the address is walked back before it is handed
    /// out: what the mapping mints is asked what a request to it would deliver to the handler, and an
    /// identifier that does not come back is refused. That check is a ROUND TRIP rather than a list of
    /// forbidden characters, because the list is never finished. Measuring it through a real host found
    /// two unrelated ways to fail and only one of them is about a character: '/' escapes to %2F, which is
    /// the single escape the path decoder preserves, so the handler receives "alerts%2Feu" and the lookup
    /// misses; while "." and ".." are not escaped at all, and the URI normalizer removes the segment
    /// before the request is sent, so no route matches. The same measurement cleared characters a
    /// blocklist would have caught by association - '\', '?', '#', '%' and non-ASCII all survive intact -
    /// so refusing them would cost an operator names that work.
    /// </para>
    /// <para>
    /// The expected side is built with the <see cref="PathString"/> CONSTRUCTOR, which stores the text as
    /// it is. Only the implicit conversion FROM a string decodes, and that is what the left side uses on
    /// purpose - it is how the ASP.NET decoder gets applied to the minted path. Writing the expected side
    /// the idiomatic way instead, <c>prefix.Add($"...")</c>, compiles identically and decodes it too, and
    /// then an identifier spelled <c>%2E%2E</c> reads as <c>..</c> and is refused although this host
    /// serves it. Dropping the two <c>.Value</c>s and comparing the PathStrings changes nothing today,
    /// so the constructor is the token to keep, not the comparison.
    /// </para>
    /// <para>
    /// Answering null rather than throwing, because both callers can act on it and neither wants a
    /// fault. A DECLARED stream is materialized when <see cref="ConfigurationStreamStore"/> is
    /// constructed - the delivery scheduler takes that store as a hosted service, so the host builds it
    /// while starting - and that store turns the null into a refusal at startup. A RECEIVER asking to
    /// move an existing stream to poll delivery reaches the same code through the management API, which
    /// is how a declared PUSH stream named something unaddressable gets here at request time: it is
    /// admitted at startup, quite rightly, since a push stream needs no address of ours, and then
    /// CAEP 2.3.8.1 obliges this transmitter to entertain a switch to poll. There the null becomes the
    /// refusal the management service already returns for a delivery method it cannot serve, which is
    /// something the receiver can read.
    /// </para>
    /// <para>
    /// A dynamically created stream is named by a GUID and never fails the round trip. A host that names
    /// its own address through <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/> never
    /// reaches this code, which is right: what an identifier has to survive there is that host's
    /// routing, not this one's.
    /// </para>
    /// </remarks>
    /// <param name="logger">Where the reason goes, since the value is only a null.</param>
    /// <param name="authority">The transmitter's authority, as its issuer states it.</param>
    /// <param name="prefix">The prefix the outside world reaches the endpoints through.</param>
    /// <param name="streamId">The stream whose queue is served there.</param>
    internal static Uri? PollEndpointOf(ILogger logger, Uri authority, PathString prefix, string streamId)
    {
        var route = prefix.Add(new PathString($"{ManagementRoutes.Poll}/{Uri.EscapeDataString(streamId)}"));
        var address = new Uri(authority, route.Value!);

        PathString delivered = address.AbsolutePath;
        if (delivered.Value == prefix.Add(new PathString($"{ManagementRoutes.Poll}/{streamId}")).Value)
        {
            return address;
        }

        logger.LogWarning(
            "No poll address can be composed for the stream identifier {StreamId}: a request to "
            + "{Address} reaches this transmitter naming something else, or nothing at all. Name the "
            + "stream something a URL path carries unchanged, or give it push delivery, which needs no "
            + "address of ours.",
            streamId,
            address);

        return null;
    }
}
