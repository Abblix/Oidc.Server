// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Builds the delivery a stream stores from the one its receiver proposed (Factory), or the refusal
/// that stops the write.
/// </summary>
/// <param name="addressPolicy">Judges the delivery address a receiver proposes.</param>
/// <param name="pollEndpoints">Where a poll stream is polled - this transmitter's own address.</param>
internal sealed class StreamDeliveryFactory(ReceiverAddressPolicy addressPolicy, PollEndpointLocator pollEndpoints)
{
    /// <summary>
    /// The delivery this transmitter will store for a proposal, or the refusal that stops it.
    /// </summary>
    /// <remarks>
    /// Resolving a method and judging its address are one decision, so they are one call. Three verbs
    /// write a stream's delivery - create, update and replace - and nothing in the type system makes
    /// the second check happen beside the first, so a path that asks only whether the METHOD is served
    /// stores an address every delivery pass then refuses. Any future write path has one method to
    /// reach for and gets both halves by having no way to ask for one.
    ///
    /// 400 on all three verbs, which is a decision rather than an oversight. SSF 1.0 Sections 8.1.1.3
    /// and 8.1.1.4 list it for a request that is "otherwise invalid", which covers update and replace
    /// outright. Section 8.1.1.1's table does not carry that phrase - its 400 is for a request that
    /// cannot be parsed, and its prose adds only that a transmitter MAY answer 400 when it does not
    /// support the delivery METHOD. An unusable ENDPOINT is unlisted there, and 403 ("the Event Receiver
    /// is not allowed to create a stream") reads as a verdict about the receiver's permission rather
    /// than about the address it wrote. Since the refusal reaches the receiver as a bare status code,
    /// one answer across the three verbs is worth more than a per-verb code that would make a receiver
    /// branch on the method it used to say the same wrong thing.
    /// </remarks>
    public ManagementResult<StreamDeliveryMethod> Create(StreamDeliveryMethod? proposed, string streamId)
    {
        if (Resolve(proposed, streamId) is not { } delivery)
        {
            // Two refusals wearing one answer send half the readers to the wrong place. A transmitter
            // that offers poll and still has no address for THIS stream advertises urn:ietf:rfc:8936 in
            // its configuration document, so calling the method unsupported contradicts what the same
            // host publishes.
            //
            // Who reads this at all: not the receiver. Render writes the status and drops the
            // description, and nothing here logs it - so over HTTP the two refusals are one 400 either
            // way, and this text reaches only a host driving this service directly.
            return ManagementResult<StreamDeliveryMethod>.BadRequest(
                proposed is PollDeliveryMethod or null && pollEndpoints.IsOffered
                    ? "This transmitter serves poll delivery, but has no poll address for this stream: "
                      + "its identifier cannot be carried into one. Name the stream something a URL path "
                      + "carries unchanged, or ask for push delivery, which needs no address of ours."
                    : "The requested delivery method is not supported by this transmitter.");
        }

        if (AddressRefusalOf(delivery) is { } refusal)
        {
            return ManagementResult<StreamDeliveryMethod>.BadRequest(
                $"The delivery endpoint cannot be used by this transmitter: {refusal}.");
        }

        return ManagementResult<StreamDeliveryMethod>.Ok(delivery);
    }

    /// <summary>The same refusal, for an endpoint whose successful body is the configuration.</summary>
    /// <remarks>
    /// A refusal carries no body, so only the status and the operator-facing description travel. This
    /// exists so the three write paths return the ONE decision above rather than each restating it -
    /// restating is how two paths come to answer differently for the same cause.
    ///
    /// A success throws rather than being re-typed. The callers reach this on "no delivery to store",
    /// which is not the same statement as "refused": <see cref="ManagementResult{TBody}"/> publishes a
    /// body-less SUCCESS too, so an outcome added to <see cref="Create"/> through it would otherwise be
    /// re-typed into a 2xx carrying nothing - a create answered to the receiver as having succeeded
    /// while it stored no stream. Loud is the right failure for that: silent is a refusal dressed as an
    /// acceptance, which is the one shape a caller cannot detect.
    /// </remarks>
    public static ManagementResult<StreamConfiguration> RefusalOf(
        ManagementResult<StreamDeliveryMethod> refused)
        => refused.StatusCode >= HttpStatusCode.BadRequest
            ? new(refused.StatusCode, default, refused.Description)
            : throw new ArgumentOutOfRangeException(
                nameof(refused),
                refused.StatusCode,
                "Only a refusal is re-typed here, and this status is not one.");

    /// <summary>
    /// The receiver-visible delivery for a proposal: push keeps the receiver's endpoint, poll
    /// gets this transmitter's own URL - the "endpoint_url value is supplied by the
    /// Transmitter" (SSF 1.0 Section 8.1.1.1) - and an absent proposal means poll. Null when
    /// the transmitter cannot serve the method.
    /// </summary>
    private StreamDeliveryMethod? Resolve(StreamDeliveryMethod? proposed, string streamId)
        => proposed switch
        {
            PushDeliveryMethod push => push,
            PollDeliveryMethod or null when pollEndpoints.Of(streamId) is { } pollEndpoint =>
                new PollDeliveryMethod(pollEndpoint),
            _ => null,
        };

    /// <summary>
    /// Why this transmitter will never deliver to the proposed address, or null when it will.
    /// </summary>
    /// <remarks>
    /// Asked here as well as at delivery, and by the same policy on purpose. The reasons an address is
    /// refused by its NAME - cleartext, or a host spelling out this deployment's own network - are true
    /// the moment the receiver writes it, so accepting the stream and refusing every push afterwards
    /// tells the receiver nothing: its create succeeded, and the refusal lives only in a log it cannot
    /// read. Two checks over one fact would drift; one policy consulted twice cannot.
    ///
    /// <see cref="ReceiverAddressPolicy.RejectionOfName"/> rather than the whole question, because what
    /// a name RESOLVES to is not settled at registration: it is looked up again for every pass, and a
    /// resolver that is briefly down is a condition an operator recovers from - which delivery treats as
    /// one by holding the queue. Answered here it would become a terminal 400, and a receiver
    /// registering while its own record is still propagating could not tell that from a permanent
    /// refusal. Asking only the fixed half also keeps this endpoint from driving the transmitter's
    /// resolver at request rate against names a caller chooses.
    ///
    /// Poll delivery is not judged: the address in it is this transmitter's own, minted by
    /// <see cref="PollEndpointLocator"/> rather than proposed from outside, and nothing arrives from the
    /// receiver to judge.
    ///
    /// Every method is named and an unnamed one throws, though nothing can reach that arm as the code
    /// stands: <see cref="Resolve"/> answers null for a method this transmitter does not serve,
    /// and the caller refuses before asking here. The arm is for the day somebody teaches that method a
    /// third delivery and not this one. The build is green either way, so the choice is between a loud
    /// throw and a quiet "nothing to judge" that exempts the new method from the check - and a delivery
    /// method carries an address from somewhere, so the exemption is the shape this guards against.
    /// </remarks>
    private string? AddressRefusalOf(StreamDeliveryMethod delivery)
        => delivery switch
        {
            PushDeliveryMethod push => addressPolicy.RejectionOfName(push.EndpointUrl),
            PollDeliveryMethod => null,
            _ => throw new ArgumentOutOfRangeException(
                nameof(delivery),
                delivery.Method,
                "This delivery method has no address rule, so nothing decided whether its endpoint may "
                    + "be used. Name it here rather than letting it deliver unjudged."),
        };
}
