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

using System.Net;
using System.Net.Http.Json;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// The receiver's side of the Event Stream Management API of one transmitter
/// (SSF 1.0 Section 8.1): stream lifecycle, status, subjects and verification, each method
/// speaking to the endpoint the transmitter's configuration metadata advertises.
/// </summary>
/// <remarks>
/// <para>
/// Outcomes the specification gives the receiver a distinct reaction to are answers, not
/// exceptions: a create that hits an existing stream (409), an update the transmitter accepted
/// but has not processed (202), a verification or subject call the transmitter throttled (429).
/// Everything else - authorization, unknown streams on writes, malformed requests - surfaces as
/// the <see cref="HttpRequestException"/> the transport already speaks.
/// </para>
/// <para>
/// Every configuration document read back is checked to assert the transmitter's own issuer, as
/// Sections 8.1.1.1 through 8.1.1.4 require of the receiver. Authentication is the
/// <see cref="HttpClient"/>'s configuration, not this type's concern.
/// </para>
/// </remarks>
/// <param name="httpClient">The client the API is spoken through.</param>
/// <param name="transmitter">
/// The transmitter's configuration metadata: the endpoints and the issuer identity every
/// response is held to.</param>
public sealed class StreamManagementClient(HttpClient httpClient, TransmitterConfiguration transmitter)
{
    /// <summary>
    /// Creates an Event Stream (SSF 1.0 Section 8.1.1.1).
    /// </summary>
    /// <param name="request">The receiver-supplied half of the configuration.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The stream's configuration as the transmitter created it, or null on "409 Conflict" -
    /// the transmitter allows one stream per receiver and it already exists, so the receiver's
    /// move is to read it and update or replace what differs.</returns>
    public async Task<StreamConfiguration?> CreateAsync(
        CreateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync(
            ConfigurationEndpoint, request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadConfigurationAsync(response, cancellationToken);
    }

    /// <summary>
    /// Reads one stream's configuration (SSF 1.0 Section 8.1.1.2).
    /// </summary>
    /// <param name="streamId">The stream to read.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The configuration, or null when no stream with this identifier exists for this
    /// receiver.</returns>
    public async Task<StreamConfiguration?> GetAsync(
        string streamId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);

        using var response = await httpClient.GetAsync(
            WithStreamId(ConfigurationEndpoint, streamId), cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadConfigurationAsync(response, cancellationToken);
    }

    /// <summary>
    /// Lists every stream configured for this receiver (SSF 1.0 Section 8.1.1.2). An empty list
    /// is the answer for a receiver with no streams, never an error.
    /// </summary>
    /// <param name="cancellationToken">Cancels the call.</param>
    public async Task<IReadOnlyList<StreamConfiguration>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(ConfigurationEndpoint, cancellationToken);
        response.EnsureSuccessStatusCode();

        var configurations = await response.Content
            .ReadFromJsonAsync<IReadOnlyList<StreamConfiguration>>(cancellationToken)
            ?? throw new InvalidOperationException(
                "The stream list deserialized to null; an empty list travels as [] (SSF 1.0 Section 8.1.1.2).");

        foreach (var configuration in configurations)
        {
            EnsureTransmitterIssuer(configuration);
        }

        return configurations;
    }

    /// <summary>
    /// Updates a stream's configuration: present receiver-supplied members change, absent ones
    /// stay (SSF 1.0 Section 8.1.1.3).
    /// </summary>
    /// <param name="request">The stream identifier and the members to change.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The entire updated configuration, or null on "202 Accepted" - the transmitter took the
    /// request but has not processed it, and the receiver may repeat the same request later for
    /// the result.</returns>
    public async Task<StreamConfiguration?> UpdateAsync(
        UpdateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PatchAsJsonAsync(
            ConfigurationEndpoint, request, cancellationToken);

        return await ReadConfigurationOrAcceptedAsync(response, cancellationToken);
    }

    /// <summary>
    /// Replaces a stream's configuration: the request carries the full receiver-supplied set,
    /// and a member absent from it is deleted (SSF 1.0 Section 8.1.1.4).
    /// </summary>
    /// <param name="request">The stream identifier and the full receiver-supplied set.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The entire updated configuration, or null on "202 Accepted", as with
    /// <see cref="UpdateAsync"/>.</returns>
    public async Task<StreamConfiguration?> ReplaceAsync(
        UpdateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PutAsJsonAsync(
            ConfigurationEndpoint, request, cancellationToken);

        return await ReadConfigurationOrAcceptedAsync(response, cancellationToken);
    }

    /// <summary>
    /// Deletes a stream (SSF 1.0 Section 8.1.1.5).
    /// </summary>
    /// <param name="streamId">The stream to delete.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    public async Task DeleteAsync(string streamId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);

        using var response = await httpClient.DeleteAsync(
            WithStreamId(ConfigurationEndpoint, streamId), cancellationToken);

        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Reads a stream's current status (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    /// <param name="streamId">The stream whose status is being queried.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The status document, or null when no stream with this identifier exists for
    /// this receiver.</returns>
    public async Task<StreamStatus?> GetStatusAsync(
        string streamId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);

        using var response = await httpClient.GetAsync(
            WithStreamId(StatusEndpoint, streamId), cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadBodyAsync<StreamStatus>(response, cancellationToken);
    }

    /// <summary>
    /// Updates a stream's status (SSF 1.0 Section 8.1.2.2).
    /// </summary>
    /// <param name="request">The stream, the new status, and optionally why.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The updated status as the transmitter echoes it, or null on "202 Accepted" - taken but
    /// not yet processed, repeatable later for the result.</returns>
    public async Task<StreamStatus?> UpdateStatusAsync(
        StreamStatus request,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync(StatusEndpoint, request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadBodyAsync<StreamStatus>(response, cancellationToken);
    }

    /// <summary>
    /// Adds a subject to a stream (SSF 1.0 Section 8.1.3.2).
    /// </summary>
    /// <param name="request">The stream, the subject, and optionally whether it is verified.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// True when the transmitter answered success - which deliberately proves nothing about the
    /// subject being known or added, so the response cannot be used to probe who the
    /// transmitter knows (SSF 1.0 Section 9.1); false when it throttled the request (429).
    /// </returns>
    public Task<bool> AddSubjectAsync(
        AddSubjectRequest request,
        CancellationToken cancellationToken = default)
        => PostForOutcomeAsync(AddSubjectEndpoint, request, cancellationToken);

    /// <summary>
    /// Removes a subject from a stream (SSF 1.0 Section 8.1.3.3).
    /// </summary>
    /// <param name="request">The stream and the subject.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>True on success, under the same no-probing caveat as
    /// <see cref="AddSubjectAsync"/>; false when throttled (429).</returns>
    public Task<bool> RemoveSubjectAsync(
        RemoveSubjectRequest request,
        CancellationToken cancellationToken = default)
        => PostForOutcomeAsync(RemoveSubjectEndpoint, request, cancellationToken);

    /// <summary>
    /// Requests a Verification Event over a stream (SSF 1.0 Section 8.1.4.2).
    /// </summary>
    /// <param name="request">The stream and optionally the state to be echoed back.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// True when the transmitter will transmit the event - possibly asynchronously and in no
    /// particular order, so the receiver must not wait on it; false when the request was
    /// throttled (429), see "min_verification_interval" in the stream's configuration.</returns>
    public Task<bool> RequestVerificationAsync(
        VerificationRequest request,
        CancellationToken cancellationToken = default)
        => PostForOutcomeAsync(VerificationEndpoint, request, cancellationToken);

    private Uri ConfigurationEndpoint => Require(
        transmitter.ConfigurationEndpoint, TransmitterConfiguration.ParameterNames.ConfigurationEndpoint);

    private Uri StatusEndpoint => Require(
        transmitter.StatusEndpoint, TransmitterConfiguration.ParameterNames.StatusEndpoint);

    private Uri AddSubjectEndpoint => Require(
        transmitter.AddSubjectEndpoint, TransmitterConfiguration.ParameterNames.AddSubjectEndpoint);

    private Uri RemoveSubjectEndpoint => Require(
        transmitter.RemoveSubjectEndpoint, TransmitterConfiguration.ParameterNames.RemoveSubjectEndpoint);

    private Uri VerificationEndpoint => Require(
        transmitter.VerificationEndpoint, TransmitterConfiguration.ParameterNames.VerificationEndpoint);

    private static Uri Require(Uri? endpoint, string memberName)
        => endpoint ?? throw new InvalidOperationException(
            $"The transmitter's configuration metadata does not advertise '{memberName}', which this "
            + "operation speaks to (SSF 1.0 Section 7.1).");

    private static Uri WithStreamId(Uri endpoint, string streamId)
    {
        var parameter = $"{StreamMemberNames.StreamId}={Uri.EscapeDataString(streamId)}";
        var builder = new UriBuilder(endpoint);
        builder.Query = builder.Query is { Length: > 1 } existing
            ? $"{existing[1..]}&{parameter}"
            : parameter;
        return builder.Uri;
    }

    private async Task<bool> PostForOutcomeAsync<TRequest>(
        Uri endpoint,
        TRequest request,
        CancellationToken cancellationToken)
    {
        using var response = await httpClient.PostAsJsonAsync(endpoint, request, cancellationToken);

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return false;
        }

        response.EnsureSuccessStatusCode();
        return true;
    }

    private async Task<StreamConfiguration?> ReadConfigurationOrAcceptedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.StatusCode == HttpStatusCode.Accepted)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        return await ReadConfigurationAsync(response, cancellationToken);
    }

    private async Task<StreamConfiguration> ReadConfigurationAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var configuration = await ReadBodyAsync<StreamConfiguration>(response, cancellationToken);
        EnsureTransmitterIssuer(configuration);
        return configuration;
    }

    private static async Task<TBody> ReadBodyAsync<TBody>(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
        => await response.Content.ReadFromJsonAsync<TBody>(cancellationToken)
           ?? throw new InvalidOperationException(
               $"The transmitter's response deserialized to null where a {typeof(TBody).Name} was expected.");

    /// <summary>
    /// The receiver's half of SSF 1.0 Sections 8.1.1.1-8.1.1.4: every configuration document
    /// read back must assert the issuer the transmitter configuration was fetched from, or a
    /// compromised or misrouted management endpoint could bind this receiver to another
    /// issuer's stream.
    /// </summary>
    private void EnsureTransmitterIssuer(StreamConfiguration configuration)
    {
        if (!string.Equals(configuration.Issuer, transmitter.Issuer, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The stream configuration asserts the issuer '{configuration.Issuer}', not the "
                + $"transmitter's '{transmitter.Issuer}' (SSF 1.0 Sections 8.1.1.1-8.1.1.4).");
        }
    }
}
