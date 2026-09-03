// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Mime;
using System.Text;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// Every status this surface answers is declared by the route that answers it, and every status a
/// route declares is one this suite has seen it answer.
/// </summary>
/// <remarks>
/// A status sent and not declared, and one declared and never sent, are the same lie read from the two
/// ends. The first leaves a generated client with no branch for an answer it will meet; the second gives
/// it a branch nothing reaches, which is then maintained forever on the strength of the document.
/// <para>
/// Both halves are asserted, and both are MEASURED rather than read: what a route answers comes from
/// driving a real request through a real host, and what it declares is read back off the endpoint's own
/// metadata. Nothing here parses the mapping source, because the mapping is what is under test.
/// </para>
/// <para>
/// The consequence to accept is that this file has to drive every status, including the two that a
/// route reaches only when its conditional write LOSES: 202 where repeating the call is the way
/// forward, 409 where the caller is told someone else is changing the stream. That is what
/// <see cref="RefusingUpdates"/> is for - a store that takes every call except the write, so the retry
/// loop ends with nothing written. Without it those answers could only be exempted by name, and a
/// named exemption is where a declaration nobody drives goes to live.
/// </para>
/// <para>
/// One framework status is outside all of this and stays there: 405 to a wrong method, which every
/// path on this surface answers. It belongs to no route, because no endpoint matched - which is also why an
/// OpenAPI document has no operation to declare it on. That is a category exemption like the one this
/// file refuses elsewhere, so it is written down rather than left to be noticed.
/// </para>
/// <para>
/// The statuses the FRAMEWORK answers are driven too - 415 to a wrong media type, 400 to a body that
/// does not bind - rather than left out as "not this package's". A receiver meets them on these routes,
/// so its client needs a branch for them whoever produced them, and the moment they are excused by
/// category the excuse covers whatever else falls into it.
/// </para>
/// <para>
/// What the drive cannot do is find a status nobody thought to reach: an answer neither driven nor
/// declared agrees with itself. Verification is the case that proves the cost - its lost-write answer
/// is reachable only BEFORE the stream has ever been verified, because afterwards the throttle refuses
/// first, so the row that reaches it has to come before the two that verify normally.
/// </para>
/// </remarks>
public sealed class TheSurfaceDeclaresEveryStatusItAnswersTests
{
    private const string Issuer = "https://transmitter.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";
    private const string Receiver = "receiver-1";
    private const string PushMethod = "urn:ietf:rfc:8935";

    private static readonly object PushDelivery = new
    {
        method = PushMethod,
        endpoint_url = "https://receiver.example/events",
    };

    [Fact]
    public async Task EveryRoute_DeclaresExactlyTheStatusesItAnswers()
    {
        var answered = await DriveEveryOutcomeAsync();

        // A route that answered nothing would satisfy "declared covers answered" while proving no part
        // of it, so the drive is required to have reached every route in the table below before
        // anything is judged. No count is written here: the table is what says how many there are, and
        // a number beside it is a second place to keep in step.
        var routes = MappedRoutes();
        var reached = answered.Select(answer => (answer.Method, answer.Pattern)).ToHashSet();
        Assert.True(
            routes.All(reached.Contains),
            "the drive never reached: "
                + string.Join(", ", routes.Where(route => !reached.Contains(route))
                    .Select(route => $"{route.Method} {route.Pattern}")));

        var disagreements = new List<string>();
        foreach (var (method, pattern) in routes)
        {
            var sent = answered
                .Where(answer => answer.Method == method && answer.Pattern == pattern)
                .Select(answer => answer.StatusCode)
                .ToHashSet();

            var declared = DeclaredBy(method, pattern);
            var published = PublishedBy(method, pattern);

            // Attached and published are two facts. The first is what this file used to check alone,
            // and it stays green over a declaration the description pipeline throws away.
            var swallowed = declared.Except(published).Order().ToList();
            if (swallowed.Count > 0)
            {
                disagreements.Add(
                    $"{method} {pattern} declares {string.Join(", ", swallowed)} and publishes "
                        + $"{string.Join(", ", published.Order())}");
            }

            // And the other direction, which is what the original defect actually looked like: an
            // operation publishing a status nobody declared, INFERRED by the pipeline because the
            // declarations it was given were thrown away. Unreachable today only because every route
            // here publishes something, and that is a property of the group rather than of this check.
            var invented = published.Except(declared).Order().ToList();
            if (invented.Count > 0)
            {
                disagreements.Add(
                    $"{method} {pattern} publishes {string.Join(", ", invented)} and declares no such thing");
            }

            var undeclared = sent.Except(declared).Order().ToList();
            if (undeclared.Count > 0)
            {
                disagreements.Add(
                    $"{method} {pattern} answers {string.Join(", ", undeclared)} without declaring it");
            }

            var unsent = declared.Except(sent).Order().ToList();
            if (unsent.Count > 0)
            {
                disagreements.Add(
                    $"{method} {pattern} declares {string.Join(", ", unsent)} and this suite never saw it");
            }
        }

        Assert.True(
            disagreements.Count == 0,
            $"routes {routes.Count}, answers driven {answered.Count}, disagreements "
                + $"{disagreements.Count}:{Environment.NewLine}"
                + string.Join(Environment.NewLine, disagreements));
    }

    /// <summary>
    /// Drives one request per outcome each route can produce, and records the status that came back.
    /// The expectation is not asserted here on purpose: what a route answers is what this method
    /// MEASURES, and an assertion would turn a wrong guess of mine into a failure about the surface.
    /// </summary>
    private async Task<List<Answer>> DriveEveryOutcomeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var answers = new List<Answer>();

        await using var host = await StartAsync(_ => Receiver);
        var store = Assert.IsType<RefusingUpdates>(host.Services.GetRequiredService<IStreamStore>());
        var client = host.GetTestClient();

        async Task Record(string method, string pattern, string path, object? body = null)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body);
            }

            using var response = await client.SendAsync(request, ct);
            answers.Add(new Answer(method, pattern, (int)response.StatusCode));
        }

        // Created, and the identifier every row below names.
        using (var created = await client.PostAsJsonAsync(
            "/ssf/stream", new { delivery = PushDelivery, events_requested = new[] { SomeEvent } }, ct))
        {
            answers.Add(new Answer("POST", StreamRoute, (int)created.StatusCode));
            var configuration = await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct);
            Assert.NotNull(configuration);
            _streamId = configuration.StreamId;
        }

        // A second stream for a receiver this transmitter allows one stream: 409 by policy.
        await Record("POST", StreamRoute, "/ssf/stream",
            new { delivery = PushDelivery, events_requested = new[] { SomeEvent } });

        // A delivery method this transmitter does not serve: refused where the proposal is read.
        await Record("POST", StreamRoute, "/ssf/stream",
            new { delivery = new { method = "urn:example:carrier-pigeon" } });

        await Record("GET", StreamRoute, "/ssf/stream");
        await Record("GET", StreamRoute, "/ssf/stream?stream_id=no-such-stream");

        await Record("PATCH", StreamRoute, "/ssf/stream",
            new { stream_id = _streamId, events_requested = new[] { SomeEvent } });
        await Record("PATCH", StreamRoute, "/ssf/stream", new { stream_id = "no-such-stream" });
        await Record("PATCH", StreamRoute, "/ssf/stream",
            new { stream_id = _streamId, delivery = new { method = "urn:example:carrier-pigeon" } });

        await Record("PUT", StreamRoute, "/ssf/stream",
            new { stream_id = _streamId, delivery = PushDelivery, events_requested = new[] { SomeEvent } });
        await Record("PUT", StreamRoute, "/ssf/stream", new { stream_id = "no-such-stream", delivery = PushDelivery });

        // Replace with no delivery at all: a replacement states the whole configuration, so an absent
        // member is a request to serve nothing rather than a member left as it was.
        await Record("PUT", StreamRoute, "/ssf/stream", new { stream_id = _streamId });

        await Record("GET", StatusRoute, $"/ssf/status?stream_id={_streamId}");
        await Record("GET", StatusRoute, "/ssf/status?stream_id=no-such-stream");
        await Record("GET", StatusRoute, "/ssf/status");

        await Record("POST", StatusRoute, "/ssf/status", new { stream_id = _streamId, status = "paused" });
        await Record("POST", StatusRoute, "/ssf/status", new { stream_id = "no-such-stream", status = "paused" });
        await Record("POST", StatusRoute, "/ssf/status", new { stream_id = _streamId, status = "asleep" });

        // Back to enabled: verification below dispatches an event, and a paused stream is a different
        // question from the one this row asks.
        await Record("POST", StatusRoute, "/ssf/status", new { stream_id = _streamId, status = "enabled" });

        var subject = new { format = "opaque", id = "subject-1" };
        await Record("POST", AddSubjectRoute, "/ssf/subjects:add", new { stream_id = _streamId, subject });
        await Record("POST", AddSubjectRoute, "/ssf/subjects:add",
            new { stream_id = "no-such-stream", subject });

        // A complex subject naming no member agrees with every event, so it is refused where it arrives.
        await Record("POST", AddSubjectRoute, "/ssf/subjects:add",
            new { stream_id = _streamId, subject = new { format = "complex" } });

        await Record("POST", RemoveSubjectRoute, "/ssf/subjects:remove", new { stream_id = _streamId, subject });
        await Record("POST", RemoveSubjectRoute, "/ssf/subjects:remove",
            new { stream_id = "no-such-stream", subject });

        await Record("POST", VerifyRoute, "/ssf/verify", new { stream_id = "no-such-stream" });

        // Contention on verification is driven FIRST, while the stream has never been verified: once
        // it has, every later request is throttled before it reaches the write, and the answer that
        // needs the lost write becomes unreachable through this route for the rest of the run.
        store.Refuse = true;
        await Record("POST", VerifyRoute, "/ssf/verify", new { stream_id = _streamId });
        store.Refuse = false;

        await Record("POST", VerifyRoute, "/ssf/verify", new { stream_id = _streamId });

        // The second request inside the stream's minimum interval is the throttle.
        await Record("POST", VerifyRoute, "/ssf/verify", new { stream_id = _streamId });

        await Record("POST", PollRoute, $"/ssf/poll/{_streamId}", new { maxEvents = 1, returnImmediately = true });
        await Record("POST", PollRoute, "/ssf/poll/no-such-stream", new { maxEvents = 1, returnImmediately = true });

        // From here the store refuses the conditional write, so every path that ends in one reports
        // that nothing was written - as 202 where repeating the call is the way forward, and as 409
        // where the caller is being told someone else is changing the stream.
        store.Refuse = true;

        await Record("PATCH", StreamRoute, "/ssf/stream",
            new { stream_id = _streamId, events_requested = new[] { SomeEvent } });
        await Record("PUT", StreamRoute, "/ssf/stream",
            new { stream_id = _streamId, delivery = PushDelivery, events_requested = new[] { SomeEvent } });
        await Record("POST", StatusRoute, "/ssf/status", new { stream_id = _streamId, status = "paused" });
        await Record("POST", AddSubjectRoute, "/ssf/subjects:add", new { stream_id = _streamId, subject });
        await Record("POST", RemoveSubjectRoute, "/ssf/subjects:remove", new { stream_id = _streamId, subject });

        store.Refuse = false;

        // What the framework answers before this package's code runs. Driven rather than exempted:
        // a body-bound route answers these to a caller who got the media type or the JSON wrong, and a
        // status a receiver can meet is a status its client needs a branch for, whoever produced it.
        // Without a stream the poll path collapses to /ssf/poll/, whose answer is a 404 that route
        // already declares - so the two rows meant for it would vanish with the suite still green.
        Assert.NotEmpty(_streamId);

        foreach (var (method, pattern, path) in BodyBoundRoutes())
        {
            using (var wrongType = new HttpRequestMessage(new HttpMethod(method), path)
            {
                Content = new StringContent("{}", Encoding.UTF8, MediaTypeNames.Text.Plain),
            })
            {
                using var refused = await client.SendAsync(wrongType, ct);
                answers.Add(new Answer(method, pattern, (int)refused.StatusCode));
            }

            using (var malformed = new HttpRequestMessage(new HttpMethod(method), path)
            {
                Content = new StringContent("{", Encoding.UTF8, MediaTypeNames.Application.Json),
            })
            {
                using var refused = await client.SendAsync(malformed, ct);
                answers.Add(new Answer(method, pattern, (int)refused.StatusCode));
            }
        }

        // Deletion last: every row above needs the stream.
        await Record("DELETE", StreamRoute, "/ssf/stream?stream_id=no-such-stream");
        await Record("DELETE", StreamRoute, "/ssf/stream");
        await Record("DELETE", StreamRoute, $"/ssf/stream?stream_id={_streamId}");

        await Record("GET", DocumentRoute, DocumentRoute);

        answers.AddRange(await DriveEveryRouteAsync(receiverId: null));
        answers.AddRange(await DriveEveryRouteAsync(receiverId: _ => Receiver, grantedScopes: _ => []));

        return answers;
    }

    /// <summary>
    /// One request per route against a host that names nobody, or grants no scope. Both refusals
    /// belong to the GROUP rather than to any handler, so they are driven over every route rather than
    /// sampled.
    /// </summary>
    /// <remarks>
    /// Not every route here is refused, and the one that is not is the point of driving all of them.
    /// The configuration document is mapped outside that group and answers 200 to a caller with no
    /// identity and no scope - which is what discovery is for, and what would break silently if the
    /// group ever grew to cover it.
    /// </remarks>
    private async Task<List<Answer>> DriveEveryRouteAsync(
        Func<HttpContext, string?>? receiverId,
        Func<HttpContext, IReadOnlyCollection<string>>? grantedScopes = null)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(receiverId, grantedScopes);
        var client = host.GetTestClient();
        var answers = new List<Answer>();

        foreach (var (method, pattern) in MappedRoutes())
        {
            var path = pattern.Replace("{streamId}", "some-stream", StringComparison.Ordinal);
            using var request = new HttpRequestMessage(new HttpMethod(method), path);

            // A body every bodied route will BIND: a malformed one is refused by the framework before
            // this package runs, which is a different answer from the one being driven here. The
            // routes that bind no body at all - the reads, and the configuration document - ignore it.
            request.Content = JsonContent.Create(new
            {
                stream_id = "some-stream",
                status = "enabled",
                subject = new { format = "opaque", id = "subject-1" },
            });

            using var response = await client.SendAsync(request, ct);
            answers.Add(new Answer(method, pattern, (int)response.StatusCode));
        }

        return answers;
    }

    private const string StreamRoute = "/ssf/stream";
    private const string StatusRoute = "/ssf/status";
    private const string AddSubjectRoute = "/ssf/subjects:add";
    private const string RemoveSubjectRoute = "/ssf/subjects:remove";
    private const string VerifyRoute = "/ssf/verify";
    private const string PollRoute = "/ssf/poll/{streamId}";
    private const string DocumentRoute = "/.well-known/ssf-configuration";

    private string _streamId = string.Empty;

    /// <summary>The routes that bind a body, which is where the framework's own refusals live.</summary>
    private List<(string Method, string Pattern, string Path)> BodyBoundRoutes() =>
    [
        ("POST", StreamRoute, "/ssf/stream"),
        ("PATCH", StreamRoute, "/ssf/stream"),
        ("PUT", StreamRoute, "/ssf/stream"),
        ("POST", StatusRoute, "/ssf/status"),
        ("POST", AddSubjectRoute, "/ssf/subjects:add"),
        ("POST", RemoveSubjectRoute, "/ssf/subjects:remove"),
        ("POST", VerifyRoute, "/ssf/verify"),
        ("POST", PollRoute, $"/ssf/poll/{_streamId}"),
    ];

    /// <summary>
    /// The routes this surface maps, as the pair a request is addressed by. Written out rather than
    /// read off the endpoint table, because the table is one of the two things being compared and a
    /// route both sides derive from it cannot disagree with itself.
    /// </summary>
    private static List<(string Method, string Pattern)> MappedRoutes() =>
    [
        ("POST", StreamRoute),
        ("GET", StreamRoute),
        ("PATCH", StreamRoute),
        ("PUT", StreamRoute),
        ("DELETE", StreamRoute),
        ("GET", StatusRoute),
        ("POST", StatusRoute),
        ("POST", AddSubjectRoute),
        ("POST", RemoveSubjectRoute),
        ("POST", VerifyRoute),
        ("POST", PollRoute),

        // Mapped by the same call and deliberately OUTSIDE the group, because discovery must answer
        // before a receiver has credentials. In scope here for exactly that reason: a route excused
        // from the comparison is a route whose document nobody checks, and this one used to publish an
        // inferred 200 while the eleven beside it were being made to state theirs.
        ("GET", DocumentRoute),
    ];

    /// <summary>
    /// The statuses a route publishes, taken from the API description the framework builds - which is
    /// what an OpenAPI document is generated from, and therefore the only place the declaration becomes
    /// something a client author can see.
    /// </summary>
    /// <remarks>
    /// Deliberately NOT the endpoint's raw metadata. Metadata reaching the endpoint and metadata
    /// surviving into a document are two facts, and the second is the one the ticket is about: a
    /// response type the description pipeline discards leaves the endpoint carrying a declaration
    /// nobody downstream ever reads, which reads exactly like a declaration that works.
    /// </remarks>
    private HashSet<int> PublishedBy(string method, string pattern)
    {
        var described = _descriptions
            .SelectMany(group => group.Items)
            .Where(item =>
                string.Equals("/" + item.RelativePath?.Split('?')[0], pattern, StringComparison.Ordinal)
                && string.Equals(item.HttpMethod, method, StringComparison.Ordinal))
            .ToList();

        // Not described is a failure rather than an empty answer, for the reason DeclaredBy states.
        Assert.NotEmpty(described);

        return [.. described.SelectMany(item => item.SupportedResponseTypes)
            .Select(response => response.StatusCode)];
    }

    /// <summary>The statuses a route declares, read back off its own metadata.</summary>
    private HashSet<int> DeclaredBy(string method, string pattern)
    {
        var endpoint = _endpoints.OfType<RouteEndpoint>().FirstOrDefault(candidate =>
            string.Equals(candidate.RoutePattern.RawText, pattern, StringComparison.Ordinal)
            && candidate.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods
                .Contains(method, StringComparer.Ordinal) is true);

        // Not found is a failure rather than an empty answer: an empty set would satisfy the
        // "answers what it declares" half exactly as a correct declaration does.
        Assert.NotNull(endpoint);

        return [.. endpoint.Metadata.OfType<IProducesResponseTypeMetadata>().Select(one => one.StatusCode)];
    }

    private IReadOnlyList<Endpoint> _endpoints = [];

    private IReadOnlyList<ApiDescriptionGroup> _descriptions = [];

    private sealed record Answer(string Method, string Pattern, int StatusCode);

    private async Task<WebApplication> StartAsync(
        Func<HttpContext, string?>? receiverId = null,
        Func<HttpContext, IReadOnlyCollection<string>>? grantedScopes = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddEndpointsApiExplorer();

        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));

        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Issuer,
            EventsSupported = [SomeEvent],
            JwksUri = new Uri($"{Issuer}/jwks"),

            // Long enough that the second verification request inside one test run is throttled by
            // the clock rather than by luck.
            MinVerificationInterval = TimeSpan.FromHours(1),
        });

        builder.Services.Replace(ServiceDescriptor.Singleton<IStreamStore>(
            _ => new RefusingUpdates(new InMemoryStreamStore())));

        builder.Services.AddSingleton(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = receiverId ?? (_ => null),
            GrantedScopesSelector = grantedScopes,
        });

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync();

        _endpoints = app.Services.GetRequiredService<EndpointDataSource>().Endpoints;
        _descriptions = app.Services
            .GetRequiredService<IApiDescriptionGroupCollectionProvider>().ApiDescriptionGroups.Items;
        return app;
    }

    /// <summary>
    /// A store that takes every call except the conditional write, so a change reaches the end of the
    /// retry loop with nothing written - which is the only way the contention answers are reachable
    /// through a real request.
    /// </summary>
    private sealed class RefusingUpdates(IStreamStore inner) : IStreamStore
    {
        public bool Refuse { get; set; }

        public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.TryCreateAsync(stream, cancellationToken);

        public Task<StreamState?> FindAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.FindAsync(receiverId, streamId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAsync(
            string receiverId, CancellationToken cancellationToken = default)
            => inner.ListAsync(receiverId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => inner.ListAllAsync(cancellationToken);

        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => Refuse ? Task.FromResult(false) : inner.UpdateAsync(stream, cancellationToken);

        public Task<bool> DeleteAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }
}
