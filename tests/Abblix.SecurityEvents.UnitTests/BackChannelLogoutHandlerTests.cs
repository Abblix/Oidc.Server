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
using System.Net.Mime;
using Abblix.SecurityEvents.BackChannelLogout;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The intake: what a back-channel logout request must look like to be read at all
/// (OpenID Connect Back-Channel Logout 1.0 Section 2.5), and what the answer is in each outcome
/// (Section 2.8).
/// </summary>
public class BackChannelLogoutHandlerTests
{
    private const string Issuer = "https://op.example.com";
    private const string Token = "header.payload.signature";

    /// <summary>
    /// Accepts whatever it is given and reports the token it was asked about, so a case can say
    /// which string reached validation rather than only that one did.
    /// </summary>
    private sealed class StubValidator(string? refuseWith = null) : ILogoutTokenValidator
    {
        public string? Received { get; private set; }

        public Task<LogoutNotification> ValidateAsync(
            string logoutToken, CancellationToken cancellationToken = default)
        {
            Received = logoutToken;

            return refuseWith is null
                ? Task.FromResult(new LogoutNotification(Issuer, "user-1", "session-1", "jti-1"))
                : throw new LogoutTokenValidationException(refuseWith);
        }
    }

    private sealed class RecordingSink(string? refuseWith = null) : ILogoutNotificationSink
    {
        public List<LogoutNotification> Consumed { get; } = [];

        public Task<string?> ConsumeAsync(
            LogoutNotification notification, CancellationToken cancellationToken = default)
        {
            Consumed.Add(notification);
            return Task.FromResult(refuseWith);
        }
    }

    private static BackChannelLogoutHandler Handler(
        StubValidator validator, ILogoutNotificationSink sink)
        => new(NullLogger<BackChannelLogoutHandler>.Instance, validator, sink);

    /// <summary>Keeps EVERY line this handler wrote: its level, its identifier and its message.</summary>
    /// <remarks>
    /// Every line, not only the warnings: a test asserting "no warning" on the success path is
    /// satisfied by a handler that chatters at Information, so it cannot tell silence from
    /// something quieter than the thing it names.
    /// </remarks>
    private sealed class RecordingLogger : ILogger<BackChannelLogoutHandler>
    {
        public List<(LogLevel Level, EventId EventId, string Message)> Lines { get; } = [];

        public IReadOnlyList<(EventId EventId, string Message)> Warnings =>
            [.. Lines.Where(line => line.Level == LogLevel.Warning).Select(line => (line.EventId, line.Message))];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Lines.Add((logLevel, eventId, formatter(state, exception)));
        }
    }

    [Fact]
    public async Task AWellFormedRequest_IsAccepted_AndReachesTheSink()
    {
        var validator = new StubValidator();
        var sink = new RecordingSink();

        var result = await Handler(validator, sink).HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded,
            $"logout_token={Token}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Null(result.Error);
        Assert.Equal(Token, validator.Received);
        Assert.Equal(Issuer, Assert.Single(sink.Consumed).Issuer);
    }

    /// <summary>
    /// Section 2.5: "The POST body MAY contain other values in addition to logout_token. Values
    /// that are not understood by the implementation MUST be ignored." A stricter reading refuses
    /// a conformant provider, and only over a parameter this endpoint has no opinion about.
    /// </summary>
    [Fact]
    public async Task ParametersItDoesNotUnderstand_AreIgnored()
    {
        var validator = new StubValidator();
        var sink = new RecordingSink();

        var result = await Handler(validator, sink).HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded,
            $"state=abc&logout_token={Token}&something_new=1",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Equal(Token, validator.Received);
    }

    /// <summary>
    /// The content type is a media type, so a charset parameter beside it is still the encoding
    /// Section 2.5 requires - refusing over it would fail a conformant provider.
    /// </summary>
    [Fact]
    public async Task AContentTypeCarryingACharset_IsStillAccepted()
    {
        var validator = new StubValidator();

        var result = await Handler(validator, new RecordingSink()).HandleAsync(
            $"{MediaTypeNames.Application.FormUrlEncoded}; charset=UTF-8",
            $"logout_token={Token}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
    }

    [Theory]
    [InlineData("application/json")]
    [InlineData(null)]
    public async Task AnotherContentType_IsRefused(string? contentType)
    {
        var validator = new StubValidator();
        var sink = new RecordingSink();

        var result = await Handler(validator, sink).HandleAsync(
            contentType, $"logout_token={Token}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Equal(BackChannelLogoutError.InvalidRequest, result.Error!.Error);

        // Nothing downstream ran: a body this endpoint cannot read is not a token to validate.
        Assert.Null(validator.Received);
        Assert.Empty(sink.Consumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("state=abc")]
    [InlineData("logout_token=")]
    public async Task AMissingToken_IsRefused(string body)
    {
        var validator = new StubValidator();

        var result = await Handler(validator, new RecordingSink()).HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded, body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null(validator.Received);
    }

    /// <summary>
    /// Section 2.6: "If any of the validation steps fails, reject the Logout Token and return an
    /// HTTP 400 Bad Request error." The reason travels in the description, which is what
    /// Section 2.8 says the body is for.
    /// </summary>
    [Fact]
    public async Task ARefusedToken_AnswersBadRequest_CarryingTheReason()
    {
        var validator = new StubValidator("The Logout Token carries a nonce, which a Logout Token must not.");
        var sink = new RecordingSink();

        var result = await Handler(validator, sink).HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded,
            $"logout_token={Token}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Contains("nonce", result.Error!.Description);
        Assert.Empty(sink.Consumed);
    }

    /// <summary>
    /// Section 2.8 makes the failed logout the RP's own statement - "if the logout request was
    /// invalid or the logout failed" - so a sink that could not end the sessions is answered as a
    /// failure rather than acknowledged.
    /// </summary>
    [Fact]
    public async Task ASinkThatCouldNotEndTheSessions_AnswersBadRequest()
    {
        var result = await Handler(new StubValidator(), new RecordingSink("The session store is unreachable."))
            .HandleAsync(
                MediaTypeNames.Application.FormUrlEncoded,
                $"logout_token={Token}",
                TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Contains("unreachable", result.Error!.Description);
    }

    /// <summary>
    ///     Every way of refusing is recorded here, not only reported to the provider.
    /// </summary>
    /// <remarks>
    ///     The description travels back in the response, which Section 2.8 asks for - but the
    ///     provider is the other party, and a receiver that kept nothing leaves its operator an
    ///     even stream of 400s with no way in. A provider signing with untrusted keys and a
    ///     receiver pointed at the wrong key document look identical without it.
    ///
    ///     A theory over all four paths rather than one case, because each reaches the recording
    ///     through a different branch. It cannot see a FIFTH path - what makes a later one recorded
    ///     is that the shaping and the recording are one method, so a refusal that skipped it would
    ///     have to be built by hand.
    /// </remarks>
    [Theory]
    [InlineData("application/json", "logout_token=x", "Section 2.5 requires")]
    [InlineData(MediaTypeNames.Application.FormUrlEncoded, "other=x", "carries no 'logout_token'")]
    [InlineData(MediaTypeNames.Application.FormUrlEncoded, "logout_token=" + Token, "refused by the validator")]
    [InlineData(MediaTypeNames.Application.FormUrlEncoded, "logout_token=" + Token, "refused by the sink")]
    public async Task EveryRefusal_IsRecorded(string contentType, string body, string expected)
    {
        var logger = new RecordingLogger();
        var validator = expected.Contains("validator", StringComparison.Ordinal)
            ? new StubValidator("refused by the validator")
            : new StubValidator();
        var sink = new RecordingSink(
            expected.Contains("sink", StringComparison.Ordinal) ? "refused by the sink" : null);

        var handler = new BackChannelLogoutHandler(logger, validator, sink);
        var result = await handler.HandleAsync(contentType, body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);

        var (eventId, warning) = Assert.Single(logger.Warnings);
        Assert.Contains(expected, warning, StringComparison.Ordinal);
        Assert.Contains(result.Error!.Error, warning, StringComparison.Ordinal);

        // The number is the contract a runbook keys off, so it is asserted rather than the message:
        // the text may be reworded, the identifier may not move.
        Assert.Equal(LogEvents.BackChannelLogout.RequestRefused, eventId.Id);
    }

    /// <summary>Success is silent at EVERY level, so the refusals stay findable among ordinary traffic.</summary>
    /// <remarks>
    /// Asserting the absence of a warning would leave the handler free to write a line per accepted
    /// logout at Information - which is the volume this endpoint would produce most of, and the
    /// noise a refusal has to be found in.
    /// </remarks>
    [Fact]
    public async Task AnAcceptedRequest_RecordsNoWarning()
    {
        var logger = new RecordingLogger();
        var handler = new BackChannelLogoutHandler(logger, new StubValidator(), new RecordingSink());

        var result = await handler.HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded,
            "logout_token=" + Token,
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Empty(logger.Lines);
    }
}
