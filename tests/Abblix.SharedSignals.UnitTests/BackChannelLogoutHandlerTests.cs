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
using Abblix.SharedSignals.Receiver.BackChannelLogout;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

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
        StubValidator validator, ILogoutNotificationSink sink) => new(validator, sink);

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
}
