// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.ProtectedResources;

namespace Abblix.Oidc.Client.UnitTests.Features.ProtectedResources;

/// <summary>
/// Reading the refusal a resource server sends back.
/// </summary>
/// <remarks>
/// Worth its own tests because the distinction it carries is the one a caller acts on: a rejected token
/// means sign in again, an insufficient one means ask for more scope, and signing in again with the same
/// scopes will fail identically forever.
/// </remarks>
public class BearerChallengeTests
{
    private static BearerChallenge? Read(params string[] headers)
    {
        using var response = new HttpResponseMessage();

        foreach (var header in headers)
            response.Headers.TryAddWithoutValidation("WWW-Authenticate", header);

        return BearerChallenge.Read(response.Headers.WwwAuthenticate);
    }

    /// <summary>
    /// A response carrying no Bearer challenge yields nothing, rather than an empty challenge that reads as
    /// one the server sent.
    /// </summary>
    [Fact]
    public void NoBearerChallengeIsNoChallenge()
    {
        Assert.Null(Read());
        Assert.Null(Read("Basic realm=\"orders\""));
    }

    /// <summary>
    /// The four parameters RFC 6750 section 3 defines are read.
    /// </summary>
    [Fact]
    public void TheDefinedParametersAreRead()
    {
        var challenge = Read(
            "Bearer realm=\"orders\", error=\"insufficient_scope\", "
            + "error_description=\"needs more\", error_uri=\"https://api.example.com/errors/scope\", "
            + "scope=\"orders.read orders.write\"");

        Assert.NotNull(challenge);
        Assert.Equal("orders", challenge.Realm);
        Assert.Equal(ErrorCodes.InsufficientScope, challenge.Error);
        Assert.Equal("needs more", challenge.ErrorDescription);
        Assert.Equal("https://api.example.com/errors/scope", challenge.ErrorUri?.OriginalString);
        Assert.Equal(["orders.read", "orders.write"], challenge.Scope);
        Assert.False(challenge.IsMalformed);
    }

    /// <summary>
    /// Scope values are case-sensitive, so their case survives.
    /// </summary>
    [Fact]
    public void ScopeCaseIsPreserved()
    {
        var challenge = Read("Bearer scope=\"Orders.Read\"");

        Assert.Equal(["Orders.Read"], challenge?.Scope);
    }

    /// <summary>
    /// RFC 6750 section 3 says each of these "MUST NOT appear more than once". A repeat leaves the value
    /// unset and marks the challenge, so a caller reads "the server did not say" rather than one of the two
    /// things it did say.
    /// </summary>
    [Fact]
    public void ARepeatedParameterIsNotResolvedInFavourOfEither()
    {
        var challenge = Read("Bearer realm=\"one\", realm=\"two\"");

        Assert.NotNull(challenge);
        Assert.Null(challenge.Realm);
        Assert.True(challenge.IsMalformed);
    }

    /// <summary>
    /// An extension parameter is tolerated. RFC 6750 section 3 defines four and leaves the grammar open, so
    /// refusing the whole challenge over a fifth would throw away the ones that were understood.
    /// </summary>
    [Fact]
    public void AnUnknownParameterIsTolerated()
    {
        var challenge = Read("Bearer error=\"invalid_token\", nonce=\"abc\"");

        Assert.NotNull(challenge);
        Assert.Equal(ErrorCodes.InvalidToken, challenge.Error);
        Assert.False(challenge.IsMalformed);
    }

    /// <summary>
    /// A challenge naming no error leaves it unset rather than assuming the commonest one. The server said
    /// nothing, and inventing <c>invalid_token</c> here would send a caller to re-authenticate over a
    /// refusal that may have been about scope.
    /// </summary>
    [Fact]
    public void AnAbsentErrorIsNotInvented()
    {
        var challenge = Read("Bearer realm=\"orders\"");

        Assert.NotNull(challenge);
        Assert.Null(challenge.Error);
    }

    /// <summary>
    /// A comma inside a quoted description does not cut it in half, which is exactly where a server puts
    /// one.
    /// </summary>
    [Fact]
    public void ACommaInsideAValueIsNotASeparator()
    {
        var challenge = Read("Bearer error=\"invalid_token\", error_description=\"expired, sign in again\"");

        Assert.Equal("expired, sign in again", challenge?.ErrorDescription);
    }

    /// <summary>
    /// A challenge for another scheme alongside the Bearer one is left alone: a server offering an
    /// alternative this client cannot use has done nothing wrong.
    /// </summary>
    [Fact]
    public void AnotherSchemeBesideItIsIgnored()
    {
        var challenge = Read("Basic realm=\"legacy\"", "Bearer error=\"invalid_token\"");

        Assert.Equal(ErrorCodes.InvalidToken, challenge?.Error);
    }

    /// <summary>
    /// An error_uri that is not a URI is dropped rather than carried as text, so a caller that follows it
    /// has something it can follow.
    /// </summary>
    [Fact]
    public void AnUnusableErrorUriIsDropped()
    {
        var challenge = Read("Bearer error_uri=\"not a uri\"");

        Assert.NotNull(challenge);
        Assert.Null(challenge.ErrorUri);
    }
}
