// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;
using System.Linq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// An error description reaches the client made only of the characters RFC 6749 (sections 4.1.2.1, 4.2.2.1 and 5.2)
/// allows in error_description, %x20-21 / %x23-5B / %x5D-7E, whatever a refusal quoted from the request, and however
/// the error carrying it was built.
/// </summary>
public class OidcErrorTests
{
    /// <summary>A tab, a NUL, a double quote, a backslash, a no-break space and a letter outside ASCII.</summary>
    private const string Quoted = "a\tb\0c\"d\\e\u00A0f\u00E9";

    /// <summary>Each of those replaced, and every allowed character kept.</summary>
    private const string Allowed = "a?b?c?d?e?f?";

    [Fact]
    public void ADescriptionKeepsOnlyTheAllowedCharacters()
        => Assert.Equal(Allowed, new OidcError(ErrorCodes.InvalidRequest, Quoted).ErrorDescription);

    [Fact]
    public void ADescriptionSetByWithKeepsOnlyTheAllowedCharacters()
    {
        var error = new OidcError(ErrorCodes.InvalidRequest, string.Empty) with { ErrorDescription = Quoted };

        Assert.Equal(Allowed, error.ErrorDescription);
    }

    [Fact]
    public void ADerivedErrorKeepsOnlyTheAllowedCharacters()
    {
        var error = new AuthorizationRequestValidationError(ErrorCodes.InvalidRequest, Quoted, null, ResponseModes.Query);

        Assert.Equal(Allowed, error.ErrorDescription);
    }

    [Fact]
    public void AnAuthorizationErrorBuiltDirectlyKeepsOnlyTheAllowedCharacters()
    {
        var error = new AuthorizationError(new AuthorizationRequest(), ErrorCodes.InvalidRequest, Quoted, ResponseModes.Query, null);

        Assert.Equal(Allowed, error.ErrorDescription);
    }

    [Fact]
    public void EveryAllowedCharacterIsKept()
    {
        var allowed = new string([.. Enumerable.Range(0x20, 0x7F - 0x20)
            .Select(code => (char)code)
            .Where(character => character is not '"' and not '\\')]);

        Assert.Equal(allowed, new OidcError(ErrorCodes.InvalidRequest, allowed).ErrorDescription);
    }
}
