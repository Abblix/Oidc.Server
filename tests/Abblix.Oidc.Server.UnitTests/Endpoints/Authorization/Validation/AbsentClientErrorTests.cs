// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization.Validation;

/// <summary>
/// The authorization endpoint's refusal of an absent client: an identifier no store holds is an unauthorized client,
/// and a client identifier URL whose document was refused or could not be had is an invalid one
/// (draft-ietf-oauth-client-id-metadata-document sections 5 and 6), never sent to a redirect URI (section 6.1).
/// </summary>
public class AbsentClientErrorTests
{
    [Theory]
    [InlineData(ClientAbsenceReason.Unknown, ErrorCodes.UnauthorizedClient)]
    [InlineData(ClientAbsenceReason.Refused, ErrorCodes.InvalidClient)]
    [InlineData(ClientAbsenceReason.TemporarilyUnavailable, ErrorCodes.InvalidClient)]
    public void AnAbsentClient_IsRefusedByWhyItIsAbsent_WithoutARedirect(ClientAbsenceReason reason, string error)
    {
        var refusal = ErrorFactory.AbsentClient(new ClientAbsence(reason));

        Assert.Equal(error, refusal.Error);
        Assert.Null(refusal.RedirectUri);
    }
}
