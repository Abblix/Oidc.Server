// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Licensing;
using Xunit;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A license is configuration a host reads from a file, a mounted secret or a YAML block, any of which may end the
/// value with a line break. The break is not part of the token, so the license loads with it.
/// </summary>
public class LicenseLineBreakTests
{
	[Theory]
	[InlineData("\n")]
	[InlineData("\r\n")]
	[InlineData(" \n")]
	public async Task ALicenseEndingInALineBreak_Loads(string ending)
	{
		await TestLicense.Loaded;

		var exception = await Record.ExceptionAsync(() => LicenseLoader.LoadAsync(TestLicense.Jwt + ending));

		Assert.Null(exception);
	}
}
