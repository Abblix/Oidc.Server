// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Names a stored device authorization without carrying its device code: the key the record is stored under.
/// </summary>
/// <remarks>
/// The verification side finds a record by the user code the user typed and then has to decide on it, so it needs
/// some way back to the record. The device code would do, and it is what this replaces: kept under the user code it
/// sat in the store's values, where whoever could read them could redeem the tokens once the user approved. The
/// storage key is derived from the device code one way, so it leads to the record and not to the code.
/// </remarks>
/// <param name="Key">The key the record is stored under, as the storage composed it.</param>
public readonly record struct DeviceAuthorizationReference(string Key);
