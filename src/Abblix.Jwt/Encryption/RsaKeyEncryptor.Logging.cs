// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Encryption;

partial class RsaKeyEncryptor
{
	[LoggerMessage(
		EventId = LogEvents.Jwt.RsaEncryptionFailed,
		Level = LogLevel.Error,
		Message = "RSA key encryption failed: Algorithm={EncryptionAlgorithm}, KeySize={KeySize} bits, CEK size={ContentEncryptionKeySize} bytes, Theoretical max CEK={MaxContentEncryptionKeySize} bytes")]
	private partial void LogEncryptionFailed(string EncryptionAlgorithm, int KeySize, int ContentEncryptionKeySize, int MaxContentEncryptionKeySize);
}
