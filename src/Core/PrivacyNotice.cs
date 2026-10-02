// SPDX-License-Identifier: MIT

using System;
using System.IO;

namespace WhitehatSecurity.Core;

/// <summary>The same privacy policy is shipped offline and published with the source.</summary>
public static class PrivacyNotice
{
    public const string ResourceName = "WhitehatSecurity.PrivacyNotice.md";

    public static string Read()
    {
        using var stream = typeof(PrivacyNotice).Assembly
            .GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException("The embedded privacy policy is missing.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
