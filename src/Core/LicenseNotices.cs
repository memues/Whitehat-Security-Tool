// SPDX-License-Identifier: MIT

using System;
using System.IO;

namespace WhitehatSecurity.Core;

/// <summary>License and dependency notices shipped inside the standalone executable.</summary>
public static class LicenseNotices
{
    public const string LicenseResourceName = "WhitehatSecurity.License.txt";
    public const string ThirdPartyResourceName = "WhitehatSecurity.ThirdPartyNotices.txt";

    public static string Read()
        => "Application license" + Environment.NewLine + Environment.NewLine
            + ReadResource(LicenseResourceName).TrimEnd()
            + Environment.NewLine + Environment.NewLine
            + "Third-party notices" + Environment.NewLine + Environment.NewLine
            + ReadResource(ThirdPartyResourceName);

    private static string ReadResource(string resourceName)
    {
        using var stream = typeof(LicenseNotices).Assembly
            .GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"The embedded notice {resourceName} is missing.");
        using var reader = new StreamReader(stream);
        var text = reader.ReadToEnd();
        if (string.IsNullOrWhiteSpace(text))
            throw new InvalidOperationException($"The embedded notice {resourceName} is empty.");
        return text;
    }
}
