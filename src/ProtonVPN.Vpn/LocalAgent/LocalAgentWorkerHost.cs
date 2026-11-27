/*
 * Copyright (c) 2026 Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

using System;
using System.IO;
using System.Threading;
using Newtonsoft.Json;
using ProtonVPN.Common.Legacy.Go;
using ProtonVPN.Vpn.Config;
using ProtonVPN.Vpn.LocalAgent.Contracts;

namespace ProtonVPN.Vpn.LocalAgent;

public static class LocalAgentWorkerHost
{
    private sealed class WorkerCommand
    {
        [JsonProperty("cmd")]
        public string Cmd { get; set; } = string.Empty;

        [JsonProperty("clientCertPem")]
        public string? ClientCertPem { get; set; }

        [JsonProperty("clientKeyPem")]
        public string? ClientKeyPem { get; set; }

        [JsonProperty("host")]
        public string? Host { get; set; }

        [JsonProperty("certServerName")]
        public string? CertServerName { get; set; }

        [JsonProperty("bouncing")]
        public string? Bouncing { get; set; }

        [JsonProperty("splitTcp")]
        public bool SplitTcp { get; set; }

        [JsonProperty("netShieldLevel")]
        public int NetShieldLevel { get; set; }

        [JsonProperty("portForwarding")]
        public bool PortForwarding { get; set; }

        [JsonProperty("moderateNat")]
        public bool ModerateNat { get; set; }
    }

    private sealed class WorkerOutput
    {
        [JsonProperty("type")]
        public string Type { get; set; } = string.Empty;

        [JsonProperty("error", NullValueHandling = NullValueHandling.Ignore)]
        public string? Error { get; set; }

        [JsonProperty("raw", NullValueHandling = NullValueHandling.Ignore)]
        public string? Raw { get; set; }
    }

    public static void Run(TextReader input, TextWriter output)
    {
        Environment.CurrentDirectory = AppContext.BaseDirectory;

        object outputLock = new();
        bool isConnected = false;
        Thread? eventThread = null;

        void WriteMessage(WorkerOutput msg)
        {
            string line = JsonConvert.SerializeObject(msg, Formatting.None);
            lock (outputLock)
            {
                output.WriteLine(line);
                output.Flush();
            }
        }

        try
        {
            while (input.ReadLine() is { } line)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                WorkerCommand? cmd;
                try
                {
                    cmd = JsonConvert.DeserializeObject<WorkerCommand>(line);
                }
                catch
                {
                    continue;
                }

                if (cmd is null)
                {
                    continue;
                }

                if (string.Equals(cmd.Cmd, "connect", StringComparison.OrdinalIgnoreCase))
                {
                    if (isConnected)
                    {
                        continue;
                    }

                    string featuresJson = JsonConvert.SerializeObject(new FeaturesContract
                    {
                        Bouncing = cmd.Bouncing ?? string.Empty,
                        SplitTcp = cmd.SplitTcp,
                        NetShieldLevel = cmd.NetShieldLevel,
                        PortForwarding = cmd.PortForwarding,
                        RandomizedNat = !cmd.ModerateNat,
                    }, Formatting.None, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore,
                    });

                    using GoString clientCertPem = (cmd.ClientCertPem ?? string.Empty).ToGoString();
                    using GoString clientKeyPem = (cmd.ClientKeyPem ?? string.Empty).ToGoString();
                    using GoString serverCaPem = VpnCertConfig.ROOT_CA.ToGoString();
                    using GoString host = (cmd.Host ?? string.Empty).ToGoString();
                    using GoString certServerName = (cmd.CertServerName ?? string.Empty).ToGoString();
                    using GoString goFeatures = featuresJson.ToGoString();

                    string error = PInvoke.Connect(
                        clientCertPem,
                        clientKeyPem,
                        serverCaPem,
                        host,
                        certServerName,
                        goFeatures,
                        connectivity: true,
                        keepAliveSeconds: 60,
                        keepAliveMaxCount: 0).ConvertToString();

                    WriteMessage(new WorkerOutput
                    {
                        Type = "connect_result",
                        Error = error,
                    });

                    if (string.IsNullOrEmpty(error))
                    {
                        isConnected = true;
                        eventThread = new Thread(() =>
                        {
                            while (true)
                            {
                                GoBytes ev;
                                try
                                {
                                    ev = PInvoke.GetEvent();
                                }
                                catch
                                {
                                    break;
                                }

                                string raw = ev.ConvertToString();
                                if (string.IsNullOrEmpty(raw))
                                {
                                    break;
                                }

                                WriteMessage(new WorkerOutput
                                {
                                    Type = "event",
                                    Raw = raw,
                                });
                            }
                        })
                        {
                            IsBackground = true,
                            Name = "LocalAgentWorkerEventDrain",
                        };
                        eventThread.Start();
                    }
                }
                else if (string.Equals(cmd.Cmd, "set_features", StringComparison.OrdinalIgnoreCase))
                {
                    if (!isConnected)
                    {
                        continue;
                    }

                    string featuresJson = JsonConvert.SerializeObject(new FeaturesContract
                    {
                        SplitTcp = cmd.SplitTcp,
                        NetShieldLevel = cmd.NetShieldLevel,
                        PortForwarding = cmd.PortForwarding,
                        RandomizedNat = !cmd.ModerateNat,
                    }, Formatting.None, new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore,
                    });

                    using GoString goFeatures = featuresJson.ToGoString();
                    PInvoke.SetFeatures(goFeatures);
                }
                else if (string.Equals(cmd.Cmd, "close", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
            }
        }
        finally
        {
            if (isConnected)
            {
                try
                {
                    PInvoke.Close();
                }
                catch
                {
                }

                try
                {
                    eventThread?.Join(TimeSpan.FromMilliseconds(2000));
                }
                catch
                {
                }
            }

            try
            {
                WriteMessage(new WorkerOutput { Type = "exited" });
            }
            catch
            {
            }
        }
    }
}
