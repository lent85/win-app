/*
 * Copyright (c) 2023 Proton AG
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
using ProtonVPN.Native.PInvoke;
using ProtonVPN.Service.Start;
using ProtonVPN.Vpn.LocalAgent;

namespace ProtonVPN.Service
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0 && string.Equals(args[0], "--local-agent-worker", StringComparison.OrdinalIgnoreCase))
            {
                Kernel32.SetDefaultDllDirectories(Kernel32.SetDefaultDllDirectoriesFlags.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                LocalAgentWorkerHost.Run(Console.In, Console.Out);
                return;
            }

            Bootstrapper bootstrapper = new();
            bootstrapper.Initialize();
        }
    }
}