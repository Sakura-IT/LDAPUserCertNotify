﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet;
using static LdapForNet.Native.Native;

namespace LDAPUserCertNotify
{
    class Program
    {
        static void Main(string[] args)
        {
            var cmds = ParseCommandLine(args);
            cmds.TryGetValue("host", out var host);
            cmds.TryGetValue("auth", out var authString);
            cmds.TryGetValue("base", out var @base);
            cmds.TryGetValue("filter", out var filter);
            cmds.TryGetValue("port", out var portStr);
            int.TryParse(portStr, out var port);
            var auth = authString == LdapAuthMechanism.GSSAPI ? LdapAuthMechanism.GSSAPI : LdapAuthMechanism.SIMPLE;
            host = host ?? "ldap.forumsys.com";
            @base = @base ?? "dc=example,dc=com";
            filter = filter ?? "(objectclass=*)";
            port = port > 0 ? port : 389;

            try
            {
                var token = new CancellationTokenSource();
                Console.CancelKeyPress += (sender, eventArgs) => token.Cancel();
                while (!token.IsCancellationRequested)
                {
                    UsingOpenLdap(auth, host, @base, port, filter, cmds).Wait();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            Console.WriteLine("End");
        }

        private static Dictionary<string, string> ParseCommandLine(string[] args)
        {
            var pattern = "^--([^=\"]*)=\"?(.*)\"?$";
            return args.Select(_ => Regex.Matches(_, pattern, RegexOptions.IgnoreCase).Cast<Match>().FirstOrDefault()?.Groups)
                .Where(_ => _ != null)
                .ToDictionary(_ => _[1].Value, _ => _[2].Value);
        }

        private static async Task UsingOpenLdap(string authType, string host, string @base, int port, string filter, IDictionary<string, string> cmds)
        {
            Console.WriteLine($"{nameof(authType)}:{authType}; {nameof(host)}:{host}; {nameof(@base)}:{@base}; {nameof(port)}:{port} ");
            using (var cn = new LdapConnection())
            {
                cn.Connect(host, port);
                if (authType == LdapAuthMechanism.GSSAPI)
                {
                    await cn.BindAsync();
                }
                else
                {
                    cmds.TryGetValue("who", out var who);
                    cmds.TryGetValue("password", out var password);
                    who = who ?? "cn=read-only-admin,dc=example,dc=com";
                    password = password ?? "password";
                    cn.Bind(LdapAuthMechanism.SIMPLE, who, password);
                }

                IList<LdapEntry> entries;

                if (cmds.TryGetValue("sid", out var sid))
                {
                    entries = await cn.SearchBySidAsync(@base, sid);
                }
                else
                {
                    var rootDse = cn.GetRootDse();
                    PrintEntry(rootDse);
                    var searchRequest = new SearchRequest(@base, filter,
                        LdapSearchScope.LDAP_SCOPE_SUBTREE)
                    {
                        AttributesOnly = false,
                        TimeLimit = TimeSpan.Zero,
                        Controls =
                        {
                            new PageResultRequestControl(500)
                            {
                                IsCritical = true
                            }

                        }
                    };
                    var searchResponse = ((SearchResponse)(await cn.SendRequestAsync(searchRequest)));
                    entries = searchResponse.Entries.Select(_ => _.ToLdapEntry()).ToList();
                }
                foreach (var ldapEntry in entries)
                {
                    PrintEntry(ldapEntry);
                }
            }
        }

        private static void PrintEntry(LdapEntry entry)
        {
            if (entry == null)
            {
                return;
            }
            Console.WriteLine($"dn: {entry.Dn}");
            foreach (var pair in entry.Attributes.SelectMany(_ => _.Value.Select(x => new KeyValuePair<string, string>(_.Key, x))))
            {
                Console.WriteLine($"{pair.Key}: {pair.Value}");
            }
            Console.WriteLine();
        }
    }
}
