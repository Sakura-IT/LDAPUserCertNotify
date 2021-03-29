using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet;
using static LdapForNet.Native.Native;

namespace LDAPUserCertNotify
{
    class Program
    {
        static string host;
        static string authString;
        static string auth;
        static string @base;
        static string filter;
        static string portStr;
        static string who;
        static string password;
        static string sid;

        static int port;

        static void Main(string[] args)
        {
            //SetLDAPParams();

            var cmds = ParseCommandLine(args);
            cmds.TryGetValue("host", out host);
            cmds.TryGetValue("auth", out authString);
            cmds.TryGetValue("base", out @base);
            cmds.TryGetValue("filter", out filter);
            cmds.TryGetValue("port", out portStr);
            cmds.TryGetValue("user", out who);
            cmds.TryGetValue("password", out password);
            int.TryParse(portStr, out var port);
            auth = authString == LdapAuthMechanism.GSSAPI ? LdapAuthMechanism.GSSAPI : LdapAuthMechanism.SIMPLE;
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
                    UsingOpenLdap(auth, host, @base, port, filter).Wait();
                    Thread.Sleep(5000);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            Console.WriteLine("End");
        }

        static void SetLDAPParams()
        {
            Console.Write("host:");
            host = Console.ReadLine();
            Console.Write("authString:");
            authString = Console.ReadLine();
            Console.Write("auth:");
            auth = Console.ReadLine();
            Console.Write("@base:");
            @base = Console.ReadLine();
            Console.Write("filter:");
            filter = Console.ReadLine();
            Console.Write("portStr:");
            portStr = Console.ReadLine();
            Console.Write("who:");
            who = Console.ReadLine();
            Console.Write("password:");
            password = Console.ReadLine();
            Console.Write("sid:");
            sid = Console.ReadLine();
        }

        private static Dictionary<string, string> ParseCommandLine(string[] args)
        {
            var pattern = "^--([^=\"]*)=\"?(.*)\"?$";
            return args.Select(_ => Regex.Matches(_, pattern, RegexOptions.IgnoreCase).Cast<Match>().FirstOrDefault()?.Groups)
                .Where(_ => _ != null)
                .ToDictionary(_ => _[1].Value, _ => _[2].Value);
        }

        private static async Task UsingOpenLdap(string authType, string host, string @base, int port, string filter)
        {
            Console.WriteLine($"{nameof(authType)}:{authType}; {nameof(host)}:{host}; {nameof(@base)}:{@base}; {nameof(port)}:{port}; {nameof(who)}:{who}; {nameof(password)}:{password}; ");
            using (var cn = new LdapConnection())
            {
                cn.Connect(host, port);
		cn.StartTransportLayerSecurity(true); 

                if (authType == LdapAuthMechanism.GSSAPI)
                {
                    await cn.BindAsync();
                }
		/* Perform anonymous bind if not using GSSAPI and password was not provided */
                else if ((authType == LdapAuthMechanism.SIMPLE) && password == null) 
                {
                    cn.Bind(LdapAuthType.Anonymous, new LdapCredential());
                }
                else
                {
                    who = who ?? "cn=read-only-admin,dc=example,dc=com";
                    password = password ?? "password";
                    cn.Bind(LdapAuthMechanism.SIMPLE, who, password);
                }

                IList<LdapEntry> entries;

                if (!string.IsNullOrEmpty(sid))
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

        private static void X509Check()
        {
            //Create new X509 store from local certificate store.
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

            //Output store information.
            Console.WriteLine("Store Information");
            Console.WriteLine("Number of certificates in the store: {0}", store.Certificates.Count);
            Console.WriteLine("Store location: {0}", store.Location);
            Console.WriteLine("Store name: {0} {1}", store.Name, Environment.NewLine);

            //Put certificates from the store into a collection so user can select one.
            X509Certificate2Collection fcollection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection collection = X509Certificate2UI.SelectFromCollection(fcollection, "Select an X509 Certificate", "Choose a certificate to examine.", X509SelectionFlag.SingleSelection);
            X509Certificate2 certificate = collection[0];
            X509Certificate2UI.DisplayCertificate(certificate);

            //Output chain information of the selected certificate.
            X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.Build(certificate);
            Console.WriteLine("Chain Information");
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);

            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
            store.Close();
        }
    }
}
