using System;
using System.Net;
using System.Net.Sockets;
using System.DirectoryServices;
using System.Diagnostics;

namespace SharpAdidnsdump
{
    class Program
    {
        public static bool verify_ip(string dns_server)
        {
            //校验dns_server输入值是否是ip地址
            System.Net.IPAddress ipAddress;
            if (System.Net.IPAddress.TryParse(dns_server, out ipAddress))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        static void Main(string[] args)
        {
            String dc_address = "";
            String domain_name = "";
            String RootDN = "";
            string zone_subfolder = "";
            string dns_server = "";
            bool dns_default_method = true;

            if (args == null || args.Length <= 0)
            {
                Console.WriteLine("[+] 可在域外机器使用，配合make_token即可。");
                Console.WriteLine("[+] usage  : SharpAdidnsdump.exe dc-address domain-name [RootDN] [zone_subfolder] [dns_server]");
                Console.WriteLine("[+] example: SharpAdidnsdump.exe 10.10.10.10 example.com default default default");
                Console.WriteLine("[+] example: SharpAdidnsdump.exe 10.10.10.10 example.com DC=ForestDnsZones ,CN=MicrosoftDNS, 10.10.10.15");
                return;
            }
            else
            {
                dc_address = args[0].ToLower();
                domain_name = args[1].ToLower();
                RootDN = args[2];
                zone_subfolder = args[3];
                dns_server = args[4].ToLower();
                Console.WriteLine("[1] DC Address              is: {0}", dc_address);
                Console.WriteLine("[2] Domain Name             is: {0}", domain_name);
                Console.WriteLine("[3] Root Distinguished Name is: {0}", RootDN);
                Console.WriteLine("[4] DNS Zone Subfolder      is: {0}", zone_subfolder);
                Console.WriteLine("[5] DNS Server              is: {0}", dns_server);
                Console.WriteLine();

            }

            //========================================校验参数start========================================
            //校验dc-address
            if (verify_ip(dc_address) == false)
            {
                Console.WriteLine("[-] dc-address参数输入错误,程序退出.");
                Environment.Exit(1);
            }

            //校验dns_server输入值
            if (dns_server == "default") 
            {
                //使用系统api和系统dns解析机器ip
                dns_default_method = true;
            }
            else if(verify_ip(dns_server) == true)
            {
                //使用nslookup工具及自定义dns地址解析机器ip
                dns_default_method = false;
            }
            else
            {
                Console.WriteLine("[-] dns_server参数输入错误,程序退出.");
                Environment.Exit(1);
            }
            //========================================校验参数end========================================

            try
            {

                Console.WriteLine("[+] Running enumeration against {0}", dc_address);

                if(RootDN == "default") 
                { 
                    RootDN = "DC=DomainDnsZones"; 
                }
                else if(RootDN == "none")
                {
                    RootDN = "";
                }
                

                String domain_local = domain_name;
                Console.WriteLine("[+] domain-name is {0}", domain_local);
                String domain_path = "";

                foreach (String domain_path_r in domain_local.Split('.'))
                {
                    domain_path += ",DC=" + domain_path_r;
                }

                RootDN += domain_path;

                if(RootDN.StartsWith(","))
                {
                    RootDN = RootDN.Substring(1, RootDN.Length - 1);
                }

                Console.WriteLine("[+] Running enumeration against {0}", "LDAP://" + dc_address + "/" + RootDN);

                DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + dc_address + "/" + RootDN);
                
                rootEntry.AuthenticationType = AuthenticationTypes.Delegation;
                DirectorySearcher searcher = new DirectorySearcher(rootEntry);

                //find domains
                var queryFormat = "(&(objectClass=DnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))";
                searcher.Filter = queryFormat;
                searcher.SearchScope = SearchScope.Subtree;

                foreach (SearchResult result in searcher.FindAll())
                {
                    String domain = (result.Properties["DC"].Count > 0 ? result.Properties["DC"][0].ToString() : string.Empty);
                    //String domain = domain_name;
                    Console.WriteLine();
                    Console.WriteLine();
                    Console.WriteLine("[+] Domain: {0}", domain);
                    Console.WriteLine();

                    if(zone_subfolder == "default")
                    {
                        zone_subfolder = ",CN=microsoftdns,";
                    }

                    DirectoryEntry rootEntry_d = new DirectoryEntry("LDAP://" + dc_address + "/DC=" + result.Properties["DC"][0].ToString() + zone_subfolder + RootDN);

                    rootEntry_d.AuthenticationType = AuthenticationTypes.Delegation;
                    DirectorySearcher searcher_h = new DirectorySearcher(rootEntry_d);

                    //find hosts
                    queryFormat = "(&(!(objectClass=DnsZone))(!(DC=@))(!(DC=*arpa))(!(DC=*DNSZones)))";
                    searcher_h.Filter = queryFormat;
                    searcher_h.SearchScope = SearchScope.Subtree;

                    foreach (SearchResult result_h in searcher_h.FindAll())
                    {
                        String target = "";

                        if (result_h.Properties["DC"].Count > 0)
                        {
                            target = result_h.Properties["DC"][0].ToString();
                        }
                        else
                        {
                            //Hidden entry
                            String path = result_h.Path;
                            target = (path.Substring(path.IndexOf("LDAP://" + dc_address + "/"), path.IndexOf(","))).Split('=')[1];
                        }

                        if (!target.EndsWith("."))
                            target += "." + domain;

                        Boolean tombstoned = result_h.Properties["dNSTombstoned"].Count > 0 ? (Boolean)result_h.Properties["dNSTombstoned"][0] : false;

                        try
                        {
                            if(dns_default_method == true)
                            {
                                IPHostEntry hostInfo = Dns.GetHostEntry(target);
                                foreach (IPAddress result_ip in hostInfo.AddressList)
                                {
                                    Console.WriteLine("[+] Host {0} {1}", target, result_ip);
                                }
                            }
                            else if (dns_default_method == false)
                            {
                                Process process = new Process();
                                process.StartInfo.FileName = "cmd.exe";
                                process.StartInfo.Arguments = "/c" + "nslookup " + target + " " + dns_server;
                                process.StartInfo.UseShellExecute = false;   //是否使用操作系统shell启动 
                                process.StartInfo.CreateNoWindow = false;   //是否在新窗口中启动该进程的值 (不显示程序窗口)
                                process.Start();
                                process.WaitForExit();  //等待程序执行完退出进程
                                process.Close();
                            }
                            
                        }
                        catch (Exception e)
                        {
                            if (tombstoned)
                            {
                                Console.WriteLine("[-] Host {0} Tombstoned", target);
                                Console.WriteLine(e.Message);
                            }
                            else
                            {
                                Console.WriteLine("[!] DNS Query with target : {0} failed", target);
                            }
                        }
                    }
                }

                Console.WriteLine();
                Console.WriteLine("[+] SharpAdidnsdump end");
                Console.WriteLine();
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error retriving data : {0}", e.Message);
                return;
            }

        }
    }
}

