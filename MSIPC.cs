using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using SmallTool_MSIPC.Models;
using System.Xml;
using System.Linq;
using System.Configuration;
using ConsoleTables;

namespace SmallTool_MSIPC
{
    public class MSIPC
    {
        private MSIPC_Response result = new MSIPC_Response();
        
        private readonly string ProgramLocation = System.AppDomain.CurrentDomain.BaseDirectory;
        private readonly static Handler Handler = new Handler();
        private string BaseLocation;
        private bool AIPInstalledFlag = false;
        private MSIPC_Rules Rule = new MSIPC_Rules();
        private MSIPC_BasicLogInfo BasicInfo = new MSIPC_BasicLogInfo();

        //flag area
        bool MachineActivationFlag = false;
        bool ServiceDiscoveryFlag = false;
        bool UserIdentityFlag = false;
        bool TemplateFlag = false;

        private List<string> CommonHTTPResponse = ConfigurationManager.AppSettings["CommonHTTPResponse"].Replace(" ","").Split(',').ToList();

        public MSIPC_Response Analyse(string Location) 
        {
            result.Flag = true;
            Handler.InitializeLogFile();
            

            //initialize MSIPC location
            BaseLocation = Handler.LocationValidator(Location, Rule.LogOnly);

            if (BaseLocation.Length < 1)
            {
                result.Flag = false;
                result.ErrMessage = "Not a valid MSIPC or MSIPC log path";
                return result;
            }

            //initialize rule
            Rule = Handler.DeserializeRules(ProgramLocation);

            if (Rule.Mode < 1 || Rule.Mode > 4)
            {
                result.ErrMessage = "Invalid Mode in rule";
                return result;
            }

            Rule.Initialize();

            Handler.TxtLogger(Handler.Serialize(Rule));

            //cert analyse
            if (Rule.CertAnalyse && !Rule.LogOnly)
            {
                CertAnalyse();
            }

            //log analyse
            if (Rule.LogAnalyse)
            {
                string[] MSIPCLogs;
                if (!Rule.LogOnly)
                {
                    MSIPCLogs = Directory.GetFiles(BaseLocation + "Logs", "*.ipclog");
                }
                else
                {
                    MSIPCLogs = Directory.GetFiles(BaseLocation, "*.ipclog");
                }

                List<string> ResponseCode;
                //initialize response
                if (Rule.ResponseType.ToLower() == "include")
                {
                    ResponseCode = Rule.ResponseCodeList.ToList();
                }
                else if (Rule.ResponseType.ToLower() == "exclude")
                {
                    ResponseCode = CommonHTTPResponse.Except(Rule.ResponseCodeList.ToList()).ToList();
                }
                else
                {
                    result.ErrMessage = "Invalid Response Type";
                    return result;
                }
                Handler.TxtLogger(Handler.Serialize(ResponseCode));

                if (MSIPCLogs.Length > 0) 
                {
                    foreach (string LogPath in MSIPCLogs)
                    {

                        //initialize flags
                        MachineActivationFlag = false;
                        ServiceDiscoveryFlag = false;
                        UserIdentityFlag = false;
                        TemplateFlag = false;

                        Handler.TxtLogger(LogPath.Split('\\')[^1]);

                        //open file
                        string[] RawContent = File.ReadAllLines(LogPath).ToArray();
                        string LogFileName = LogPath.Split('\\')[^1];
                        Console.WriteLine("\n\n++++++++++  " + LogFileName + "  ++++++++++");

                        //initially parse log
                        List<string[]> ParsedContent = ParseMSIPCLog(RawContent);

                        LogBasicAnalyse(ParsedContent, ResponseCode, LogFileName);

                        if (Rule.Bootstrap)
                        {
                            BootstrapAnalyse(ParsedContent, LogFileName);
                        }
                        if (Rule.RAC_CLC)
                        {
                            RACAnalyse(ParsedContent, LogFileName);
                        }
                        if (Rule.Template)
                        {

                        }
                        if (Rule.EUL)
                        {

                        }
                        Console.WriteLine("++++++++++  " + LogFileName + "  ++++++++++\n\n");
                    }

                    //conclusion display part

                    //bootstrap info
                    if (Rule.Bootstrap)
                    {
                        //if (AIPInstalledFlag)
                        //{
                        //    Console.WriteLine("\nAIP client is installed");
                        //}
                    }
                }
            }

            return result;
        }

        private void CertAnalyse()
        {
            string[] RACs = Directory.GetFiles(BaseLocation, "GIC-*");
            string[] CLCs = Directory.GetFiles(BaseLocation, "CLC-*");
            string[] EULs = Directory.GetFiles(BaseLocation, "EUL-*");
            if (RACs.Length > 0)
            {
                Console.WriteLine("==========RAC Info in Cert Begins==========");
                //RACAnalyze(RACs);
                CertAnalyse(RACs, Rule.CertRules.RAC,"RAC");
                Console.WriteLine("==========RAC Info in Cert Ends==========");
            }
            else 
            {
                Console.WriteLine("No RAC in the Folder");
            }

            if (CLCs.Length > 0)
            {
                Console.WriteLine("==========CLC Info in Cert Begins==========");
                CertAnalyse(CLCs, Rule.CertRules.CLC,"CLC");
                Console.WriteLine("==========CLC Info in Cert Ends==========");
            }
            else
            {
                Console.WriteLine("No CLC in the Folder");
            }
            if (EULs.Length > 0)
            {
                Console.WriteLine("==========EUL Info in Cert Begins==========");
                CertAnalyse(EULs, Rule.CertRules.EUL,"EUL");
                Console.WriteLine("==========EUL Info in Cert Ends==========");
            }
            else
            {
                Console.WriteLine("No EUL in the Folder");
            }
        }

        private void CertAnalyse(string[] Certs, string[] C_Rule, string Type)
        {
            //Identities in RACs/CLCs
            var Identities = new List<string>();

            foreach (string Cert in Certs)
            {
                Handler.TxtLogger(Cert.Split('\\')[^1]);
                var XrML = new XmlDocument();
                XrML.LoadXml(Handler.XmlValidator(Cert));
                if (C_Rule.Length > 0)
                {
                    foreach (string SingleRule in C_Rule)
                    {
                        var RuleXml = new XmlDocument();
                        RuleXml.LoadXml(SingleRule);
                        if (Type == "EUL")
                        {

                            if (RuleXml.ChildNodes[0].Name != "Permission")
                            {
                                var Node = XrML.SelectNodes("/WRAPPER" + RuleXml.ChildNodes[0].InnerText)[0];
                                Console.WriteLine(RuleXml.ChildNodes[0].Name + " : " + Node.InnerText);
                            }
                            else
                            {
                                XmlNodeList PermissionNodes = XrML.SelectNodes("/WRAPPER" + RuleXml.ChildNodes[0].InnerText)[0].ChildNodes;
                                var Permissions = new List<string>();
                                foreach (XmlNode Node in PermissionNodes)
                                {
                                    if (Node.Name == "RIGHT" && Node.Attributes["name"] != null)
                                    {
                                        Permissions.Add(Node.Attributes["name"].Value);
                                    }
                                    else
                                    {
                                        Permissions.Add(Node.Name);
                                    }
                                }
                                Permissions.Sort();
                                Console.WriteLine(RuleXml.ChildNodes[0].Name + " : " + JsonSerializer.Serialize(Permissions, new JsonSerializerOptions()));
                            }

                        }
                        else
                        {
                            var Node = XrML.SelectNodes("/WRAPPER" + RuleXml.ChildNodes[0].InnerText)[0];
                            if ((Type == "RAC" || Type == "CLC") && RuleXml.ChildNodes[0].Name == "Principal")
                            {
                                Identities.Add(Node.InnerText);
                            }
                            Handler.TxtLogger(RuleXml.ChildNodes[0].Name + " : " + Node.InnerText);
                        }
                    }
                }
                else 
                {
                    result.ErrMessage = "No available Rule!";
                }
            }


            if (Identities.Distinct().ToList().Count > 1)
            {
                Console.WriteLine("There are multiple identities recorded in the RAC/CLC sets, which are " + JsonSerializer.Serialize(Identities.Distinct().ToList(), new JsonSerializerOptions()));
            }
            else if(Type != "EUL")
            {
                Console.WriteLine("Identity is good. Only identity " + JsonSerializer.Serialize(Identities.Distinct()) + "is in the log");
            }
        }

        private void LogBasicAnalyse(List<string[]> content, List<string> CodeList, string FileName)
        {
            //get all HTTP request info
            if (FindStartWithInParsedLog(content, "* MSIPC Version")) { BasicInfo.MSIPCVersion = content.Find(x => x[1].StartsWith("* MSIPC Version:"))[1].Split(':')[1].Trim(); }
            if (FindStartWithInParsedLog(content, "* AppName")) { BasicInfo.AppName = content.Find(x => x[1].StartsWith("* AppName"))[1].Split(':')[1].Trim(); }
            if (FindStartWithInParsedLog(content, "* AppVersion")) { BasicInfo.AppVersion = content.Find(x => x[1].StartsWith("* AppVersion"))[1].Split(':')[1].Trim(); }
            if (FindStartWithInParsedLog(content, "        -->dwType")) { BasicInfo.AuthType = content.Find(x => x[1].StartsWith("        -->dwType"))[1].Split(':')[1].Trim(); }
            if (FindStartWithInParsedLog(content, "    -->wszID")) { BasicInfo.Identity = content.Find(x => x[1].StartsWith("    -->wszID"))[1].Split(':')[1].Trim(); }
            
            //find all request, response and correlation ID lines
            List<string[]> RawRequestsAndResponse = content.FindAll( x => Handler.IsFiltered(x[1], new string []{"MSIPC_Request","MSIPC_Response","MSIPC_Correlation"})).ToList();

            List<List<string[]>> GroupedRequestsAndResponses = GroupRequestsAndResponses(RawRequestsAndResponse);
            List<List<string[]>> TempRemoveRequestsAndResponses = new List<List<string[]>>();


            //group the requests and the responses by session. remove the requests based on code list
            foreach (List<string[]> Session in GroupedRequestsAndResponses)
            {
                var TempSession = Session;
                foreach (string[] Line in TempSession.ToList())
                {
                    //if (!CodeList.Any(x => Line[1].Contains(x)) && Line[1].StartsWith("------ Sending"))
                    if (!CodeList.Any(x => Line[1].Contains(x)) && Handler.IsFiltered(Line[1],"MSIPC_Response"))
                    {
                        var Index = Session.IndexOf(Line);
                        if (Index > 0 && Handler.IsFiltered(Session[Index - 1][1], "MSIPC_Correlation"))
                        {
                            Session.Remove(Session[Index-1]);
                            Session.Remove(Line);
                        }
                        else
                        {
                            Session.Remove(Line);
                        }
                    }
                }
                if (Session.Count <= 1)
                {
                    TempRemoveRequestsAndResponses.Add(TempSession);
                }
            }

            GroupedRequestsAndResponses = GroupedRequestsAndResponses.Except(TempRemoveRequestsAndResponses).ToList();

            Handler.TxtLogger(Handler.Serialize(BasicInfo));

            if (GroupedRequestsAndResponses.Count != 0)
            {
                Console.WriteLine("\n==========MSIPC Traces: " + FileName + "==========");
                //display basic info
                Console.WriteLine(Handler.Serialize(BasicInfo) + "\n");

                if (BasicInfo.AppName.Contains("MSIP.ExecutionHost32.exe"))
                {
                    AIPInstalledFlag = true;
                    Console.WriteLine("AIP client is installed");
                }

                //print the requests and the responses
                foreach (var Lines in GroupedRequestsAndResponses)
                {
                    var table = new ConsoleTable("Line", "Info");
                    foreach (var Line in Lines)
                    {
                        string LineNo = Line[0];
                        string Text = Line[1];

                        if (Handler.IsFiltered(Text, "MSIPC_Request"))
                        {
                            string[] RequestElement = Text.Split(',');
                            string URL = RequestElement[0].Split('=')[1];
                            string RMSServiceId = URL.Split("//")[1].Split('/')[0];
                            string Service = URL.Split('/')[^2] + '/' + URL.Split('/')[^1];

                            table.AddRow((Int32.Parse(LineNo) + 1).ToString(),"Request to " + RMSServiceId + ". Action: " + Service);

                            //Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": Request to " + RMSServiceId + ". Action: " + Service);
                        }
                        else if (Handler.IsFiltered(Text, "MSIPC_Response"))
                        {
                            string Code = Text.Replace("-", "").Split('=')[1].Trim();

                            table.AddRow((Int32.Parse(LineNo) + 1).ToString(), "With Response: " + Code);

                            //Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": With Response: " + Code);
                        }
                        else if (Handler.IsFiltered(Text, "MSIPC_Correlation"))
                        {
                            string CorrelationId = Text.Substring(Text.IndexOf('{') + 1, Text.IndexOf('}') - Text.IndexOf('{') - 1);

                            table.AddRow((Int32.Parse(LineNo) + 1).ToString(), "Correlation Id: " + CorrelationId);

                            //Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": Correlation Id: " + CorrelationId);
                        }

                        //var i = int32.parse(line[0]) + 1;
                        Handler.TxtLogger("line:" + (Int32.Parse(LineNo) + 1).ToString() + ":" + Text);
                        //Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ":" + Text);
                    }
                    table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                    Console.WriteLine("");
                }

                Console.WriteLine("==========MSIPC Traces Ends==========\n");
            }
            else 
            {
                Console.WriteLine("\nNo trace to display based on rule in log " + FileName);
            }
        }

        private void BootstrapAnalyse(List<string[]> content,string FileName)
        {
            //check if the log is AIP client log
            if (IsAIPLog(content) )
            {
                AIPInstalledFlag = true;
            }
            List<string[]> GroupedInformation = GroupInformation(content);
            if (GroupedInformation.Count > 0)
            {
                int MachineActivationCount = 0;
                int ServiceDiscoveryCount = 0;
                int ServiceDiscoverySuccessCount = 0;
                int UserIdentityCount = 0;
                int TemplateCount = 0;
                foreach (string[] Information in GroupedInformation)
                {
                    Handler.TxtLogger("line:" + Information[0] + ": " + Information[1]);
                    //Console.WriteLine("line:" + Information[0] + ": " + Information[1]);
                    if (Handler.IsFiltered(Information[1], "MSIPC_MachineAvtivationFlag"))
                    {
                        MachineActivationCount++;
                    }
                    else if (Handler.IsFiltered(Information[1], "MSIPC_ServiceDiscoveryFlag"))
                    {
                        ServiceDiscoveryCount++;
                        if (Information[1].Contains("succe"))
                        {
                            ServiceDiscoveryFlag = true;
                        }
                    }
                    else if (Handler.IsFiltered(Information[1], "MSIPC_UserIdentityFlag"))
                    {
                        UserIdentityFlag = true;
                    }
                    else if (Handler.IsFiltered(Information[1], "MSIPC_TemplateFlag"))
                    {
                        TemplateCount++;
                        TemplateFlag = true;
                    }
                }

                var table = new ConsoleTable("Info", "Result");

                //machine cert checking
                if (MachineActivationCount > 1)
                {
                    table.AddRow("Machine activation", "OK");
                    //Console.WriteLine("Machine activation ok");
                }
                else if (MachineActivationCount == 1)
                {
                    table.AddRow("Machine activation", "May fail");
                    //Console.WriteLine("Machine activation may fail");
                }
                else
                {
                    table.AddRow("Machine activation", "May skip");
                    //Console.WriteLine("Machine activation may skip");
                }

                //service discovery checking. May need add AIP/not logic later
                if (ServiceDiscoveryFlag)
                {
                    table.AddRow("Service discovery", "OK");
                    //Console.WriteLine("Service discovery ok");
                }
                else if (ServiceDiscoveryCount == 0)
                {
                    table.AddRow("Service discovery", "May skip or terminate");
                    //Console.WriteLine("Service discovery may skip or terminate");
                }
                else
                {
                    table.AddRow("Service discovery", "May fail");
                    //Console.WriteLine("Service discovery may fail");
                }

                //user identity
                if (UserIdentityFlag)
                {
                    table.AddRow("User identity initialization", "OK");
                    //Console.WriteLine("User identity initialization ok");
                }
                else
                {
                    table.AddRow("User identity initialization", "May fail");
                    //Console.WriteLine("User identity initialization may fail");
                }

                //template
                if (TemplateFlag)
                {
                    table.AddRow("Template getting", "OK");
                    //Console.WriteLine("Template getting ok\n");
                }
                else
                {
                    table.AddRow("Template getting", "May fail");
                    //Console.WriteLine("Template getting may fail\n");
                }

                table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                Console.WriteLine("");

            }

        }

        private void RACAnalyse(List<string[]> content, string FileName)
        {
            List<List<string[]>> GroupedRACInformation = GroupRACInformation(content);


            //RAC CLC info
            if (GroupedRACInformation[0].Count > 0)
            {
                List<string[]> RACCLCInformation = GroupedRACInformation[0];
                List<List<string[]>> RACCLCInformationOutput = new List<List<string[]>>();
                List<string[]> Set = new List<string[]>();
                string CompareString = "";

                foreach (string[] Information in RACCLCInformation)
                {
                    List<string[]> TempSet = new List<string[]>();
                    if (Handler.IsFiltered(Information[1],new string[] { "MSIPC_LicenseRAC", "MSIPC_LicenseCLC" }))
                    {
                        string Type = Information[1].Split(':')[0];
                        string[] temp = Information[1].Trim(',').Split(": ");
                        string Name = temp[0].Split(':')[1];
                        string Value = temp[1];
                        if (CompareString == "")
                        {
                            CompareString = Type;
                            Set.Add(new string[] { Type, Name, Value });
                        }
                        else if (CompareString == Type)
                        {
                            Set.Add(new string[] { Type, Name, Value });
                        }
                        else 
                        {
                            TempSet = Set;
                            RACCLCInformationOutput.Add(TempSet);
                            Set = new List<string[]>();
                            CompareString = Type;
                            Set.Add(new string[] { Type, Name, Value });
                        }
                    }
                }
                if (Set.Count > 0)
                {
                    RACCLCInformationOutput.Add(Set);
                }

                //delete repeated RAC/CLC
                RACCLCInformationOutput = Handler.ListGroup(RACCLCInformationOutput);


                //prepare the table
                Console.WriteLine("==========RAC CLC Info in Logs Begins==========");
                foreach (List<string[]> License in RACCLCInformationOutput)
                {
                    string Type = License[0][0];
                    Console.WriteLine(Type);
                    var table = new ConsoleTable("Name","Value");
                    foreach (string[] row in License)
                    { 
                        table.AddRow(row[1],row[2]);
                        Handler.TxtLogger(Type + " " + row[1] + " " + row[2]);
                    }
                    table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                }
                Console.WriteLine("==========RAC CLC Info in Logs Ends==========\n");
            }

            //license info
            if (GroupedRACInformation[1].Count > 0)
            {
                List<string[]> LicenseInformation = GroupedRACInformation[1];
                List<string[]> LicenseInformationOutput = new List<string[]>();
                bool CleanLicenseFlag = false;

                foreach (string[] Information in LicenseInformation)
                {
                    if (Handler.IsFiltered(Information[1], "MSIPC_LicenseDeleted"))
                    {
                        LicenseInformationOutput.Clear();
                    }
                    else if (Handler.IsFiltered(Information[1], "MSIPC_LicenseFound"))
                    {
                        LicenseInformationOutput.Add(Information);
                    }
                    Handler.TxtLogger("line:" + (Int32.Parse(Information[0]) + 1).ToString() + ": " + Information[1]);
                }

                List<string> Licenses = LicenseInformationOutput.Select(x=>x[1]).Distinct().ToList();

                if (Licenses.Count > 0)
                {
                    var table = new ConsoleTable("Info");

                    Console.WriteLine("==========License Info in Logs Begins==========");
                    foreach (string License in Licenses)
                    {
                        Handler.TxtLogger("License found: " + License);
                        //Console.WriteLine("License found: " + License);
                        table.AddRow("License found");
                        table.AddRow(License.Split(" - ")[1]);
                    }
                    table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                    Console.WriteLine("==========License Info in Logs Ends==========");
                }
                else 
                {
                    Console.WriteLine("No RAC&CLC info in Logs");
                }
            }
        }

        private List<string[]> ParseMSIPCLog(string[] RawContent)
        {
            List<string[]> ParsedContent = new List<string[]>();

            foreach (var Item in RawContent.Select((value, i) => (value, i)))
            {
                string Line = Item.value;
                int Index = Item.i;
                if (Line.Length > 0)
                {
                    string[] LineInfo = { Index.ToString(), Line };
                    ParsedContent.Add(LineInfo);
                }
            }
            return ParsedContent;
        }

        private List<List<string[]>> GroupRequestsAndResponses(List<string[]> input)
        {
            List<List<string[]>> output = new List<List<string[]>>();
            var Session = new List<string[]>();
            foreach (string[] item in input)
            {

                if (Handler.IsFiltered(item[1], "MSIPC_Request"))
                {
                    if (Session.Count > 0)
                    {
                        output.Add(Session);
                    }
                    Session = new List<string[]>
                    {
                        item
                    };
                }
                else if (Handler.IsFiltered(item[1], "MSIPC_Response") || Handler.IsFiltered(item[1], "MSIPC_Correlation"))
                {
                    Session.Add(item);
                }
            }
            output.Add(Session);
            return output;
        }

        private bool FindStartWithInParsedLog(List<string[]> content, string pattern)
        {
            var result = content.Find(x => x[1].StartsWith(pattern));
            if (result == null)
            { return false;}
            return true;
        }

        private bool IsAIPLog(List<string[]> content)
        {
            if (FindStartWithInParsedLog(content, "* AppName: MSIP.ExecutionHost32.exe"))
            {
                return true;
            }

            return false;
        }

        private List<string[]> GroupInformation(List<string[]> input)
        {
            List<string[]> output = new List<string[]>();

            foreach (string[] item in input)
            {
                if (Handler.IsFiltered(item[1], new string[] { "MSIPC_Information", "MSIPC_Information_2" }))
                {
                    string[] newItem = new string[2];
                    newItem[0] = item[0];
                    newItem[1] = Handler.SubstringString(item[1], "MSIPC_Information").Trim('n').Trim('+').Trim();
                    output.Add(newItem);
                }
            }

            return output;
        }

        private List<List<string[]>> GroupRACInformation(List<string[]> input)
        {
            //output:
            //[0] license store processes
            //[1] RAC/CLC issue
            List<List<string[]>> output = new List<List<string[]>>();

            List<string[]> RAC_CLC_Info = new List<string[]>();
            List<string[]> LicenseInfo = new List<string[]>();
            foreach (string[] item in input)
            {
                if (Handler.Contains(item[1], new string[] { " RAC", "GIC", " CLC" }))
                {
                    string[] newItem = new string[2];
                    newItem[0] = item[0];
                    if (Handler.Contains(item[1], new string[] { "RAC details", "CLC details" }))
                    {
                        newItem[1] = item[1].Trim().Trim('-').Trim('+').Trim();
                        RAC_CLC_Info.Add(newItem);
                        int index = input.IndexOf(item) + 1;
                        string Detail = item[1].Split(':')[1];
                        while (input[index][1].StartsWith("     "))
                        {
                            newItem = new string[2];
                            newItem[0] = input[index][0];
                            newItem[1] = Detail.Trim() + ":" + input[index][1].Trim();
                            RAC_CLC_Info.Add(newItem);
                            index++;
                        }
                    }
                    else if (Handler.IsFiltered(item[1], "MSIPC_License"))
                    {
                        newItem[1] = item[1];
                        LicenseInfo.Add(newItem);
                    }
                    else
                    {
                        newItem[1] = item[1].Trim().Trim('-').Trim('+').Trim();
                        RAC_CLC_Info.Add(newItem);
                    }
                }
            }

            output.Add(RAC_CLC_Info);
            output.Add(LicenseInfo);

            return output;
        }



    }
}
