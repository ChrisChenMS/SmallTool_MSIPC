using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using SmallTool_MSIPC.Models;
using System.Xml;
using System.Linq;
using System.Configuration;

namespace SmallTool_MSIPC
{
    public class MSIPC
    {
        private MSIPC_Response result = new MSIPC_Response();
        
        private readonly string ProgramLocation = System.AppDomain.CurrentDomain.BaseDirectory;
        private readonly static Handler Handler = new Handler();
        private string BaseLocation;
        private string errorRecorder;
        private MSIPC_Rules Rule = new MSIPC_Rules();
        private MSIPC_BasicLogInfo BasicInfo = new MSIPC_BasicLogInfo();

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

            if (Rule.Mode < 1 || Rule.Mode > 3)
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
                        Handler.TxtLogger(LogPath.Split('\\')[^1]);

                        //open file
                        string[] RawContent = File.ReadAllLines(LogPath).ToArray();

                        //initially parse log
                        List<string[]> ParsedContent = ParseMSIPCLog(RawContent);

                        LogBasicAnalyse(ParsedContent, ResponseCode, LogPath.Split('\\')[^1]);

                        if (Rule.Bootstrap)
                        {
                            BootstrapAnalyse(ParsedContent);
                        }
                        if (Rule.RAC_CLC)
                        {

                        }
                        if (Rule.Template)
                        {

                        }
                        if (Rule.EUL)
                        {

                        }
                        
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
                Console.WriteLine("==========RAC Info Begins==========");
                //RACAnalyze(RACs);
                CertAnalyse(RACs, Rule.CertRules.RAC,"RAC");
                Console.WriteLine("==========RAC Info Ends==========");
            }
            else 
            {
                Console.WriteLine("No RAC in the Folder");
            }

            if (CLCs.Length > 0)
            {
                Console.WriteLine("==========CLC Info Begins==========");
                CertAnalyse(CLCs, Rule.CertRules.CLC,"CLC");
                Console.WriteLine("==========CLC Info Ends==========");
            }
            else
            {
                Console.WriteLine("No CLC in the Folder");
            }
            if (EULs.Length > 0)
            {
                Console.WriteLine("==========EUL Info Begins==========");
                CertAnalyse(EULs, Rule.CertRules.EUL,"EUL");
                Console.WriteLine("==========EUL Info Ends==========");
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
            var a = content.Find(x => x[1].StartsWith("    -->wszID"));

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
                    //var ab = !CodeList.Any(x => Line[1].Contains(x));
                    //var b = Line[1].StartsWith("------ Sending");
                    //var c = Line[1].StartsWith("Correlation");

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
                Console.WriteLine("\n==========MSIPC Log: " + FileName + "==========");
                //display basic info
                Console.WriteLine(Handler.Serialize(BasicInfo) + "\n");

                //print the requests and the responses
                foreach (var Lines in GroupedRequestsAndResponses)
                {
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
                            Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": Request to " + RMSServiceId + ". Action: " + Service);
                        }
                        else if (Handler.IsFiltered(Text, "MSIPC_Response"))
                        {
                            string Code = Text.Replace("-", "").Split('=')[1].Trim();
                            Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": With Response: " + Code);
                        }
                        else if (Handler.IsFiltered(Text, "MSIPC_Correlation"))
                        {
                            string CorrelationId = Text.Substring(Text.IndexOf('{') + 1, Text.IndexOf('}') - Text.IndexOf('{') - 1);
                            Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ": Correlation Id: " + CorrelationId);
                        }

                        //var i = int32.parse(line[0]) + 1;
                        Handler.TxtLogger("line:" + (Int32.Parse(LineNo) + 1).ToString() + ":" + Text);
                        //Console.WriteLine("line:" + (Int32.Parse(LineNo) + 1).ToString() + ":" + Text);
                    }
                    Console.WriteLine("");
                }

                Console.WriteLine("==========MSIPC Log Info Ends==========\n");
            }
            else 
            {
                Console.WriteLine("\nNo info to display based on rule in log " + FileName);
            }
        }

        private void BootstrapAnalyse(List<string[]> content)
        {
            //check if the log is AIP client log
            IsAIPLog(content);
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



    }
}
