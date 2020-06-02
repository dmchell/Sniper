using System;
using System.Diagnostics;
namespace Sniper
{
    class Program
    {
        static void Main(string[] args)
        {
           
            Process[] processlist = Process.GetProcesses();
            foreach (Process theprocess in processlist)
            {
                    try
                    {
                        ProcessModuleCollection myProcessModuleCollection = theprocess.Modules;
                        ProcessModule myProcessModule;

                        for (int i = 0; i < myProcessModuleCollection.Count; i++)
                        {
                            myProcessModule = myProcessModuleCollection[i];
                            if (myProcessModule.ModuleName.Contains("clr.dll"))
                            {

                                Console.WriteLine("######### Process: {0} ID: {1}", theprocess.ProcessName, theprocess.Id);

                                Console.WriteLine("The moduleName is "
                                    + myProcessModule.ModuleName);
                                Console.WriteLine("The " + myProcessModule.ModuleName + "'s base address is: "
                                    + myProcessModule.BaseAddress);
                                Console.WriteLine("The " + myProcessModule.ModuleName + "'s Entry point address is: "
                                    + myProcessModule.EntryPointAddress);
                                Console.WriteLine("The " + myProcessModule.ModuleName + "'s File name is: "
                                    + myProcessModule.FileName);
                                i = myProcessModuleCollection.Count;
                                Scanner.MemScan(theprocess.ProcessName);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("!!!!!!!! Unable to Access Process: {0} ID: {1}", theprocess.ProcessName, theprocess.Id);
                        //Console.WriteLine(e.Message);
                    }
                }
            Console.WriteLine("Complete...");
            Console.ReadLine();
        }
    }
}
