package bandwidth;

import icmp.ICMPFilter;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * <h1>Bandwidth Analyzer</h1>
 * BandwidthAnalyzer utilises the tcpdstat commandline tool to gain stats about bandwidth from dumps
 */
public class BandwidthAnalyzer {

    private static String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read the files from whilst specifying whether to analyse " +
            "uplink or downlink e.g -uplink/-downlink sample_folder";

    private static String DATA_DISPLAY_SEPARATOR = "======================================================================";

    private static String TEMP_FOLDER_NAME = "temp";

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
        else if(args.length == 2)
        {
            if(args[0].equals("-uplink") || args[0].equals("-downlink"))
            {
                boolean doUplinkAnalysis = args[0].equals("-uplink");
                System.out.println(DATA_DISPLAY_SEPARATOR);

                String folderName = args[1];

                //setup folder to hold temporary files during analysis

                File tempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME);

                if(tempFolder.exists())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Deleting temp folder in : " + folderName);
                    deleteDirectory(tempFolder);
                }

                tempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME);

                System.out.println(DATA_DISPLAY_SEPARATOR);
                printCurrentTime();

                if(tempFolder.mkdir())
                {
                    System.out.println("Created temp folder in : " + folderName);
                }
                else
                {
                    System.out.println("Failed to make temp folder in : " + folderName);
                    System.exit(1);
                }

                //iterate through the dumps in the provided folder
                File folder = new File(folderName);

                for(File file : folder.listFiles())
                {
                    if(file.isFile() && !file.isHidden())
                    {
                        System.out.println(DATA_DISPLAY_SEPARATOR);
                        printCurrentTime();
                        System.out.println("Preparing to process file : " + file.getName());

                        generateRequiredLinkFiles(doUplinkAnalysis, folderName, file.getName(), folderName + "/" + TEMP_FOLDER_NAME);
                    }
                }

                //do analysis on files in the temp folder

                System.out.println(DATA_DISPLAY_SEPARATOR);
                System.out.println(DATA_DISPLAY_SEPARATOR);

                for(File file : tempFolder.listFiles())
                {
                    if(file.isFile() && !file.isHidden())
                    {
                        System.out.println(DATA_DISPLAY_SEPARATOR);
                        printCurrentTime();
                        System.out.println("Analysing file : " + file.getName());

                        doAnalysisForGeneratedFiles(folderName + "/" + TEMP_FOLDER_NAME, file.getName());
                    }
                }


                //delete all evidence
                deleteDirectory(tempFolder);

            }
            else
            {
                System.out.println("Wrong arguments provided. Please do one of the following:");
                System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            }
        }
        else
        {
            System.out.println("More arguments provided than needed. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
        }
    }

    public static void generateRequiredLinkFiles(boolean isUplinkAnalysis, String folderName, String fileName, String tempFolderName)
    {
        //generate the right filter string depending on whether uplink or downlink analysis is being done

        String filterString = null;
        if(isUplinkAnalysis)
        {
            filterString = "(src net 192.168.0.0/16 or 10.0.0.0/8) and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";
        }
        else
        {
            filterString = "(dst net 192.168.0.0/16 or 10.0.0.0/8) and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";
        }

        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump", filterString, "-r", (folderName + "/" + fileName), "-w",
                (tempFolderName + "/temp_" + fileName));

        try
        {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);

            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            printCurrentTime();
            if(errorCode == 0)
            {
                System.out.println("No error occured on running tcpdump command for file: " + folderName + "/" + fileName);
            }
            else
            {
                System.out.println("An error occurred while running tcpdump command for file: " + folderName + "/" + fileName);

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                String line = null;

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void doAnalysisForGeneratedFiles(String folderName, String fileName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("tcpdstat", folderName + "/" + fileName);

        try {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);
            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            BufferedReader bufferedReader = null;
            String line = null;

            if(errorCode == 0)
            {
                printCurrentTime();
                System.out.println("No error occurred on running tcpdstat command for file : " + fileName);

                printCurrentTime();
                System.out.println("Printing out obtained input : ");
                bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }
            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred on running the tcpdstat command for file : " + fileName);

                bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void printCurrentTime() {
        ICMPFilter.printCurrentTime();}

    public static void deleteDirectory(File file)
    {
        ICMPFilter.deleteDirectory(file);
    }
}
