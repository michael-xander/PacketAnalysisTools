package ports;

import icmp.ICMPFilter;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * <h1>Port Analyser</h1>
 * Gives breakdown of TCP/UDP ports utilised from pcap files
 * @author Michael Kyeyune
 * @since 2016-04-28
 */
public class PortAnalyser
{
    private static String FOlDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read pcap files from i.e -d sample_folder";
    private static String FILE_ARGUMENT_INSTRUCTION = "- Provide a pcap file to read from i.e -d file_directory -f sample_file";

    private static String DATA_DISPLAY_SEPARATOR = "======================================================================";

    private static String TEMP_FOLDER_NAME = "ports_temp";

    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOlDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
        else if(args.length == 2 || args.length == 4)
        {
            String folderName = args[1];
            File[] files = null;

            //directory submitted
            if(args.length == 2 && args[0].equals("-d"))
            {
                File folder = new File(folderName);
                files = folder.listFiles();
            }
            else if(args.length == 4 && args[0].equals("-d") && args[2].equals("-f"))
            {
                String fileName = args[3];

                File file = new File(folderName + "/" + fileName);

                File[] tempFiles = new File[1];
                tempFiles[0] = file;

                files = tempFiles;
            }
            else
            {
                System.out.println("Wrong arguments provided. Please do one of the following:");
                System.out.println(FOlDER_ARGUMENT_INSTRUCTION);
                System.out.println(FILE_ARGUMENT_INSTRUCTION);
                System.exit(1);
            }

            System.out.println(DATA_DISPLAY_SEPARATOR);

            //temp folder for temporary files during analysis
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
                System.out.println("Create temp folder in : " + folderName);
            }
            else
            {
                System.out.println("Failed to make temp folder in : " + folderName);
                System.exit(1);
            }

            //iterate through the pcap files

            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing to process file : " + file.getName());

                    generateFilteredFiles(folderName, file.getName(), folderName + "/" + TEMP_FOLDER_NAME);
                }
            }

            //start analysis on generated files
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Carrying out analysis on files");

            files = tempFolder.listFiles();

            //TODO: create data structure to hold counts
            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing to analyse file : " + file.getName());

                    analyseFilteredFiles((folderName + "/" + TEMP_FOLDER_NAME), file.getName());
                }
            }

            //delete the temporary folder
            deleteDirectory(tempFolder);
        }
        else
        {
            System.out.println("More arguments provided than needed. Please do one of the following:");
            System.out.println(FOlDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
    }

    public static void generateFilteredFiles(String folderName, String fileName, String tempFolderName)
    {
        String filterString = "not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";

        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump", filterString, "-r", (folderName + "/" + fileName),
                "-w", (tempFolderName + "/temp_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);

            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            printCurrentTime();

            if(errorCode == 0)
            {
                System.out.println("No error occurred on running tcpdump command for file: " + folderName + "/" + fileName);
            }
            else
            {
                System.out.println("An error occurred on running tcpdump command for file: " + folderName + "/" + fileName);

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

    public static void analyseFilteredFiles(String folderName, String fileName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("tcpdstat", (folderName + "/" + fileName));

        try {
            printCurrentTime();
            System.out.println("Analysing file : " + fileName);
            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            BufferedReader bufferedReader = null;
            String line = null;

            printCurrentTime();

            if(errorCode == 0)
            {
                System.out.println("No error occurred on running tcpdstat command for file : " + fileName);

                printCurrentTime();
                System.out.println("Obtaining breakdown of results");

                bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                boolean inProtocolSection = false;
                int lineCounter = 1;

                printCurrentTime();
                System.out.println("protocol, service, bytes");

                boolean isTCPBreakdown = false;
                boolean isUDPBreakdown = false;

                String currentProtocol = null;

                while((line = bufferedReader.readLine()) != null)
                {
                    if(line.equals("### Protocol Breakdown ###"))
                        inProtocolSection = true;
                    else if(line.equals(">>>>"))
                        inProtocolSection = false;

                    if(inProtocolSection)
                    {
                        // the actual protocol breakdown past the table boundary
                        if(lineCounter >= 5)
                        {
                            String tempLine = line.replaceAll("\\(\\s+", "(");

                            String[] strArr = tempLine.split("\\s+");

                            if(strArr[0].equals("[2]"))
                            {
                                currentProtocol = null;
                                isTCPBreakdown = false;
                                isUDPBreakdown = false;
                            }

                            // do processing in here
                            if(isTCPBreakdown || isUDPBreakdown)
                            {
                                String serviceName = strArr[1];
                                String serviceBytes = strArr[4];

                                System.out.println(currentProtocol + ", " + serviceName + ", " + serviceBytes);
                            }

                            // tcp breakdown to follow
                            if(strArr[1].equals("tcp"))
                            {
                                currentProtocol = "tcp";
                                isTCPBreakdown = true;
                                isUDPBreakdown = false;
                            }
                            else if(strArr[1].equals("udp"))
                            {
                                currentProtocol = "udp";
                                isUDPBreakdown = true;
                                isTCPBreakdown = false;
                            }
                            else if(strArr[1].equals("other"))
                            {
                                currentProtocol = null;
                                isTCPBreakdown = false;
                                isUDPBreakdown = false;
                            }


                        }
                        lineCounter++;
                    }
                }
            }
            else
            {
                printCurrentTime();
                System.out.println("An error occurred on running tcpdstat command for file : " + fileName);

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



    public static void printCurrentTime()
    {
        ICMPFilter.printCurrentTime();
    }

    public static void deleteDirectory(File file)
    {
        ICMPFilter.deleteDirectory(file);
    }
}
