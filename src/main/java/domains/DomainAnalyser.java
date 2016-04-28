package domains;

import icmp.ICMPFilter;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Scanner;

/**
 * <h1>Domain Analyser</h1>
 * Lists the domains from pcap files.
 * @author Michael Kyeyune
 * @since 2016-04-27
 */
public class DomainAnalyser
{
    private static String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read pcap files from i.e -d sample_folder.";
    private static String FILE_ARGUMENT_INSTRUCTION = "- Provide a pcap file to read from i.e -d file_directory -f sample_file";

    private static String TEMP_FOLDER_NAME = "temp";
    private static String SUB_TEMP_FOLDER_NAME = "data";

    private static String DATA_DISPLAY_SEPARATOR = "======================================================================";


    public static void main(String[] args)
    {
        if(args.length == 0)
        {
            System.out.println("No arguments provided. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
        else if (args.length == 2 || args.length == 4)
        {
            String folderName = args[1];
            File[] files = null;

            // directory submitted
            if(args.length == 2 && args[0].equals("-d"))
            {
                File folder = new File(folderName);
                files = folder.listFiles();
            }
            else if (args.length == 4 && args[0].equals("-d") && args[2].equals("-f")) // a file and its directory submitted
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
                System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
                System.out.println(FILE_ARGUMENT_INSTRUCTION);
                System.exit(1);
            }

            System.out.println(DATA_DISPLAY_SEPARATOR);

            //setup temp folder to temporary files during analysis
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

                    generateFilteredPcapFile(folderName, file.getName(), (folderName + "/" + TEMP_FOLDER_NAME));
                }
            }

            // start analysis on generated files
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Beginning IP breakdown");

            files = tempFolder.listFiles();

            File subTempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME);
            subTempFolder.mkdir();

            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing to analyse file : " + file.getName());

                    generateIPCountFile((folderName + "/" + TEMP_FOLDER_NAME), file.getName(), (folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME));
                }
            }

            //read in the files with ip breakdowns and tally up the counts
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Beginning tallying for IP addresses");

            files = subTempFolder.listFiles();

            Scanner scanner = null;
            InetAddress inetAddress = null;

            // map to hold the counts for domains encountered
            HashMap<String, Integer> domainCounterMap = new HashMap<String, Integer>();
            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Getting tally from file : " + file.getName());
                    System.out.println("-> Domain, Count");
                    try {
                        scanner = new Scanner(file);

                        String line = null;
                        while(scanner.hasNextLine())
                        {
                            line = scanner.nextLine();

                            if(!line.contains("!"))
                            {
                                String[] strArr = line.split("\\s+");

                                String ipAddress = strArr[0];
                                String ipAddressStrCount = strArr[1];

                                try {
                                    inetAddress = InetAddress.getByName(ipAddress);
                                    String host = inetAddress.getHostName();

                                    System.out.println("-> " + host + ", " + ipAddressStrCount);

                                    // add domain count to map
                                    int ipAddressCount = Integer.parseInt(ipAddressStrCount);

                                    if(!domainCounterMap.containsKey(host))
                                    {
                                        domainCounterMap.put(host, 0);
                                    }

                                    int currentCount = domainCounterMap.get(host);

                                    //update the host count
                                    domainCounterMap.put(host, (currentCount + ipAddressCount));

                                } catch (UnknownHostException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }

            //TODO: place tallies in csv file

            //delete temporary folder
            deleteDirectory(tempFolder);
        }
        else
        {
            System.out.println("More arguments provided than needed. Please do one of the following:");
            System.out.println(FOLDER_ARGUMENT_INSTRUCTION);
            System.out.println(FILE_ARGUMENT_INSTRUCTION);
        }
    }

    public static void generateFilteredPcapFile(String folderName, String fileName, String tempFolderName)
    {
        String filterString = "(src net 192.168.0.0/16 or 10.0.0.0/8) and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";

        ProcessBuilder processBuilder = new ProcessBuilder("tcpdump", filterString, "-r", (folderName + "/" + fileName), "-w",
                (tempFolderName + "/temp_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Processing file : " + fileName);

            Process process = processBuilder.start();
            int errorCode = process.waitFor();

            printCurrentTime();
            if(errorCode == 0)
                System.out.println("No error occurred on running tcpdump commannd for file: " + folderName + "/" + fileName);
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

    public static void generateIPCountFile(String folderName, String fileName, String tempFolderName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("ipaggcreate", "-d" , "-r", (folderName + "/" + fileName),
                "-o", (tempFolderName + "/data_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Analysing file : " + fileName);

            Process process = processBuilder.start();
            int errorCode = process.waitFor();

            printCurrentTime();
            if(errorCode == 0)
                System.out.println("No error occurred on running ipaggcreate command for file: " + folderName + "/" + fileName);
            else
            {
                System.out.println("An error occurred while running ipaggcreate command for file : " + folderName + "/" + fileName);

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
    public static void printCurrentTime()
    {
        ICMPFilter.printCurrentTime();
    }

    public static void deleteDirectory(File file)
    {
        ICMPFilter.deleteDirectory(file);
    }
}
