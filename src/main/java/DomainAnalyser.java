import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Scanner;

/**
 * <h1>Domain Analyser</h1>
 * Lists the domains visited from pcap files.
 * @author Michael Kyeyune
 * @since 2016-04-27
 */
public class DomainAnalyser
{
    private static String FOLDER_ARGUMENT_INSTRUCTION = "- Provide a folder to read pcap files from i.e -d sample_folder.";
    private static String FILE_ARGUMENT_INSTRUCTION = "- Provide a pcap file to read from i.e -d file_directory -f sample_file";

    private static String TEMP_FOLDER_NAME = "domain_temp";
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
            System.out.println("Beginning host name breakdown");

            files = tempFolder.listFiles();

            File subTempFolder = new File(folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME);
            subTempFolder.mkdir();

            //for each pcap file, apply the httpry tool to obtain the hosts and write to file
            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Preparing to get host names from file : " + file.getName());

                    generateHostNameFiles((folderName + "/" + TEMP_FOLDER_NAME), file.getName(), (folderName + "/" + TEMP_FOLDER_NAME + "/" + SUB_TEMP_FOLDER_NAME));
                }
            }

            //read in the files with host breakdowns and tally up the counts
            System.out.println(DATA_DISPLAY_SEPARATOR);
            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Beginning host name retrieval");

            files = subTempFolder.listFiles();

            Scanner scanner = null;

            //counting the different domains
            HashMap<String, Long> domainCounterMap = new HashMap<String, Long>();

            //map to hold the different domains read from the httpry output files
            HashMap<String, Long> dataCounterMap = new HashMap<String, Long>();

            // read the input from the files written by httpry for host names
            for(File file : files)
            {
                if(file.isFile() && !file.isHidden())
                {
                    System.out.println(DATA_DISPLAY_SEPARATOR);
                    printCurrentTime();
                    System.out.println("Hosts from file : " + file.getName());
                    try {
                        scanner = new Scanner(file);

                        String line = null;
                        while(scanner.hasNextLine())
                        {
                            line = scanner.nextLine();

                            if(!line.contains("#"))
                            {
                                String temp = line.trim();

                                if(!dataCounterMap.containsKey(temp))
                                {
                                    dataCounterMap.put(temp, 0L);
                                }

                                long currentCount = dataCounterMap.get(temp);
                                dataCounterMap.put(temp, (currentCount + 1));

                            }
                        }
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                }
            }

            System.out.println(DATA_DISPLAY_SEPARATOR);
            printCurrentTime();
            System.out.println("Doing conversion");

            InetAddress inetAddress = null;

            //summarise the different host names to their respective domains.
            for(String tempDomain : dataCounterMap.keySet())
            {
                String[] strArr = tempDomain.split("\\.");

                String hostName = null;

                String lastItem = strArr[strArr.length-1];

                if(lastItem.matches("[a-zA-Z]+"))
                {
                    if(strArr.length >= 2)
                        hostName = "*." + (strArr[strArr.length - 2] + "." + strArr[strArr.length -1]);
                    else
                        hostName = "*." + lastItem;
                }
                else if(lastItem.matches("[0-9]+")) // if an ip address, try to lookup the host name
                {
                    try {
                        inetAddress = InetAddress.getByName(tempDomain);
                        String host = inetAddress.getHostName();
                        String[] tempArr = host.split("\\.");

                        //on failing to get a host name, stick to the ip address as domain
                        if(tempArr[tempArr.length - 1].matches("[0-9]+"))
                        {
                            hostName = host;
                        }
                        else
                        {
                            if(tempArr.length >= 2)
                                hostName = "*." + (tempArr[tempArr.length - 2] + "." + tempArr[tempArr.length -1]);
                            else
                                hostName = "*." + (tempArr[tempArr.length - 1]);
                        }
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                }
                else
                {
                    hostName = tempDomain;
                }

                if(!domainCounterMap.containsKey(hostName))
                {
                    domainCounterMap.put(hostName, 0L);
                }

                long currentCount = domainCounterMap.get(hostName);
                long countToAdd = dataCounterMap.get(tempDomain);

                domainCounterMap.put(hostName, (currentCount + countToAdd));
            }

            // write the domains to file
            String analysedDataFileName = "domain-analysis.csv";

            FileWriter writer = null;

            System.out.println(DATA_DISPLAY_SEPARATOR);

            printCurrentTime();
            System.out.println("Writing host counts to file");

            try {
                writer = new FileWriter(analysedDataFileName);

                printCurrentTime();
                System.out.println("host, count");
                //the column heads
                writer.append("host, count");
                writer.append("\n");

                for(String domainName : domainCounterMap.keySet())
                {
                    long count = domainCounterMap.get(domainName);

                    printCurrentTime();
                    System.out.println(domainName + ", " + count);

                    writer.append(domainName + ", " + count);
                    writer.append("\n");
                }

                writer.flush();
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
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

    /**
     * Filters pcap files removing local traffic and leaving only packets destined outside the local network i.e incoming traffic removed
     * @param folderName - folder where pcap file to be filtered is held
     * @param fileName - name of the pcap file to filter
     * @param tempFolderName - folder where tcpdump filtered pcap file will be placed
     */
    public static void generateFilteredPcapFile(String folderName, String fileName, String tempFolderName)
    {
        String filterString = "(src net 192.168.0.0/16 or 10.0.0.0/8) and (port http or https) and not ((src net 192.168.0.0/16 or 10.0.0.0/8) and (dst net 192.168.0.0/16 or 10.0.0.0/8))";

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

    /**
     * Applies httpry tool to pcap files to get the host names then write them to file
     * @param folderName - folder where the pcap file is located
     * @param fileName - the name of the pcap file
     * @param tempFolderName - the folder where the httpry output file with hosts is to be placed
     */
    public static void generateHostNameFiles(String folderName, String fileName, String tempFolderName)
    {
        ProcessBuilder processBuilder = new ProcessBuilder("httpry", "-f", "host" , "-r", (folderName + "/" + fileName), "-o", (tempFolderName + "/data_" + fileName));

        try {
            printCurrentTime();
            System.out.println("Getting hosts for file : " + fileName);

            Process process = processBuilder.start();

            int errorCode = process.waitFor();

            printCurrentTime();
            if(errorCode == 0)
            {
                System.out.println("No error occurred on running httpry command for file : " + fileName);
            }
            else
            {
                System.out.println("An error occurred on running httpry command for file : " + fileName);

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

    /**
     * Prints the current system time
     */
    public static void printCurrentTime()
    {
        ICMPAnalyser.printCurrentTime();
    }

    /**
     * Deletes the provided file/directory
     * @param file - the file to delete
     */
    public static void deleteDirectory(File file)
    {
        ICMPAnalyser.deleteDirectory(file);
    }
}
